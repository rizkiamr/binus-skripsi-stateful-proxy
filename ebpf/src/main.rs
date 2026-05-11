#![no_std]
#![no_main]

use core::mem;
use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{Array, LruHashMap},
    programs::XdpContext,
};
use aya_log_ebpf::info;
use common::{BackendInfo, FlowKey};

#[map]
static mut CT_MAP: LruHashMap<FlowKey, u32> = LruHashMap::with_max_entries(1_000_000, 0);

#[map]
static mut BACKENDS: Array<BackendInfo> = Array::with_max_entries(256, 0);

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[no_mangle]
static _license: [u8; 4] = *b"GPL\0";

// Basic definitions for L2/L3 parsing
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    pub dst_addr: [u8; 6],
    pub src_addr: [u8; 6],
    pub ether_type: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct Ipv4Hdr {
    pub ihl_version: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct TcpHdr {
    pub source: u16,
    pub dest: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub flags: u16,
    pub window: u16,
    pub check: u16,
    pub urg_ptr: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct UdpHdr {
    pub source: u16,
    pub dest: u16,
    pub len: u16,
    pub check: u16,
}

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

const VIP_ADDR: u32 = u32::from_be_bytes([10, 0, 0, 100]);
const PROXY_IP: u32 = u32::from_be_bytes([10, 0, 0, 54]);

#[inline(always)]
fn csum_fold_helper(mut csum: u64) -> u16 {
    for _ in 0..4 {
        if (csum >> 16) > 0 {
            csum = (csum & 0xffff) + (csum >> 16);
        }
    }
    !(csum as u16)
}

#[inline(always)]
fn ipv4_csum(hdr: &Ipv4Hdr) -> u16 {
    let ptr = hdr as *const Ipv4Hdr as *const u16;
    let mut sum: u64 = 0;
    for i in 0..10 {
        sum += unsafe { *ptr.add(i) } as u64;
    }
    csum_fold_helper(sum)
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let eth_hdr: *const EthHdr = ptr_at(&ctx, 0)?;
    if u16::from_be(unsafe { (*eth_hdr).ether_type }) != ETH_P_IP {
        return Ok(xdp_action::XDP_PASS);
    }

    let eth_hdr_len = mem::size_of::<EthHdr>();
    let ipv4_hdr: *const Ipv4Hdr = ptr_at(&ctx, eth_hdr_len)?;
    let ihl = (unsafe { (*ipv4_hdr).ihl_version } & 0x0f) as usize;
    let ipv4_hdr_len = ihl * 4;

    if eth_hdr_len + ipv4_hdr_len > ctx.data_end() - ctx.data() {
        return Err(());
    }

    let protocol = unsafe { (*ipv4_hdr).protocol };
    let daddr = u32::from_be(unsafe { (*ipv4_hdr).daddr });

    if protocol != IPPROTO_TCP && protocol != IPPROTO_UDP {
        return Ok(xdp_action::XDP_PASS);
    }

    let l4_offset = eth_hdr_len + ipv4_hdr_len;
    let (src_port, dst_port) = match protocol {
        IPPROTO_TCP => {
            let tcp_hdr: *const TcpHdr = ptr_at(&ctx, l4_offset)?;
            (u16::from_be(unsafe { (*tcp_hdr).source }), u16::from_be(unsafe { (*tcp_hdr).dest }))
        }
        IPPROTO_UDP => {
            let udp_hdr: *const UdpHdr = ptr_at(&ctx, l4_offset)?;
            (u16::from_be(unsafe { (*udp_hdr).source }), u16::from_be(unsafe { (*udp_hdr).dest }))
        }
        _ => return Ok(xdp_action::XDP_PASS),
    };

    if dst_port != 80 {
        return Ok(xdp_action::XDP_PASS);
    }

    // info!(&ctx, "Matched: dst_port 80, daddr {:x}", daddr);

    let saddr = u32::from_be(unsafe { (*ipv4_hdr).saddr });
    let flow_key = FlowKey {
        src_ip: saddr,
        dst_ip: daddr,
        src_port,
        dst_port,
        proto: protocol,
        _padding: [0; 3],
    };

    let backend_id = unsafe {
        match CT_MAP.get(&flow_key) {
            Some(id_ptr) => *id_ptr,
            None => {
                let id = 0;
                let _ = CT_MAP.insert(&flow_key, &id, 0);
                id
            }
        }
    };

    let backend = unsafe {
        match BACKENDS.get(backend_id) {
            Some(b) => *b,
            None => return Ok(xdp_action::XDP_PASS),
        }
    };

    let inner_ipv4_tot_len = u16::from_be(unsafe { (*ipv4_hdr).tot_len });
    let old_eth = unsafe { core::ptr::read(eth_hdr) };

    let ipv4_size = mem::size_of::<Ipv4Hdr>();
    let ret = unsafe { aya_ebpf::helpers::bpf_xdp_adjust_head(ctx.ctx as *mut _, -(ipv4_size as i32)) };
    if ret != 0 {
        return Ok(xdp_action::XDP_DROP);
    }

    let new_eth_hdr = ptr_at::<EthHdr>(&ctx, 0)? as *mut EthHdr;
    let outer_ipv4_hdr = ptr_at::<Ipv4Hdr>(&ctx, mem::size_of::<EthHdr>())? as *mut Ipv4Hdr;

    unsafe {
        core::ptr::write(new_eth_hdr, old_eth);
        (*new_eth_hdr).dst_addr = backend.mac;

        let mut new_ip = Ipv4Hdr {
            ihl_version: 0x45,
            tos: 0,
            tot_len: u16::to_be(inner_ipv4_tot_len + ipv4_size as u16),
            id: 0,
            frag_off: 0,
            ttl: 64,
            protocol: 4,
            check: 0,
            saddr: u32::to_be(PROXY_IP),
            daddr: u32::to_be(backend.ip),
        };
        new_ip.check = ipv4_csum(&new_ip);
        core::ptr::write(outer_ipv4_hdr, new_ip);
    }

    Ok(xdp_action::XDP_TX)
}
