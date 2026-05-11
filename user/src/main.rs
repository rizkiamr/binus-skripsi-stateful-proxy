use anyhow::Context;
use aya::{
    include_bytes_aligned,
    maps::Array,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use common::BackendInfo;
use std::net::Ipv4Addr;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // 6.1 Program Loading
    // Always use the release build for eBPF as it's required for verifier compliance.
    let bpf_data = include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/ebpf"
    );

    let mut bpf = Ebpf::load(bpf_data)?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
        println!("failed to initialize ebpf logger: {}", e);
    }
    for (name, _) in bpf.programs() {
        println!("Found program: {}", name);
    }
    
    // 6.2 Program Attachment
    let iface = std::env::var("IFACE").unwrap_or_else(|_| "eth0".to_string());
    let program: &mut Xdp = bpf.program_mut("xdp_firewall").ok_or_else(|| anyhow::anyhow!("program not found"))?.try_into()?;
    program.load()?;
    program.attach(&iface, XdpFlags::default())
        .context(format!("failed to attach the XDP program with default flags to interface {}", iface))?;

    // 6.3 Map Population
    // Populating mock backend servers into the BACKENDS eBPF map.
    let mut backends: Array<_, BackendInfo> = Array::try_from(bpf.map_mut("BACKENDS").unwrap())?;

    let mock_backends = [
        BackendInfo {
            ip: u32::from(Ipv4Addr::new(10, 0, 0, 56)),
            mac: [0x00, 0x0c, 0x29, 0xd7, 0x6e, 0xbf],
            _padding: [0; 2],
        },
    ];

    for (i, backend) in mock_backends.iter().enumerate() {
        backends.set(i as u32, *backend, 0)?;
    }

    println!("Populated {} backends.", mock_backends.len());

    // 6.4 Graceful Shutdown
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
