#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub proto: u8,
    pub _padding: [u8; 3], // 8-byte alignment
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BackendInfo {
    pub ip: u32,
    pub mac: [u8; 6],
    pub _padding: [u8; 2],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for FlowKey {}

#[cfg(feature = "user")]
unsafe impl aya::Pod for BackendInfo {}
