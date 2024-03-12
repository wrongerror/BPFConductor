#![no_std]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub mod vmlinux;

pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 10;
pub const MAX_CONNECTIONS: u32 = 1000000;

pub const TCP_SYN_SENT: u32 = 2;
pub const TCP_SYN_RECV: u32 = 3;
pub const TCP_CLOSE: u32 = 7;

pub const INET_SOCK_SKADDR_OFFSET: usize = 8;
pub const INET_SOCK_NEWSTATE_OFFSET: usize = 20;

pub const CONNECTION_ROLE_UNKNOWN: u32 = 0;
pub const CONNECTION_ROLE_CLIENT: u32 = 1;
pub const CONNECTION_ROLE_SERVER: u32 = 2;

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SockInfo {
    pub id: u32,
    pub pid: u32,
    pub is_active: u32,
    pub role: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for SockInfo {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ConnectionKey {
    pub id: u32,
    pub pid: u32,
    pub src_addr: u32,
    pub src_port: u32,
    pub dest_addr: u32,
    pub dest_port: u32,
    pub role: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionKey {}

#[derive(Copy, Clone, Debug, Default)]
#[repr(C)]
pub struct ConnectionStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub is_active: u64,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ConnectionStats {}
