use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use parking_lot::Mutex;

use socket_tracer_common::{AF_INET, AF_INET6, SocketAddressable};

pub(crate) fn convert_src_to_socket_addr(event: &impl SocketAddressable) -> Option<SocketAddr> {
    match event.sa_family() {
        AF_INET => {
            let ip = Ipv4Addr::from(event.src_addr_in4());
            let port = event.src_port() as u16;
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        AF_INET6 => {
            let ip = Ipv6Addr::from(event.src_addr_in6());
            let port = event.src_port() as u16;
            Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => None,
    }
}

pub(crate) fn convert_dst_to_socket_addr(event: &impl SocketAddressable) -> Option<SocketAddr> {
    match event.sa_family() {
        AF_INET => {
            let ip = Ipv4Addr::from(event.dst_addr_in4());
            let port = event.dst_port() as u16;
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        AF_INET6 => {
            let ip = Ipv6Addr::from(event.dst_addr_in6());
            let port = event.dst_port() as u16;
            Some(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        }
        _ => None,
    }
}

pub(crate) fn is_unspecified(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ipv4) => ipv4.is_unspecified(),
        IpAddr::V6(ipv6) => ipv6.is_unspecified(),
    }
}

pub struct ObjPool<T> {
    capacity: usize,
    pool: Mutex<VecDeque<T>>,
}

impl<T> ObjPool<T>
where
    T: Default,
{
    pub fn new(capacity: usize) -> Self {
        ObjPool {
            capacity,
            pool: Mutex::new(VecDeque::with_capacity(capacity)),
        }
    }

    pub fn pop(&self) -> T {
        let mut pool = self.pool.lock();
        if let Some(obj) = pool.pop_front() {
            obj
        } else {
            T::default()
        }
    }

    pub fn recycle(&self, obj: T) {
        let mut pool = self.pool.lock();
        if pool.len() < self.capacity {
            pool.push_back(obj);
        }
    }
}
