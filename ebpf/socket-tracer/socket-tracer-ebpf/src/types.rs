use socket_tracer_common::SourceFunction;

use crate::vmlinux::{iovec, sock, sockaddr};

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum AlignedBool {
    False = 0,
    True = 1,
}

impl From<AlignedBool> for bool {
    fn from(value: AlignedBool) -> Self {
        match value {
            AlignedBool::False => false,
            AlignedBool::True => true,
        }
    }
}

impl From<bool> for AlignedBool {
    fn from(value: bool) -> Self {
        if value {
            AlignedBool::True
        } else {
            AlignedBool::False
        }
    }
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct ConnectArgs {
    pub fd: i32,
    pub sockaddr: *const sockaddr,
}

unsafe impl Sync for ConnectArgs {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct AcceptArgs {
    pub sockaddr: *const sockaddr,
    pub sock: *const sock,
}

unsafe impl Sync for AcceptArgs {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct DataArgs {
    // Represents the function from which this argument group originates.
    pub source_function: SourceFunction,

    // For sendmsg()/recvmsg()/writev()/readv().
    pub iovlen: u64,

    // For send()/recv()/write()/read() 和 sendmsg()/recvmsg()/writev()/readv()。
    pub buf: *const u8,
    pub iov: *mut iovec,

    // Did the data event call sock_sendmsg/sock_recvmsg.
    // Used to filter out read/write and readv/writev calls that are not to sockets.
    pub sock_event: AlignedBool,

    // For sendmmsg()
    pub msg_len: u32,

    pub fd: i32,
}

unsafe impl Sync for DataArgs {}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct CloseArgs {
    pub fd: i32,
}

#[derive(Copy, Clone, Debug)]
#[repr(C)]
pub struct SendfileArgs {
    pub out_fd: i32,
    pub in_fd: i32,
    pub count: usize,
}
