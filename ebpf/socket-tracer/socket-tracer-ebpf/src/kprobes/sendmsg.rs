#![no_std]
#![no_main]

use aya_ebpf::{
    cty::ssize_t,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::tracepoint,
    programs::TracePointContext,
};

use socket_tracer_common::{SourceFunction, TrafficDirection::Egress};
use socket_tracer_lib::{
    maps::{ACTIVE_CONNECT_MAP, ACTIVE_WRITE_MAP},
    process_implicit_conn, process_syscall_data_vecs, types,
    types::AlignedBool,
    vmlinux::{iovec, sockaddr, user_msghdr},
};

#[tracepoint]
pub fn entry_sendmsg(ctx: TracePointContext) -> u32 {
    try_entry_sendmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

pub const SENDMSG_FD_OFFSET: usize = 16;
pub const SENDMSG_MSGHDR_OFFSET: usize = 24;

fn try_entry_sendmsg(ctx: TracePointContext) -> Result<u32, i64> {
    let fd: i32 = unsafe { ctx.read_at(SENDMSG_FD_OFFSET)? };
    let msg_hdr_ptr: *const user_msghdr = unsafe { ctx.read_at(SENDMSG_MSGHDR_OFFSET)? };
    let pid_tgid = bpf_get_current_pid_tgid();

    if msg_hdr_ptr.is_null() {
        return Ok(0);
    }

    let msg_hdr = unsafe { bpf_probe_read_user(msg_hdr_ptr).map_err(|_| 1i64)? };

    unsafe {
        let msg_name_ptr = msg_hdr.msg_name;
        let sockaddr = msg_hdr.msg_name as *const sockaddr;

        if !msg_name_ptr.is_null() {
            let connect_args = types::ConnectArgs { sockaddr, fd };
            _ = ACTIVE_CONNECT_MAP.insert(&pid_tgid, &connect_args, 0);
        }
    }

    unsafe {
        let msg_iov: *mut iovec = msg_hdr.msg_iov;
        let msg_iovlen: u64 = msg_hdr.msg_iovlen;
        let data_args = types::DataArgs {
            source_function: SourceFunction::SyscallSendMsg,
            sock_event: AlignedBool::True,
            fd,
            buf: core::ptr::null(),
            iov: msg_iov,
            iovlen: msg_iovlen,
            msg_len: 0,
        };

        ACTIVE_WRITE_MAP.insert(&pid_tgid, &data_args, 0)?;
    }

    Ok(0)
}

#[tracepoint]
pub fn ret_sendmsg(ctx: TracePointContext) -> u32 {
    try_ret_sendmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

pub const SENDMSG_RET_OFFSET: usize = 16;

fn try_ret_sendmsg(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let bytes_count: ssize_t = unsafe { ctx.read_at(SENDMSG_RET_OFFSET)? };

    if let Some(connect_args) = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid) } {
        if bytes_count > 0 {
            process_implicit_conn(&ctx, pid_tgid, connect_args, SourceFunction::SyscallSendMsg);
        }
        unsafe {
            ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
        }
    }

    let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1i64)? };
    let res = process_syscall_data_vecs(&ctx, pid_tgid, Egress, data_args, bytes_count);

    unsafe {
        ACTIVE_WRITE_MAP.remove(&pid_tgid)?;
    }

    res
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
