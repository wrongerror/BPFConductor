#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe},
    programs::ProbeContext,
};

use socket_tracer_common::{SourceFunction, TrafficDirection::Egress};
use socket_tracer_lib::{
    maps::{ACTIVE_CONNECT_MAP, ACTIVE_WRITE_MAP},
    process_syscall_data_vecs, types,
    types::AlignedBool,
    vmlinux::{iovec, sockaddr, user_msghdr},
};

#[kprobe]
pub fn entry_sendmsg(ctx: ProbeContext) -> u32 {
    try_entry_sendmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let fd: i32 = ctx.arg(0).ok_or(1)?;
    let msghdr: *const user_msghdr = ctx.arg(1).ok_or(1)?;
    let pid_tgid = bpf_get_current_pid_tgid();

    if msghdr.is_null() {
        return Ok(0);
    }

    let msg_hdr = unsafe { bpf_probe_read_kernel(msghdr).map_err(|_| 1)? };

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

#[kretprobe]
pub fn ret_sendmsg(ctx: ProbeContext) -> u32 {
    try_ret_sendmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_sendmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let bytes_count = ctx.ret().ok_or(1)?;

    let connect_args = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid) };
    if connect_args.is_some() {
        // TODO: handle implicit connect
        unsafe {
            _ = ACTIVE_CONNECT_MAP.remove(&pid_tgid);
        }
    }

    let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1)? };
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
