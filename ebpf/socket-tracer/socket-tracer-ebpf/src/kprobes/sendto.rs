#![no_std]
#![no_main]

use aya_ebpf::{
    cty::ssize_t,
    helpers::bpf_get_current_pid_tgid,
    macros::{kprobe, kretprobe},
    programs::ProbeContext,
};

use socket_tracer_common::{SourceFunction, TrafficDirection::Egress};
use socket_tracer_lib::{
    maps::{ACTIVE_CONNECT_MAP, ACTIVE_WRITE_MAP},
    process_syscall_data, types,
    types::AlignedBool,
    vmlinux::sockaddr,
};

#[kprobe]
pub fn entry_sendto(ctx: ProbeContext) -> u32 {
    try_entry_sendto(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_sendto(ctx: ProbeContext) -> Result<u32, i64> {
    let fd: i32 = ctx.arg(0).ok_or(1)?;
    let buf: *const u8 = ctx.arg(1).ok_or(1)?;
    let dest_addr: *const sockaddr = ctx.arg(4).ok_or(1)?;
    let pid_tgid = bpf_get_current_pid_tgid();

    if !dest_addr.is_null() {
        let connect_args = types::ConnectArgs {
            fd,
            sockaddr: dest_addr,
        };

        unsafe {
            ACTIVE_CONNECT_MAP.insert(&pid_tgid, &connect_args, 0)?;
        }
    }

    let pid_tgid = bpf_get_current_pid_tgid();
    let data_args = types::DataArgs {
        source_function: SourceFunction::SyscallSendTo,
        sock_event: AlignedBool::False,
        fd,
        buf,
        iov: core::ptr::null_mut(),
        iovlen: 0,
        msg_len: 0,
    };

    unsafe {
        ACTIVE_WRITE_MAP.insert(&pid_tgid, &data_args, 0)?;
    }

    Ok(0)
}

#[kretprobe]
pub fn ret_sendto(ctx: ProbeContext) -> u32 {
    try_ret_sendto(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_sendto(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let bytes_count: ssize_t = ctx.ret().ok_or(1)?;

    let connect_args = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid) };
    if connect_args.is_some() && bytes_count > 0 {
        // TODO: Handle implicit conn
    }
    unsafe {
        ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
    }

    let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1)? };
    let res = process_syscall_data(&ctx, pid_tgid, Egress, data_args, bytes_count);

    unsafe {
        ACTIVE_WRITE_MAP.remove(&pid_tgid)?;
    }

    res
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
