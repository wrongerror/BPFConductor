#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{kprobe, kretprobe},
    programs::ProbeContext,
};

use socket_tracer_common::{SourceFunction, TrafficDirection::Egress};
use socket_tracer_lib::{
    maps::ACTIVE_WRITE_MAP, process_syscall_data_vecs, types, types::AlignedBool, vmlinux::iovec,
};

#[kprobe]
pub fn entry_writev(ctx: ProbeContext) -> u32 {
    try_entry_writev(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_writev(ctx: ProbeContext) -> Result<u32, i64> {
    let fd: i32 = ctx.arg(0).ok_or(1)?;
    let iov: *mut iovec = ctx.arg(1).ok_or(1)?;
    let iovlen: u64 = ctx.arg(2).ok_or(1)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let data_args = types::DataArgs {
        source_function: SourceFunction::SyscallWriteV,
        sock_event: AlignedBool::False,
        fd,
        buf: core::ptr::null(),
        iov,
        iovlen,
        msg_len: 0,
    };

    unsafe {
        ACTIVE_WRITE_MAP.insert(&pid_tgid, &data_args, 0)?;
    }

    Ok(0)
}

#[kretprobe]
pub fn ret_writev(ctx: ProbeContext) -> u32 {
    try_ret_writev(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_writev(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let bytes_count = ctx.ret().ok_or(1)?;
    let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1)? };

    if data_args.sock_event.into() {
        process_syscall_data_vecs(&ctx, pid_tgid, Egress, data_args, bytes_count)?;
    }

    unsafe {
        ACTIVE_WRITE_MAP.remove(&pid_tgid)?;
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
