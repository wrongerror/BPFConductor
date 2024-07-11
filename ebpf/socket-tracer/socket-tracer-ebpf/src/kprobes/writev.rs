#![no_std]
#![no_main]

use aya_ebpf::{
    cty::ssize_t, helpers::bpf_get_current_pid_tgid, macros::tracepoint,
    programs::TracePointContext,
};

use socket_tracer_common::{SourceFunction, TrafficDirection::Egress};
use socket_tracer_lib::{
    maps::ACTIVE_WRITE_MAP, process_syscall_data_vecs, types, types::AlignedBool, vmlinux::iovec,
};

#[tracepoint]
pub fn entry_writev(ctx: TracePointContext) -> u32 {
    try_entry_writev(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

pub const WRITEV_FD_OFFSET: usize = 16;
pub const WRITEV_IOV_OFFSET: usize = 24;
pub const WRITEV_IOVLEN_OFFSET: usize = 32;

fn try_entry_writev(ctx: TracePointContext) -> Result<u32, i64> {
    let fd: i32 = unsafe { ctx.read_at(WRITEV_FD_OFFSET)? };
    let iov: *mut iovec = unsafe { ctx.read_at(WRITEV_IOV_OFFSET)? };
    let iovlen: u64 = unsafe { ctx.read_at(WRITEV_IOVLEN_OFFSET)? };

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

#[tracepoint]
pub fn ret_writev(ctx: TracePointContext) -> u32 {
    try_ret_writev(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

pub const WRITEV_RET_OFFSET: usize = 16;

fn try_ret_writev(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let bytes_count: ssize_t = unsafe { ctx.read_at(WRITEV_RET_OFFSET)? };
    let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1i64)? };

    let mut res = Ok(0);
    if data_args.sock_event.into() {
        res = process_syscall_data_vecs(&ctx, pid_tgid, Egress, data_args, bytes_count);
    }

    unsafe {
        ACTIVE_WRITE_MAP.remove(&pid_tgid)?;
    }

    res
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
