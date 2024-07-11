#![no_std]
#![no_main]

use aya_ebpf::{
    cty::ssize_t, helpers::bpf_get_current_pid_tgid, macros::tracepoint,
    programs::TracePointContext,
};

use socket_tracer_common::{SourceFunction, TrafficDirection::Egress};
use socket_tracer_lib::{
    maps::{ACTIVE_CONNECT_MAP, ACTIVE_WRITE_MAP},
    process_implicit_conn, process_syscall_data, types,
    types::AlignedBool,
    vmlinux::sockaddr,
};

#[tracepoint]
pub fn entry_sendto(ctx: TracePointContext) -> u32 {
    try_entry_sendto(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

pub const SENDTO_FD_OFFSET: usize = 16;
pub const SENDTO_BUF_OFFSET: usize = 24;
pub const SENDTO_ADDR_OFFSET: usize = 48;

fn try_entry_sendto(ctx: TracePointContext) -> Result<u32, i64> {
    let fd: i32 = unsafe { ctx.read_at(SENDTO_FD_OFFSET)? };
    let buf: *const u8 = unsafe { ctx.read_at(SENDTO_BUF_OFFSET)? };
    let dest_addr: *const sockaddr = unsafe { ctx.read_at(SENDTO_ADDR_OFFSET)? };
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

#[tracepoint]
pub fn ret_sendto(ctx: TracePointContext) -> u32 {
    try_ret_sendto(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

pub const SENDTO_RET_OFFSET: usize = 16;

fn try_ret_sendto(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let bytes_count: ssize_t = unsafe { ctx.read_at(SENDTO_RET_OFFSET)? };

    if let Some(connect_args) = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid) } {
        if bytes_count > 0 {
            process_implicit_conn(&ctx, pid_tgid, connect_args, SourceFunction::SyscallSendTo);
        }
        unsafe {
            ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
        }
    }

    let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1i64)? };
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
