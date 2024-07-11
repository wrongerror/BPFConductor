#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid, macros::tracepoint, programs::TracePointContext,
};

use socket_tracer_common::{EndpointRole, SourceFunction};
use socket_tracer_lib::{
    maps::*, match_trace_tgid, OpenEventArgs, submit_open_event, TargetTgidMatchResult, types,
    vmlinux::sockaddr,
};

#[tracepoint]
pub fn entry_connect(ctx: TracePointContext) -> u32 {
    try_entry_connect(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

pub const CONNECT_FD_OFFSET: usize = 16;
pub const CONNECT_SOCKADDR_OFFSET: usize = 24;
pub const CONNECT_ADDRLEN_OFFSET: usize = 32;

fn try_entry_connect(ctx: TracePointContext) -> Result<u32, i64> {
    let fd: i32 = unsafe { ctx.read_at(CONNECT_FD_OFFSET)? };
    let sockaddr: *const sockaddr = unsafe { ctx.read_at(CONNECT_SOCKADDR_OFFSET)? };
    let pid_tgid = bpf_get_current_pid_tgid();

    let connect_args = types::ConnectArgs { fd, sockaddr };
    unsafe {
        ACTIVE_CONNECT_MAP.insert(&pid_tgid, &connect_args, 0)?;
    }

    Ok(0)
}

#[tracepoint]
pub fn ret_connect(ctx: TracePointContext) -> u32 {
    try_ret_connect(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

pub const CONNECT_RET_OFFSET: usize = 16;
fn try_ret_connect(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let connect_args = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid).ok_or(1i64)? };
    let res = process_syscall_connect(&ctx, pid_tgid, connect_args);
    unsafe {
        ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
    }
    res
}

fn process_syscall_connect(
    ctx: &TracePointContext,
    pid_tgid: u64,
    args: &types::ConnectArgs,
) -> Result<u32, i64> {
    let tgid: u32 = (pid_tgid >> 32) as u32;
    let retval: i32 = unsafe { ctx.read_at(CONNECT_RET_OFFSET)? };

    if match_trace_tgid(tgid) == TargetTgidMatchResult::Unmatched {
        return Ok(0);
    }

    if args.fd < 0 {
        return Ok(0);
    }

    if retval < 0 {
        return Ok(0);
    }

    let open_event_args = OpenEventArgs {
        tgid,
        fd: args.fd,
        sockaddr: args.sockaddr,
        sk: core::ptr::null(),
        role: EndpointRole::Client,
        source_fn: SourceFunction::SyscallConnect,
    };

    submit_open_event(ctx, &open_event_args)?;

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
