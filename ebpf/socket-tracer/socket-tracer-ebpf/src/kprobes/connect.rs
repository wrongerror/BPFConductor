#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{kprobe, kretprobe},
    programs::ProbeContext,
};

use socket_tracer_common::{EndpointRole, SourceFunction};
use socket_tracer_lib::{
    maps::*, match_trace_tgid, OpenEventArgs, submit_open_event, TargetTgidMatchResult, types,
    vmlinux::sockaddr,
};

#[kprobe]
pub fn entry_connect(ctx: ProbeContext) -> u32 {
    try_entry_connect(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_connect(ctx: ProbeContext) -> Result<u32, i64> {
    let fd: i32 = ctx.arg(0).ok_or(1)?;
    let sockaddr: *const sockaddr = ctx.arg(1).ok_or(1)?;
    let pid_tgid = bpf_get_current_pid_tgid();

    let connect_args = types::ConnectArgs { fd, sockaddr };
    unsafe {
        ACTIVE_CONNECT_MAP.insert(&pid_tgid, &connect_args, 0)?;
    }

    Ok(0)
}

#[kretprobe]
pub fn ret_connect(ctx: ProbeContext) -> u32 {
    try_ret_connect(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_connect(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let connect_args = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid).ok_or(1)? };
    let res = process_syscall_connect(&ctx, pid_tgid, connect_args);
    unsafe {
        ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
    }
    res
}

fn process_syscall_connect(
    ctx: &ProbeContext,
    pid_tgid: u64,
    args: &types::ConnectArgs,
) -> Result<u32, i64> {
    let tgid: u32 = (pid_tgid >> 32) as u32;
    let retval: i32 = ctx.ret().ok_or(1u32)?;

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
