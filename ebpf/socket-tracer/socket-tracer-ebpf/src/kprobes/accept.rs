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
pub fn entry_accept(ctx: ProbeContext) -> u32 {
    try_entry_accept(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_accept(ctx: ProbeContext) -> Result<u32, i64> {
    let sockaddr: *const sockaddr = ctx.arg(1).ok_or(1)?;
    let pid_tgid = bpf_get_current_pid_tgid();

    let accept_args = types::AcceptArgs {
        sockaddr,
        sock: core::ptr::null(),
    };

    unsafe {
        ACTIVE_ACCEPT_MAP.insert(&pid_tgid, &accept_args, 0)?;
    }

    Ok(0)
}

#[kretprobe]
pub fn ret_accept(ctx: ProbeContext) -> u32 {
    try_ret_accept(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_accept(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let accept_args = unsafe { ACTIVE_ACCEPT_MAP.get(&pid_tgid).ok_or(1)? };
    let res = process_syscall_accept(&ctx, pid_tgid, accept_args);

    unsafe {
        ACTIVE_ACCEPT_MAP.remove(&pid_tgid)?;
    }

    res
}

fn process_syscall_accept(
    ctx: &ProbeContext,
    pid_tgid: u64,
    args: &types::AcceptArgs,
) -> Result<u32, i64> {
    let tgid: u32 = (pid_tgid >> 32) as u32;
    let ret_fd: i32 = ctx.ret().ok_or(1u32)?;

    if match_trace_tgid(tgid) == TargetTgidMatchResult::Unmatched {
        return Ok(0);
    }

    if ret_fd < 0 {
        return Ok(0);
    }

    let open_event_args = OpenEventArgs {
        tgid,
        fd: ret_fd,
        sockaddr: args.sockaddr,
        sk: args.sock,
        role: EndpointRole::Server,
        source_fn: SourceFunction::SyscallAccept,
    };

    submit_open_event(ctx, &open_event_args)?;

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
