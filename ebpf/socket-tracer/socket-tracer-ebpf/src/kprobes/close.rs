#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_get_current_pid_tgid,
    macros::{kprobe, kretprobe},
    programs::ProbeContext,
};

use socket_tracer_common::SourceFunction;
use socket_tracer_lib::{
    filters::should_trace_sockaddr_family, gen_tgid_fd, maps::*, match_trace_tgid,
    populate_conn_stats_event, submit_close_event, TargetTgidMatchResult, types,
};

#[kprobe]
pub fn entry_close(ctx: ProbeContext) -> u32 {
    try_entry_close(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_close(ctx: ProbeContext) -> Result<u32, i64> {
    let fd: i32 = ctx.arg(0).ok_or(1)?;
    let close_args = types::CloseArgs { fd };

    unsafe {
        ACTIVE_CLOSE_MAP.insert(&bpf_get_current_pid_tgid(), &close_args, 0)?;
    }

    Ok(0)
}

#[kretprobe]
pub fn ret_close(ctx: ProbeContext) -> u32 {
    try_ret_close(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_close(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let close_args = unsafe { ACTIVE_CLOSE_MAP.get(&pid_tgid).ok_or(1)? };
    let res = process_syscall_close(&ctx, pid_tgid, close_args);

    unsafe {
        ACTIVE_CLOSE_MAP.remove(&pid_tgid)?;
    }

    res
}

fn process_syscall_close(
    ctx: &ProbeContext,
    pid_tgid: u64,
    args: &types::CloseArgs,
) -> Result<u32, i64> {
    let tgid: u32 = (pid_tgid >> 32) as u32;
    let retval: i32 = ctx.ret().ok_or(1u32)?;

    if args.fd < 0 {
        return Ok(0);
    }

    if retval < 0 {
        return Ok(0);
    }

    if match_trace_tgid(tgid) == TargetTgidMatchResult::Unmatched {
        return Ok(0);
    }

    let tgid_fd = gen_tgid_fd(tgid, args.fd);
    let conn_info = unsafe { CONN_INFO_MAP.get(&tgid_fd).ok_or(1)? };
    // info!(
    //     ctx,
    //     "close: tgid: {}, fd: {}, retval: {}, write_bytes: {}, read_bytes: {}, sa_family: {}",
    //     tgid,
    //     args.fd,
    //     retval,
    //     conn_info.write_bytes,
    //     conn_info.read_bytes,
    //     conn_info.sa_family
    // );

    if should_trace_sockaddr_family(conn_info.sa_family)
        || conn_info.write_bytes > 0
        || conn_info.read_bytes > 0
    {
        submit_close_event(ctx, &conn_info, SourceFunction::SyscallClose)?;

        let mut event = populate_conn_stats_event(*conn_info)?;
        event.event_flags = event.event_flags | (1 << 1);
        unsafe {
            CONN_STATS_EVENTS.output(ctx, &event, 0);
        }
    }

    unsafe {
        CONN_INFO_MAP.remove(&tgid_fd)?;
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
