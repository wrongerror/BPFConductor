#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    cty::{size_t, ssize_t},
    helpers::bpf_get_current_pid_tgid,
    macros::{kprobe, kretprobe},
    programs::ProbeContext,
};

use socket_tracer_common::{SocketDataEventInner, SourceFunction, TrafficDirection::Egress};
use socket_tracer_lib::{
    filters::should_trace_conn,
    gen_tgid_fd, get_or_create_conn_info,
    maps::{ACTIVE_SENDFILE_MAP, CONN_DISABLED_MAP, SOCKET_DATA_EVENTS},
    match_trace_tgid, populate_socket_data_event, should_send_data, TargetTgidMatchResult, types,
    update_conn_stats,
};

#[kprobe]
pub fn entry_sendfile(ctx: ProbeContext) -> u32 {
    try_entry_sendfile(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_sendfile(ctx: ProbeContext) -> Result<u32, i64> {
    let out_fd: i32 = ctx.arg(0).ok_or(1)?;
    let in_fd: i32 = ctx.arg(1).ok_or(1)?;
    let count: size_t = ctx.arg(3).ok_or(1)?;

    let pid_tgid = bpf_get_current_pid_tgid();
    let sendfile_args = types::SendfileArgs {
        out_fd,
        in_fd,
        count,
    };

    unsafe {
        ACTIVE_SENDFILE_MAP.insert(&pid_tgid, &sendfile_args, 0)?;
    }

    Ok(0)
}

#[kretprobe]
pub fn ret_sendfile(ctx: ProbeContext) -> u32 {
    try_ret_sendfile(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_sendfile(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let bytes_count: ssize_t = ctx.ret().ok_or(1)?;
    let sendfile_args = unsafe { ACTIVE_SENDFILE_MAP.get(&pid_tgid).ok_or(1)? };
    process_syscall_sendfile(&ctx, pid_tgid, sendfile_args, bytes_count)?;

    unsafe {
        ACTIVE_SENDFILE_MAP.remove(&pid_tgid)?;
    }

    Ok(0)
}

fn process_syscall_sendfile(
    ctx: &ProbeContext,
    id: u64,
    args: &types::SendfileArgs,
    bytes_count: ssize_t,
) -> Result<u32, i64> {
    let tgid = (id >> 32) as u32;

    if args.out_fd < 0 {
        return Ok(0);
    }

    if bytes_count <= 0 {
        return Ok(0);
    }

    let match_result = match_trace_tgid(tgid);
    if match_result == TargetTgidMatchResult::Unmatched {
        return Ok(0);
    }
    let force_trace_tgid = match_result == TargetTgidMatchResult::Matched;

    let mut conn_info = get_or_create_conn_info(tgid, args.out_fd)?;
    if !should_trace_conn(&conn_info) {
        return Ok(0);
    }

    let tgid_fd = gen_tgid_fd(tgid, args.out_fd);
    let conn_disabled_tsid = unsafe {
        match CONN_DISABLED_MAP.get(&tgid_fd) {
            Some(&tsid) => tsid,
            None => 0,
        }
    };

    if should_send_data(tgid, conn_disabled_tsid, force_trace_tgid, conn_info) {
        let event =
            populate_socket_data_event(SourceFunction::SyscallSendFile, Egress, &conn_info)?;
        event.inner.position = conn_info.write_bytes as u64;
        event.inner.msg_size = bytes_count as u32;
        event.inner.msg_buf_size = 0;
        unsafe {
            let data_size = mem::size_of::<SocketDataEventInner>() as u64;
            SOCKET_DATA_EVENTS.output_with_size(ctx, event, data_size, 0);
        }
    }

    update_conn_stats(ctx, &mut conn_info, Egress, bytes_count)?;

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
