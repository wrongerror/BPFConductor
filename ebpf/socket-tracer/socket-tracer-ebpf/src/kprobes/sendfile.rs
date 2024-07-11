#![no_std]
#![no_main]

use aya_ebpf::{
    cty::{size_t, ssize_t},
    helpers::bpf_get_current_pid_tgid,
    macros::tracepoint,
    programs::TracePointContext,
};

use socket_tracer_common::{SocketDataEventInner, SourceFunction, TrafficDirection::Egress};
use socket_tracer_lib::{
    filters::should_trace_conn,
    gen_tgid_fd, get_or_create_conn_info,
    maps::{ACTIVE_SENDFILE_MAP, CONN_DISABLED_MAP, SOCKET_DATA_EVENTS},
    match_trace_tgid, populate_socket_data_event, should_send_data, TargetTgidMatchResult, types,
    update_conn_stats,
};

pub const SENDFILE_OUT_FD_OFFSET: usize = 16;
pub const SENDFILE_IN_FD_OFFSET: usize = 24;
pub const SENDFILE_COUNT_OFFSET: usize = 40;
pub const SENDFILE_RET_OFFSET: usize = 16;

#[tracepoint]
pub fn entry_sendfile64(ctx: TracePointContext) -> u32 {
    try_entry_sendfile(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_sendfile(ctx: TracePointContext) -> Result<u32, i64> {
    let out_fd: i32 = unsafe { ctx.read_at(SENDFILE_OUT_FD_OFFSET)? };
    let in_fd: i32 = unsafe { ctx.read_at(SENDFILE_IN_FD_OFFSET)? };
    let count: size_t = unsafe { ctx.read_at(SENDFILE_COUNT_OFFSET)? };

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

#[tracepoint]
pub fn ret_sendfile64(ctx: TracePointContext) -> u32 {
    try_ret_sendfile(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_sendfile(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let bytes_count: ssize_t = unsafe { ctx.read_at(SENDFILE_RET_OFFSET)? };
    let sendfile_args = unsafe { ACTIVE_SENDFILE_MAP.get(&pid_tgid).ok_or(1i64)? };
    process_syscall_sendfile(&ctx, pid_tgid, sendfile_args, bytes_count)?;

    unsafe {
        ACTIVE_SENDFILE_MAP.remove(&pid_tgid)?;
    }

    Ok(0)
}

fn process_syscall_sendfile(
    ctx: &TracePointContext,
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

    if should_send_data(tgid, conn_disabled_tsid, force_trace_tgid, &conn_info) {
        let event =
            populate_socket_data_event(SourceFunction::SyscallSendFile, Egress, &conn_info)?;
        event.inner.position = conn_info.write_bytes as u64;
        event.inner.msg_size = bytes_count as u32;
        event.inner.msg_buf_size = 0;
        unsafe {
            let data_size = core::mem::size_of::<SocketDataEventInner>() as u64;
            SOCKET_DATA_EVENTS.output_with_size(ctx, event, data_size, 0);
        }
    }

    update_conn_stats(ctx, tgid_fd, &mut conn_info, Egress, bytes_count)?;

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
