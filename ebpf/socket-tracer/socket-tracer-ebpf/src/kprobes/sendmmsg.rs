#![no_std]
#![no_main]

use aya_ebpf::{
    cty::ssize_t,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::tracepoint,
    programs::TracePointContext,
};

use socket_tracer_common::{SourceFunction, TrafficDirection::Egress};
use socket_tracer_lib::{
    maps::{ACTIVE_CONNECT_MAP, ACTIVE_WRITE_MAP},
    process_implicit_conn, process_syscall_data_vecs, types,
    types::AlignedBool,
    vmlinux::{mmsghdr, sockaddr},
};

pub const SENDMMSG_FD_OFFSET: usize = 16;
pub const SENDMMSG_MMSG_OFFSET: usize = 24;
pub const SENDMMSG_VLEN_OFFSET: usize = 32;
pub const SENDMMSG_FLAGS_OFFSET: usize = 40;
pub const SENDMMSG_RET_OFFSET: usize = 16;

#[tracepoint]
pub fn entry_sendmmsg(ctx: TracePointContext) -> u32 {
    try_entry_sendmmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_sendmmsg(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd: i32 = unsafe { ctx.read_at(SENDMMSG_FD_OFFSET)? };
    let msgvec: *const mmsghdr = unsafe { ctx.read_at(SENDMMSG_MMSG_OFFSET)? };
    let vlen: u32 = unsafe { ctx.read_at(SENDMMSG_VLEN_OFFSET)? };

    if !msgvec.is_null() && vlen >= 1 {
        let mmsg_hdr = unsafe { bpf_probe_read_kernel(msgvec).map_err(|_| 1i64)? };
        let msg_hdr = mmsg_hdr.msg_hdr;
        if !msg_hdr.msg_name.is_null() {
            let connect_args = types::ConnectArgs {
                sockaddr: msg_hdr.msg_name as *const sockaddr,
                fd,
            };

            unsafe {
                _ = ACTIVE_CONNECT_MAP.insert(&pid_tgid, &connect_args, 0);
            }
        }

        let data_args = types::DataArgs {
            source_function: SourceFunction::SyscallSendMMsg,
            sock_event: AlignedBool::False,
            fd,
            buf: core::ptr::null(),
            iov: msg_hdr.msg_iov,
            iovlen: msg_hdr.msg_iovlen,
            msg_len: mmsg_hdr.msg_len,
        };

        unsafe {
            ACTIVE_WRITE_MAP.insert(&pid_tgid, &data_args, 0)?;
        }
    }
    Ok(0)
}

#[tracepoint]
pub fn ret_sendmmsg(ctx: TracePointContext) -> u32 {
    try_ret_sendmmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_sendmmsg(ctx: TracePointContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let num_msgs: u32 = unsafe { ctx.read_at(SENDMMSG_RET_OFFSET)? };

    if let Some(connect_args) = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid) } {
        if num_msgs > 0 {
            process_implicit_conn(
                &ctx,
                pid_tgid,
                connect_args,
                SourceFunction::SyscallSendMMsg,
            );
        }
    }

    unsafe {
        ACTIVE_CONNECT_MAP.remove(&pid_tgid)?;
    }

    let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1i64)? };
    let bytes_count = data_args.msg_len;
    let mut res = Result::<u32, i64>::Ok(0);
    if num_msgs > 0 {
        res = process_syscall_data_vecs(&ctx, pid_tgid, Egress, data_args, bytes_count as ssize_t);
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
