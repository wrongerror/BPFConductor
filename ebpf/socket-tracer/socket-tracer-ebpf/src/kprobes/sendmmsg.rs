#![no_std]
#![no_main]

use aya_ebpf::{
    cty::ssize_t,
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_kernel},
    macros::{kprobe, kretprobe},
    programs::ProbeContext,
};

use socket_tracer_common::{SourceFunction, TrafficDirection::Egress};
use socket_tracer_lib::{
    maps::{ACTIVE_CONNECT_MAP, ACTIVE_WRITE_MAP},
    process_syscall_data_vecs, types,
    types::AlignedBool,
    vmlinux::{mmsghdr, sockaddr},
};

#[kprobe]
pub fn entry_sendmmsg(ctx: ProbeContext) -> u32 {
    try_entry_sendmmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_sendmmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let fd: i32 = ctx.arg(0).ok_or(1)?;
    let msgvec: *const mmsghdr = ctx.arg(1).ok_or(1)?;
    let vlen: u32 = ctx.arg(2).ok_or(1)?;

    if !msgvec.is_null() && vlen >= 1 {
        let mmsg_hdr = unsafe { bpf_probe_read_kernel(msgvec).map_err(|_| 1)? };
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

#[kretprobe]
pub fn ret_sendmmsg(ctx: ProbeContext) -> u32 {
    try_ret_sendmmsg(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_sendmmsg(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let num_msgs: u32 = ctx.ret().ok_or(1)?;

    let connect_args = unsafe { ACTIVE_CONNECT_MAP.get(&pid_tgid) };
    if let Some(&_args) = connect_args {
        unsafe {
            _ = ACTIVE_CONNECT_MAP.remove(&pid_tgid);
        }
    }
    let data_args = unsafe { ACTIVE_WRITE_MAP.get(&pid_tgid).ok_or(1)? };
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
