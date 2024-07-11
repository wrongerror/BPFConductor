#![no_std]
#![no_main]

use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::kprobe, programs::ProbeContext};

use socket_tracer_lib::{
    maps::{ACTIVE_READ_MAP, ACTIVE_WRITE_MAP},
    types::AlignedBool,
};

#[kprobe]
pub fn entry_security_socket_sendmsg(ctx: ProbeContext) -> u32 {
    try_entry_security_socket_sendmsg(ctx)
        .unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_security_socket_sendmsg(_ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let data_args = unsafe { ACTIVE_WRITE_MAP.get_ptr_mut(&pid_tgid).ok_or(1i64)? };

    unsafe {
        (*data_args).sock_event = AlignedBool::True;
    }

    Ok(0)
}

#[kprobe]
pub fn entry_security_socket_recvmsg(ctx: ProbeContext) -> u32 {
    try_entry_security_socket_recvmsg(ctx)
        .unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_entry_security_socket_recvmsg(_ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let data_args = unsafe { ACTIVE_READ_MAP.get_ptr_mut(&pid_tgid).ok_or(1i64)? };

    unsafe {
        (*data_args).sock_event = AlignedBool::True;
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
