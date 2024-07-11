#![no_std]
#![no_main]

use aya_ebpf::{helpers::bpf_get_current_pid_tgid, macros::kretprobe, programs::ProbeContext};

use socket_tracer_lib::{maps::ACTIVE_ACCEPT_MAP, vmlinux::socket};

#[kretprobe]
pub fn ret_sock_alloc(ctx: ProbeContext) -> u32 {
    try_ret_sock_alloc(ctx).unwrap_or_else(|ret| ret.try_into().unwrap_or_else(|_| 1))
}

fn try_ret_sock_alloc(ctx: ProbeContext) -> Result<u32, i64> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let sock: *const socket = ctx.ret().ok_or(1i64)?;

    let accept_args = unsafe { ACTIVE_ACCEPT_MAP.get_ptr_mut(&pid_tgid).ok_or(1i64)? };
    unsafe {
        if (*accept_args).sock.is_null() {
            (*accept_args).sock = sock;
        }
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
