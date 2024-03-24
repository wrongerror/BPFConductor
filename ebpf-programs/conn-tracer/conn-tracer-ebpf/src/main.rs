#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_ktime_get_ns, bpf_probe_read_kernel},
    macros::{kprobe, map, tracepoint},
    programs::{ProbeContext, TracePointContext},
};
use conn_tracer_common::{
    vmlinux::{sock, sock_common, tcp_sock},
    ConnectionKey, ConnectionStats, SockInfo, AF_INET, AF_INET6, CONNECTION_ROLE_CLIENT,
    CONNECTION_ROLE_SERVER, CONNECTION_ROLE_UNKNOWN, INET_SOCK_NEWSTATE_OFFSET,
    INET_SOCK_SKADDR_OFFSET, MAX_CONNECTIONS, TCP_CLOSE, TCP_SYN_RECV, TCP_SYN_SENT,
};

#[map(name = "SOCKETS")]
static mut SOCKETS: aya_ebpf::maps::LruHashMap<*const sock, SockInfo> =
    aya_ebpf::maps::LruHashMap::<*const sock, SockInfo>::pinned(MAX_CONNECTIONS, 0);

#[map(name = "CONNECTIONS")]
static mut CONNECTIONS: aya_ebpf::maps::LruHashMap<ConnectionKey, ConnectionStats> =
    aya_ebpf::maps::LruHashMap::<ConnectionKey, ConnectionStats>::pinned(MAX_CONNECTIONS, 0);

#[kprobe]
pub fn sock_conn_tracer(ctx: ProbeContext) -> u32 {
    match try_sock_conn_tracer(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_sock_conn_tracer(ctx: ProbeContext) -> Result<u32, i64> {
    // first argument to tcp_data_queue is a struct sock*
    let sk: *const sock = ctx.arg(0).ok_or(1i64)?;
    let mut conn_key = ConnectionKey::default();
    let mut conn_stats = ConnectionStats::default();

    parse_sock_data(sk, &mut conn_key, &mut conn_stats)?;

    if conn_key.dest_addr == 0 && conn_key.dest_port == 0 {
        return Ok(0);
    }

    match unsafe { SOCKETS.get(&sk) } {
        Some(&sock_info) => {
            conn_key.id = sock_info.id;
            conn_key.pid = sock_info.pid;
            conn_key.role = sock_info.role;
            if sock_info.is_active == 0u32 {
                return Err(1i64);
            }
            conn_stats.is_active = sock_info.is_active as u64;
            unsafe {
                CONNECTIONS.insert(&conn_key, &conn_stats, 0_u64)?;
            }
        }
        None => {
            let sock_info = SockInfo {
                id: get_unique_id(),
                pid: 0,
                is_active: 1,
                role: get_sock_role(sk),
            };

            unsafe {
                SOCKETS.insert(&sk, &sock_info, 0_u64)?;
            }

            conn_key.id = sock_info.id;
            conn_key.pid = sock_info.pid;
            conn_key.role = sock_info.role;
            conn_stats.is_active = 1;

            unsafe {
                CONNECTIONS.insert(&conn_key, &conn_stats, 0_u64)?;
            }
        }
    }

    Ok(0)
}

fn parse_sock_data(
    sk: *const sock,
    conn_key: &mut ConnectionKey,
    conn_stats: &mut ConnectionStats,
) -> Result<u32, i64> {
    let sk_common =
        unsafe { bpf_probe_read_kernel(&(*sk).__sk_common as *const sock_common).map_err(|e| e)? };

    let tcp_sk = sk as *const tcp_sock;

    // read throughput data
    conn_stats.bytes_sent =
        unsafe { bpf_probe_read_kernel(&(*tcp_sk).bytes_sent as *const u64).map_err(|e| e)? };
    conn_stats.bytes_received =
        unsafe { bpf_probe_read_kernel(&(*tcp_sk).bytes_received as *const u64).map_err(|e| e)? };

    // read connection data
    match sk_common.skc_family {
        AF_INET => {
            let src_addr =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let dest_addr: u32 =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
            let src_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num });
            let dest_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });
            conn_key.src_addr = src_addr;
            conn_key.dest_addr = dest_addr;
            conn_key.src_port = src_port as u32;
            conn_key.dest_port = dest_port as u32;
            Ok(0)
        }
        AF_INET6 => Err(1i64),
        _ => Err(1i64),
    }
}

fn get_sock_role(sk: *const sock) -> u32 {
    let max_ack_backlog = unsafe { bpf_probe_read_kernel(&(*sk).sk_max_ack_backlog as *const u32) };
    match max_ack_backlog {
        Ok(role) => {
            if role == 0 {
                CONNECTION_ROLE_CLIENT
            } else {
                CONNECTION_ROLE_SERVER
            }
        }
        Err(_) => CONNECTION_ROLE_UNKNOWN,
    }
}

fn get_unique_id() -> u32 {
    unsafe { bpf_ktime_get_ns() as u32 }
}

#[tracepoint]
pub fn sock_state_tracer(ctx: TracePointContext) -> u32 {
    match try_state_tracer(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_state_tracer(ctx: TracePointContext) -> Result<u32, i64> {
    let sk: *const sock = unsafe { ctx.read_at::<*const sock>(INET_SOCK_SKADDR_OFFSET)? };
    let new_state: i32 = unsafe { ctx.read_at::<i32>(INET_SOCK_NEWSTATE_OFFSET)? };

    match new_state {
        TCP_SYN_RECV => handle_tcp_syn_recv(sk),
        TCP_SYN_SENT => handle_tcp_syn_sent(sk),
        TCP_CLOSE => handle_tcp_close(sk),
        _ => Ok(0),
    }
}

fn handle_tcp_syn_sent(sk: *const sock) -> Result<u32, i64> {
    let id = get_unique_id();
    let pid = bpf_get_current_pid_tgid() as u32;
    let sock_info = SockInfo {
        id,
        pid,
        is_active: 1,
        role: CONNECTION_ROLE_CLIENT,
    };

    unsafe {
        SOCKETS.insert(&sk, &sock_info, 0_u64)?;
    }

    Ok(0)
}

fn handle_tcp_syn_recv(sk: *const sock) -> Result<u32, i64> {
    let mut conn_key = ConnectionKey::default();
    let mut conn_stats = ConnectionStats::default();

    parse_sock_data(sk, &mut conn_key, &mut conn_stats)?;

    let sock_info = SockInfo {
        id: get_unique_id(),
        pid: 0,
        is_active: 1,
        role: CONNECTION_ROLE_SERVER,
    };

    unsafe {
        SOCKETS.insert(&sk, &sock_info, 0_u64)?;
    }

    if conn_key.dest_addr == 0 {
        return Ok(0);
    }

    conn_key.id = sock_info.id;
    conn_key.pid = sock_info.pid;
    conn_key.role = sock_info.role;

    unsafe {
        CONNECTIONS.insert(&conn_key, &conn_stats, 0_u64)?;
    }

    Ok(0)
}

fn handle_tcp_close(sk: *const sock) -> Result<u32, i64> {
    let mut conn_key = ConnectionKey::default();
    let mut conn_stats = ConnectionStats::default();

    parse_sock_data(sk, &mut conn_key, &mut conn_stats)?;

    if let Some(sock_info) = unsafe { SOCKETS.get(&sk) } {
        conn_key.id = sock_info.id;
        conn_key.pid = sock_info.pid;
        conn_key.role = sock_info.role;
        unsafe {
            SOCKETS.remove(&sk)?;
        }
    } else {
        conn_key.id = get_unique_id();
        conn_key.pid = 0;
        conn_key.role = get_sock_role(sk);
    }

    conn_stats.is_active = 0;
    unsafe {
        CONNECTIONS.insert(&conn_key, &conn_stats, 0_u64)?;
    }

    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
