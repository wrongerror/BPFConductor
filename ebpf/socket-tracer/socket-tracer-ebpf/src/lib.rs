#![no_std]
#![no_main]

use core::{cmp::PartialEq, fmt::Debug};

use aya_ebpf::{
    cty::ssize_t,
    helpers::{bpf_ktime_get_ns, bpf_probe_read_kernel, bpf_probe_read_user},
    programs::TracePointContext,
};
use aya_log_ebpf::debug;

use helpers::get_tgid_start_time;
use socket_tracer_common::{
    AF_INET, AF_INET6, AF_UNKNOWN, CHUNK_LIMIT, CONN_STATS_DATA_THRESHOLD, ConnId,
    ConnInfo, ConnStatsEvent, ControlEventType, ControlValueIndex, EndpointRole,
    LOOP_LIMIT,
    MAX_MSG_SIZE,
    MessageType, PROTOCOL_VEC_LIMIT, SocketControlEvent, SocketDataEvent, SocketDataEventInner, SourceFunction, TrafficDirection,
    TrafficDirection::{Egress, Ingress}, TrafficProtocol, Uid,
};

use crate::{
    filters::{
        is_self_tgid, should_trace_conn, should_trace_protocol_data, should_trace_sockaddr_family,
    },
    helpers::bpf_probe_read_buf_with_size,
    maps::{
        CONN_DISABLED_MAP, CONN_INFO_MAP, CONN_STATS_EVENT_BUFFER, CONN_STATS_EVENTS,
        CONTROL_VALUES, SOCKET_CONTROL_EVENTS, SOCKET_DATA_EVENT_BUFFER, SOCKET_DATA_EVENTS,
    },
    types::ConnectArgs,
    vmlinux::{iovec, sock, sock_common, sockaddr, sockaddr_in, sockaddr_in6, socket},
};

pub mod filters;
pub mod helpers;
pub mod maps;
pub mod protocols;
pub mod types;
#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
pub mod vmlinux;

#[repr(u32)]
#[derive(Debug, PartialEq)]
pub enum TargetTgidMatchResult {
    Unspecified,
    All,
    Matched,
    Unmatched,
}

pub fn match_trace_tgid(tgid: u32) -> TargetTgidMatchResult {
    let idx = ControlValueIndex::TargetTGIDIndex as u32;
    let target_tgid_val = unsafe { CONTROL_VALUES.get(idx) };
    match target_tgid_val {
        Some(&target_tgid) => {
            if target_tgid <= 0 {
                TargetTgidMatchResult::All
            } else if target_tgid as u32 == tgid {
                TargetTgidMatchResult::Matched
            } else {
                TargetTgidMatchResult::Unmatched
            }
        }
        None => TargetTgidMatchResult::Unspecified,
    }
}

pub fn update_traffic_class(
    ctx: &TracePointContext,
    tgid_fd: u64,
    conn_info: &mut ConnInfo,
    direction: TrafficDirection,
    buf_ptr: *const u8,
    count: usize,
) -> Result<u32, i64> {
    conn_info.protocol_total_count += 1;

    let inferred_protocol = protocols::infer_protocol(ctx, buf_ptr, count);
    match inferred_protocol.protocol {
        TrafficProtocol::Unknown => {
            return Ok(0);
        }
        protocol => {
            conn_info.protocol = protocol;
            if conn_info.role == EndpointRole::Unknown
                && inferred_protocol.msg_type != MessageType::Unknown
            {
                //    direction  req_resp_type  => role
                //    ------------------------------------
                //    Egress    Request       => Client
                //    Egress    Response      => Server
                //    Ingress   Request       => Server
                //    Ingress   Response      => Client
                conn_info.role = if (direction == Egress)
                    ^ (inferred_protocol.msg_type == MessageType::Response)
                {
                    EndpointRole::Client
                } else {
                    EndpointRole::Server
                };
            }
        }
    }

    unsafe { CONN_INFO_MAP.insert(&tgid_fd, conn_info, 0)? }

    Ok(0)
}

pub fn parse_sock_data(
    ctx: &TracePointContext,
    sock: *const socket,
    conn_info: &mut ConnInfo,
) -> Result<u32, i64> {
    let sk_ptr = unsafe { &(*sock).sk as *const *mut sock };
    let sk = unsafe { bpf_probe_read_kernel(sk_ptr)? };
    let sk_common =
        unsafe { bpf_probe_read_kernel(&(*sk).__sk_common as *const sock_common).map_err(|e| e)? };
    // read connection data
    match sk_common.skc_family as u32 {
        AF_INET => {
            let src_addr =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr });
            let dst_addr: u32 =
                u32::from_be(unsafe { sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr });
            let src_port = unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num };
            let dst_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });
            conn_info.sa_family = AF_INET;
            conn_info.src_addr_in4 = src_addr;
            conn_info.dst_addr_in4 = dst_addr;
            conn_info.src_port = src_port as u32;
            conn_info.dst_port = dst_port as u32;
            debug!(
                ctx,
                "AF_INET: tgid={}, src_addr={:i}, dst_addr={:i}, src_port={}, dst_port={}",
                conn_info.id.uid.tgid,
                src_addr,
                dst_addr,
                src_port,
                dst_port
            );
        }
        AF_INET6 => {
            let src_addr = unsafe { sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8 };
            let dst_addr = unsafe { sk_common.skc_v6_daddr.in6_u.u6_addr8 };
            let src_port = unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_num };
            let dst_port =
                u16::from_be(unsafe { sk_common.__bindgen_anon_3.__bindgen_anon_1.skc_dport });
            conn_info.sa_family = AF_INET6;
            conn_info.src_addr_in6 = src_addr;
            conn_info.dst_addr_in6 = dst_addr;
            conn_info.src_port = src_port as u32;
            conn_info.dst_port = dst_port as u32;
        }
        _ => return Err(1),
    }

    Ok(0)
}

pub fn parse_sockaddr_data(
    ctx: &TracePointContext,
    sockaddr: *const sockaddr,
    conn_info: &mut ConnInfo,
) -> Result<u32, i64> {
    conn_info.sa_family =
        unsafe { bpf_probe_read_user(&(*sockaddr).sa_family as *const u16)? as u32 };
    match conn_info.sa_family {
        AF_INET => {
            let sa_ptr_in = sockaddr as *const sockaddr_in;
            let sa_in = unsafe { bpf_probe_read_user(sa_ptr_in).map_err(|e| e)? };
            conn_info.dst_addr_in4 = u32::from_be(sa_in.sin_addr.s_addr);
            conn_info.dst_port = u16::from_be(sa_in.sin_port) as u32;
            debug!(
                ctx,
                "parse_sockaddr_data AF_INET src address: {:i}, dest address: {:i}",
                conn_info.src_addr_in4,
                conn_info.dst_addr_in4,
            );
        }
        AF_INET6 => {
            let sa_ptr_in6 = sockaddr as *const sockaddr_in6;
            let sa_in6 = unsafe { bpf_probe_read_user(sa_ptr_in6).map_err(|e| e)? };
            conn_info.dst_addr_in6 = unsafe { sa_in6.sin6_addr.in6_u.u6_addr8 };
            conn_info.dst_port = u16::from_be(sa_in6.sin6_port) as u32;
            debug!(
                ctx,
                "parse_sockaddr_data AF_INET6 src address: {:i}, dest address: {:i}",
                conn_info.src_addr_in6,
                conn_info.dst_addr_in6,
            )
        }
        _ => return Err(1),
    }
    Ok(0)
}

// perf submit functions

#[repr(C)]
pub struct OpenEventArgs {
    pub tgid: u32,
    pub fd: i32,
    pub sockaddr: *const sockaddr,
    pub sk: *const socket,
    pub role: EndpointRole,
    pub source_fn: SourceFunction,
}

pub fn init_and_insert_conn_info(
    ctx: &TracePointContext,
    args: &OpenEventArgs,
) -> Result<u32, i64> {
    let mut conn_info = ConnInfo::default();
    init_conn_info(args.tgid, args.fd, &mut conn_info);
    conn_info.role = args.role;

    if !args.sk.is_null() {
        parse_sock_data(ctx, args.sk, &mut conn_info)?;
    } else if !args.sockaddr.is_null() {
        parse_sockaddr_data(ctx, args.sockaddr, &mut conn_info)?;
    }

    let tgid_fd = gen_tgid_fd(args.tgid, args.fd);
    unsafe {
        CONN_INFO_MAP.insert(&tgid_fd, &conn_info, 0)?;
    }

    if !should_trace_sockaddr_family(conn_info.sa_family) {
        return Err(1);
    }

    Ok(0)
}

pub fn output_socket_control_event(
    ctx: &TracePointContext,
    tgid_fd: u64,
    source_function: SourceFunction,
) -> Result<u32, i64> {
    let conn_info = unsafe { CONN_INFO_MAP.get(&tgid_fd).ok_or(1i64)? };

    let mut event = SocketControlEvent {
        id: conn_info.id,
        event_type: ControlEventType::Open,
        sa_family: conn_info.sa_family as u64,
        source_function,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        src_addr_in4: conn_info.src_addr_in4,
        src_addr_in6: [0; 16],
        src_port: conn_info.src_port,
        dst_addr_in4: conn_info.dst_addr_in4,
        dst_addr_in6: [0; 16],
        dst_port: conn_info.dst_port,
        role: conn_info.role,
        write_bytes: conn_info.write_bytes,
        read_bytes: conn_info.read_bytes,
    };

    // Manually copy src_addr_in6
    // Since the eBPF virtual machine does not support the memmove function,
    // we need to manually copy each byte to avoid using memmove.
    for i in 0..16 {
        event.src_addr_in6[i] = conn_info.src_addr_in6[i];
    }

    // Manually copy dst_addr_in6
    // Similarly, manually copy each byte to ensure the program can load and
    // run correctly in the eBPF virtual machine.
    for i in 0..16 {
        event.dst_addr_in6[i] = conn_info.dst_addr_in6[i];
    }

    unsafe {
        SOCKET_CONTROL_EVENTS.output(ctx, &event, 0);
    }

    Ok(0)
}

pub fn submit_open_event(ctx: &TracePointContext, args: &OpenEventArgs) -> Result<u32, i64> {
    init_and_insert_conn_info(ctx, args)?;
    let tgid_fd = gen_tgid_fd(args.tgid, args.fd);
    output_socket_control_event(ctx, tgid_fd, args.source_fn)?;
    Ok(0)
}

pub fn submit_close_event(
    ctx: &TracePointContext,
    conn_info: &ConnInfo,
    src_fn: SourceFunction,
) -> Result<u32, i64> {
    let socket_control_event = SocketControlEvent {
        id: conn_info.id,
        event_type: ControlEventType::Close,
        sa_family: conn_info.sa_family as u64,
        source_function: src_fn,
        timestamp_ns: unsafe { bpf_ktime_get_ns() },
        src_addr_in4: conn_info.src_addr_in4,
        src_addr_in6: conn_info.src_addr_in6,
        src_port: conn_info.src_port,
        dst_addr_in4: conn_info.dst_addr_in4,
        dst_addr_in6: conn_info.dst_addr_in6,
        dst_port: conn_info.dst_port,
        role: conn_info.role,
        write_bytes: conn_info.write_bytes,
        read_bytes: conn_info.read_bytes,
    };

    unsafe {
        SOCKET_CONTROL_EVENTS.output(ctx, &socket_control_event, 0);
    }
    Ok(0)
}

pub fn perf_submit_buf(
    ctx: &TracePointContext,
    buf: *const u8,
    mut buf_size: usize,
    event: &mut SocketDataEvent,
) -> Result<u32, i64> {
    event.inner.msg_size = buf_size as u32;

    if buf_size == 0 {
        return Ok(0);
    }

    // Note that buf_size_minus_1 will be positive due to the if-statement above.
    let buf_size_minus_1 = buf_size - 1;

    buf_size = buf_size_minus_1 + 1;

    let mut amount_copied = 0;
    let msg = event.msg.as_mut();
    if buf_size_minus_1 < MAX_MSG_SIZE {
        unsafe {
            bpf_probe_read_buf_with_size(msg, buf_size, buf)?;
        }
        amount_copied = buf_size;
    } else if buf_size_minus_1 < 0x7fffffff {
        // If-statement condition above is only required to prevent Rust compiler from optimizing
        // away the `if (amount_copied > 0)` below.
        unsafe {
            bpf_probe_read_buf_with_size(msg, MAX_MSG_SIZE, buf)?;
        }
        amount_copied = MAX_MSG_SIZE;
    }

    // If-statement is redundant, but is required to keep the verifier happy.
    if amount_copied > 0 {
        event.inner.msg_buf_size = amount_copied as u32;
        unsafe {
            let data_size = size_of::<SocketDataEventInner>() + amount_copied;
            SOCKET_DATA_EVENTS.output_with_size(ctx, event, data_size as u64, 0);
        }
    }
    Ok(0)
}

pub fn submit_data_event(
    ctx: &TracePointContext,
    buf: *const u8,
    buf_size: usize,
    event: &mut SocketDataEvent,
) -> Result<u32, i64> {
    let mut bytes_submitted: usize = 0;
    for i in 0..CHUNK_LIMIT {
        let bytes_remaining = buf_size - bytes_submitted;
        if bytes_remaining <= 0 {
            break;
        }
        let current_size: usize = if bytes_remaining > MAX_MSG_SIZE && i != CHUNK_LIMIT - 1 {
            MAX_MSG_SIZE
        } else {
            bytes_remaining
        };
        let current_buf = unsafe { buf.add(bytes_submitted) };
        perf_submit_buf(ctx, current_buf, current_size, event)?;
        bytes_submitted += current_size;

        event.inner.position += current_size as u64;
    }

    Ok(0)
}

pub fn submit_data_event_iovecs(
    ctx: &TracePointContext,
    iov: *mut iovec,
    iovlen: u64,
    total_size: usize,
    event: &mut SocketDataEvent,
) -> Result<u32, i64> {
    let mut bytes_sent = 0;

    for i in 0..LOOP_LIMIT {
        if i >= iovlen as usize {
            break;
        }

        if bytes_sent >= total_size {
            break;
        }

        let iov_ptr = unsafe { iov.add(i) };
        let iov_cpy = unsafe { bpf_probe_read_user(iov_ptr as *const iovec)? };
        let bytes_remaining = total_size - bytes_sent;
        let iov_size = bytes_remaining.min(iov_cpy.iov_len as usize);

        perf_submit_buf(ctx, iov_cpy.iov_base as *const u8, iov_size, event)?;
        bytes_sent += iov_size;
        event.inner.position += iov_size as u64;
    }

    Ok(0)
}

// process functions

pub fn should_send_data(
    tgid: u32,
    conn_disabled_tsid: u64,
    force_trace_tgid: bool,
    conn_info: &ConnInfo,
) -> bool {
    if is_self_tgid(tgid) {
        return false;
    }

    if conn_info.id.tsid <= conn_disabled_tsid {
        return false;
    }

    return force_trace_tgid || should_trace_protocol_data(conn_info);
}

pub fn update_conn_stats(
    ctx: &TracePointContext,
    tgid_fd: u64,
    conn_info: &mut ConnInfo,
    direction: TrafficDirection,
    bytes_count: ssize_t,
) -> Result<u32, i64> {
    match direction {
        Egress => {
            conn_info.write_bytes += bytes_count as i64;
        }
        Ingress => {
            conn_info.read_bytes += bytes_count as i64;
        }
    }

    let total_bytes = conn_info.write_bytes + conn_info.read_bytes;
    let meets_activity_threshold =
        total_bytes >= conn_info.prev_reported_bytes + CONN_STATS_DATA_THRESHOLD;

    if meets_activity_threshold {
        let event = populate_conn_stats_event(conn_info)?;
        unsafe {
            CONN_STATS_EVENTS.output(ctx, event, 0);
        }
        conn_info.prev_reported_bytes = total_bytes;
    }

    unsafe { CONN_INFO_MAP.insert(&tgid_fd, conn_info, 0)? }

    Ok(0)
}

#[repr(C)]
pub struct ProcessDataArgs {
    vecs: bool,
    pid_tgid: u64,
    direction: TrafficDirection,
    bytes_count: ssize_t,
}

pub fn process_data(
    ctx: &TracePointContext,
    args: &types::DataArgs,
    extra_args: &ProcessDataArgs,
) -> Result<u32, i64> {
    let tgid: u32 = (extra_args.pid_tgid >> 32) as u32;

    if !extra_args.vecs && args.buf.is_null() {
        return Ok(0);
    }

    if extra_args.vecs && (args.iov.is_null() || args.iovlen <= 0) {
        return Ok(0);
    }

    if args.fd < 0 {
        return Ok(0);
    }

    if extra_args.bytes_count <= 0 {
        return Ok(0);
    }

    let match_result = match_trace_tgid(tgid);
    if match_result == TargetTgidMatchResult::Unmatched {
        return Ok(0);
    }

    let force_trace_tgid = match_result == TargetTgidMatchResult::Matched;

    let mut conn_info = get_or_create_conn_info(tgid, args.fd)?;
    if !should_trace_conn(&conn_info) {
        return Ok(0);
    }

    let tgid_fd = gen_tgid_fd(tgid, args.fd);
    let conn_disabled_tsid = unsafe { CONN_DISABLED_MAP.get(&tgid_fd).copied().unwrap_or(0) };

    if extra_args.vecs {
        for i in 0..PROTOCOL_VEC_LIMIT {
            if i >= args.iovlen as usize {
                break;
            }
            let iov_ptr = unsafe { args.iov.add(0) };
            let iov = unsafe { bpf_probe_read_user(iov_ptr as *const iovec) }
                .map_err(|err| err as i64)?;
            let buf_size = extra_args.bytes_count.min(iov.iov_len as ssize_t);
            if buf_size != 0 {
                update_traffic_class(
                    ctx,
                    tgid_fd,
                    &mut conn_info,
                    extra_args.direction,
                    iov.iov_base as *const u8,
                    buf_size as usize,
                )?;
                break;
            }
        }
    } else {
        update_traffic_class(
            ctx,
            tgid_fd,
            &mut conn_info,
            extra_args.direction,
            args.buf,
            extra_args.bytes_count as usize,
        )?;
    }

    if should_send_data(tgid, conn_disabled_tsid, force_trace_tgid, &conn_info) {
        let event =
            populate_socket_data_event(args.source_function, extra_args.direction, &conn_info)?;
        if extra_args.vecs {
            _ = submit_data_event_iovecs(
                ctx,
                args.iov,
                args.iovlen,
                extra_args.bytes_count as usize,
                event,
            );
        } else {
            _ = submit_data_event(ctx, args.buf, extra_args.bytes_count as usize, event);
        }
    }

    update_conn_stats(
        ctx,
        tgid_fd,
        &mut conn_info,
        extra_args.direction,
        extra_args.bytes_count,
    )?;

    Ok(0)
}

pub fn process_syscall_data(
    ctx: &TracePointContext,
    pid_tgid: u64,
    direction: TrafficDirection,
    args: &types::DataArgs,
    bytes_count: ssize_t,
) -> Result<u32, i64> {
    let extra_args = ProcessDataArgs {
        vecs: false,
        pid_tgid,
        direction,
        bytes_count,
    };
    process_data(ctx, args, &extra_args)
}

pub fn process_syscall_data_vecs(
    ctx: &TracePointContext,
    pid_tgid: u64,
    direction: TrafficDirection,
    args: &types::DataArgs,
    bytes_count: ssize_t,
) -> Result<u32, i64> {
    let extra_args = ProcessDataArgs {
        vecs: true,
        pid_tgid,
        direction,
        bytes_count,
    };
    process_data(ctx, args, &extra_args)
}

pub fn gen_tgid_fd(tgid: u32, fd: i32) -> u64 {
    ((tgid as u64) << 32) | (fd as u64)
}

pub fn gen_tsid() -> u64 {
    unsafe { bpf_ktime_get_ns() as u64 }
}

pub fn init_conn_id(tgid: u32, fd: i32) -> ConnId {
    ConnId {
        uid: Uid {
            tgid: tgid as u64,
            start_time_ticks: get_tgid_start_time().unwrap_or(0),
        },
        fd: fd as i64,
        tsid: gen_tsid(),
    }
}

pub fn init_conn_info(tgid: u32, fd: i32, conn_info: &mut ConnInfo) {
    conn_info.id = init_conn_id(tgid, fd);
    conn_info.role = EndpointRole::Unknown;
    conn_info.sa_family = AF_UNKNOWN;
}

pub fn get_or_create_conn_info(tgid: u32, fd: i32) -> Result<ConnInfo, i64> {
    let tgid_fd = gen_tgid_fd(tgid, fd);
    if let Some(&info) = unsafe { CONN_INFO_MAP.get(&tgid_fd) } {
        return Ok(info);
    }

    let mut conn_info = ConnInfo::default();
    init_conn_info(tgid, fd, &mut conn_info);

    unsafe {
        CONN_INFO_MAP.insert(&tgid_fd, &conn_info, 0)?;
    }

    Ok(conn_info)
}

pub fn populate_socket_data_event(
    src_fn: SourceFunction,
    direction: TrafficDirection,
    conn_info: &ConnInfo,
) -> Result<&mut SocketDataEvent, i64> {
    let idx: u32 = 0;
    let event_ptr = unsafe { SOCKET_DATA_EVENT_BUFFER.get_ptr_mut(idx).ok_or(1i64)? };
    let event = unsafe { event_ptr.as_mut().ok_or(1i64)? };
    event.inner.timestamp_ns = unsafe { bpf_ktime_get_ns() };
    event.inner.source_function = src_fn;
    event.inner.direction = direction;
    event.inner.id = conn_info.id;
    event.inner.protocol = conn_info.protocol;
    event.inner.role = conn_info.role;
    event.inner.position = match direction {
        Egress => conn_info.write_bytes as u64,
        Ingress => conn_info.read_bytes as u64,
    };

    Ok(event)
}

pub fn populate_conn_stats_event(conn_info: &ConnInfo) -> Result<&mut ConnStatsEvent, i64> {
    let idx: u32 = 0;
    let event_ptr = unsafe { CONN_STATS_EVENT_BUFFER.get_ptr_mut(idx).ok_or(1i64)? };
    let event = unsafe { event_ptr.as_mut().ok_or(1i64)? };

    event.id = conn_info.id;
    event.src_addr_in4 = conn_info.src_addr_in4;
    event.src_addr_in6 = conn_info.src_addr_in6;
    event.src_port = conn_info.src_port;
    event.dst_addr_in4 = conn_info.dst_addr_in4;
    event.dst_addr_in6 = conn_info.dst_addr_in6;
    event.dst_port = conn_info.dst_port;
    event.role = conn_info.role;
    event.write_bytes = conn_info.write_bytes;
    event.read_bytes = conn_info.read_bytes;
    event.event_flags = 0;
    event.timestamp_ns = unsafe { bpf_ktime_get_ns() };

    Ok(event)
}

pub fn process_implicit_conn(
    ctx: &TracePointContext,
    pid_tgid: u64,
    connect_args: &ConnectArgs,
    source_function: SourceFunction,
) {
    if connect_args.sockaddr.is_null() {
        return;
    }

    let tgid = (pid_tgid >> 32) as u32;

    if match_trace_tgid(tgid) == TargetTgidMatchResult::Unmatched {
        return;
    }

    if connect_args.fd < 0 {
        return;
    }

    let tgid_fd = gen_tgid_fd(tgid, connect_args.fd);

    if unsafe { CONN_INFO_MAP.get(&tgid_fd) }.is_some() {
        return;
    }

    let open_event_args = OpenEventArgs {
        tgid,
        fd: connect_args.fd,
        sockaddr: connect_args.sockaddr,
        sk: core::ptr::null(),
        role: EndpointRole::Unknown,
        source_fn: source_function,
    };

    _ = submit_open_event(ctx, &open_event_args);
}
