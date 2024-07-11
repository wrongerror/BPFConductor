use std::any::Any;
use std::cmp::PartialEq;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use lazy_static::lazy_static;
use log::{debug, error, info};
use parking_lot::Mutex;

use socket_tracer_common::{
    CONN_CLOSE, ConnId, ConnStatsEvent, ControlEventType, EndpointRole, SocketControlEvent,
    SocketDataEvent, TrafficDirection, TrafficProtocol,
};

use crate::progs::socket_tracer::protocols;
use crate::progs::socket_tracer::protocols::core::datastream::{DataStream, SslSource};
use crate::progs::socket_tracer::protocols::core::types::{
    NoState, ProtocolTrait, RecordsWithErrorCount, StateType,
};
use crate::progs::socket_tracer::protocols::http::types::HTTPState;
use crate::progs::socket_tracer::tracker_manager::ConnTrackerManager;
use crate::progs::socket_tracer::utils::{
    convert_dst_to_socket_addr, convert_src_to_socket_addr, is_unspecified,
};

pub(crate) const PARSE_FAILURE_RATE_THRESHOLD: f64 = 0.4;
pub(crate) const STITCH_FAILURE_RATE_THRESHOLD: f64 = 0.5;
pub(crate) const DEATH_COUNTDOWN_ITERS: i32 = 3;

fn create_trace_roles() -> HashMap<TrafficProtocol, HashSet<EndpointRole>> {
    let mut res = HashMap::new();
    res.insert(TrafficProtocol::Unknown, HashSet::new());
    res.insert(
        TrafficProtocol::HTTP,
        [EndpointRole::Server].iter().cloned().collect(),
    );
    res.insert(
        TrafficProtocol::HTTP2,
        [EndpointRole::Server].iter().cloned().collect(),
    );
    res.insert(
        TrafficProtocol::MySQL,
        [EndpointRole::Server, EndpointRole::Client]
            .iter()
            .cloned()
            .collect(),
    );
    res.insert(
        TrafficProtocol::PGSQL,
        [EndpointRole::Server].iter().cloned().collect(),
    );
    res.insert(
        TrafficProtocol::DNS,
        [EndpointRole::Client, EndpointRole::Server]
            .iter()
            .cloned()
            .collect(),
    );
    res.insert(
        TrafficProtocol::Redis,
        [EndpointRole::Server].iter().cloned().collect(),
    );
    res.insert(
        TrafficProtocol::NATS,
        [EndpointRole::Server].iter().cloned().collect(),
    );
    res.insert(
        TrafficProtocol::Kafka,
        [EndpointRole::Server].iter().cloned().collect(),
    );
    res.insert(
        TrafficProtocol::AMQP,
        [EndpointRole::Server].iter().cloned().collect(),
    );

    // 确保所有键都已设置
    assert_eq!(res.len(), 13);
    res
}

lazy_static! {
    static ref TRACE_ROLES: HashMap<TrafficProtocol, HashSet<EndpointRole>> = create_trace_roles();
}

fn should_trace_protocol_role(protocol: &TrafficProtocol, role: &EndpointRole) -> bool {
    TRACE_ROLES
        .get(protocol)
        .map_or(false, |roles| roles.contains(role))
}

#[derive(Debug, Clone)]
pub(crate) struct SocketOpen {
    pub timestamp_ns: u64,
    pub remote_addr: SocketAddr,
    pub local_addr: SocketAddr,
}

impl Default for SocketOpen {
    fn default() -> Self {
        SocketOpen {
            timestamp_ns: 0,
            remote_addr: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
            local_addr: SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SocketClose {
    pub timestamp_ns: u64,
    pub send_bytes: i64,
    pub recv_bytes: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TrackerState {
    Collecting,
    Transferring,
    Disabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TrackerStats {
    DataEventSent,
    DataEventRecv,
    BytesSent,
    BytesRecv,
    BytesSentTransferred,
    BytesRecvTransferred,
    ValidRecords,
    InvalidRecords,
}

#[derive(Debug, Clone)]
pub(crate) struct StatCounter {
    stats: HashMap<TrackerStats, u64>,
}

impl StatCounter {
    pub(crate) fn new() -> Self {
        Self {
            stats: HashMap::new(),
        }
    }

    pub(crate) fn increment(&mut self, key: TrackerStats, value: u64) {
        let counter = self.stats.entry(key).or_insert(0);
        *counter += value;
    }

    pub(crate) fn get(&self, key: TrackerStats) -> u64 {
        *self.stats.get(&key).unwrap_or(&0)
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ConnStatsTracker {
    bytes_recv: i64,
    bytes_sent: i64,
    closed: bool,
    last_reported_bytes_recv: i64,
    last_reported_bytes_sent: i64,
    last_reported_open: bool,
    last_reported_close: bool,
}

impl ConnStatsTracker {
    pub(crate) fn new() -> Self {
        Self {
            bytes_recv: 0,
            bytes_sent: 0,
            closed: false,
            last_reported_bytes_recv: 0,
            last_reported_bytes_sent: 0,
            last_reported_open: false,
            last_reported_close: false,
        }
    }

    pub(crate) fn set_closed(&mut self, closed: bool) {
        self.closed = closed;
    }

    pub(crate) fn set_bytes_recv(&mut self, bytes_recv: i64) {
        self.bytes_recv = bytes_recv;
    }

    pub(crate) fn set_bytes_sent(&mut self, bytes_sent: i64) {
        self.bytes_sent = bytes_sent;
    }

    pub(crate) fn bytes_recv(&self) -> i64 {
        self.bytes_recv
    }

    pub(crate) fn bytes_sent(&self) -> i64 {
        self.bytes_sent
    }

    pub(crate) fn closed(&self) -> bool {
        self.closed
    }

    pub(crate) fn open_since_last_read(&mut self) -> bool {
        let val = !self.last_reported_open;
        self.last_reported_open = true;
        val
    }

    pub(crate) fn close_since_last_read(&mut self) -> bool {
        let val = self.closed && !self.last_reported_close;
        self.last_reported_close = self.closed;
        val
    }

    pub(crate) fn bytes_recv_since_last_read(&mut self) -> i64 {
        let val = self.bytes_recv - self.last_reported_bytes_recv;
        self.last_reported_bytes_recv = self.bytes_recv;
        val
    }

    pub(crate) fn bytes_sent_since_last_read(&mut self) -> i64 {
        let val = self.bytes_sent - self.last_reported_bytes_sent;
        self.last_reported_bytes_sent = self.bytes_sent;
        val
    }
}

pub(crate) struct Inner {
    pub(crate) conn_id: ConnId,
    pub protocol: TrafficProtocol,
    pub role: EndpointRole,
    pub ssl: bool,
    pub open_info: SocketOpen,
    pub close_info: SocketClose,
    pub conn_stats: ConnStatsTracker,
    pub last_conn_stats_update: u64,
    pub final_conn_stats_reported: bool,
    pub ssl_source: SslSource,
    pub send_data: DataStream,
    pub recv_data: DataStream,
    pub idle_iteration: bool,
    pub idle_iteration_count: i32,
    pub idle_iteration_threshold: i32,
    pub disable_reason: String,
    pub death_countdown: i32,
    pub state: TrackerState,
    pub stats: StatCounter,
    pub protocol_state: Box<dyn StateType>,
    pub is_tracked_upid: bool,
    pub current_time: Instant,
    pub creation_timestamp: Instant,
    pub last_bpf_timestamp_ns: u64,
    pub last_activity_timestamp: Option<Instant>,
    pub inactivity_duration: Duration,
    pub conn_tracker_manager: Option<Arc<Mutex<ConnTrackerManager>>>,
}

pub(crate) struct ConnTracker {
    inner: Arc<Mutex<Inner>>,
}

impl fmt::Debug for ConnTracker {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let inner = self.inner.lock();
        f.debug_struct("ConnTracker")
            .field("conn_id", &inner.conn_id)
            .field("protocol", &inner.protocol)
            .field("role", &inner.role)
            .field("ssl", &inner.ssl)
            .field("open_info", &inner.open_info)
            .field("close_info", &inner.close_info)
            .field("conn_stats", &inner.conn_stats)
            .field("last_conn_stats_update", &inner.last_conn_stats_update)
            .field(
                "final_conn_stats_reported",
                &inner.final_conn_stats_reported,
            )
            .field("ssl_source", &inner.ssl_source)
            .field("send_data", &inner.send_data)
            .field("recv_data", &inner.recv_data)
            .field("idle_iteration", &inner.idle_iteration)
            .field("idle_iteration_count", &inner.idle_iteration_count)
            .field("idle_iteration_threshold", &inner.idle_iteration_threshold)
            .field("disable_reason", &inner.disable_reason)
            .field("death_countdown", &inner.death_countdown)
            .field("state", &inner.state)
            .field("stats", &inner.stats)
            .field("protocol_state", &inner.protocol_state)
            .field("is_tracked_upid", &inner.is_tracked_upid)
            .field("current_time", &inner.current_time)
            .field("creation_timestamp", &inner.creation_timestamp)
            .field("last_bpf_timestamp_ns", &inner.last_bpf_timestamp_ns)
            .field("last_activity_timestamp", &inner.last_activity_timestamp)
            .field("inactivity_duration", &inner.inactivity_duration)
            .finish()
    }
}

impl ConnTracker {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                conn_id: ConnId::default(),
                protocol: TrafficProtocol::Unknown,
                role: EndpointRole::Unknown,
                ssl: false,
                open_info: SocketOpen::default(),
                close_info: SocketClose::default(),
                conn_stats: ConnStatsTracker::new(),
                last_conn_stats_update: 0,
                final_conn_stats_reported: false,
                ssl_source: Default::default(),
                send_data: DataStream::new(0, 0, 0),
                recv_data: DataStream::new(0, 0, 0),
                idle_iteration: false,
                idle_iteration_count: 0,
                idle_iteration_threshold: 0,
                disable_reason: String::new(),
                death_countdown: -1,
                state: TrackerState::Collecting,
                stats: StatCounter::new(),
                protocol_state: Box::new(NoState),
                conn_tracker_manager: None,
                is_tracked_upid: false,
                current_time: Instant::now(),
                creation_timestamp: Instant::now(),
                last_bpf_timestamp_ns: 0,
                last_activity_timestamp: None,
                inactivity_duration: Duration::from_secs(300),
            })),
        }
    }

    pub(crate) fn set_inactivity_duration(&self, duration: Duration) {
        let mut inner = self.inner.lock();
        inner.inactivity_duration = duration;
    }

    pub(crate) fn set_current_time(&self, time: Instant) -> Result<()> {
        let mut inner = self.inner.lock();
        if time < inner.current_time {
            return Err(anyhow!(
                "New time must be greater than or equal to current time"
            ));
        }
        inner.current_time = time;
        Ok(())
    }

    pub(crate) fn add_event(&self, event: &SocketControlEvent) -> Result<()> {
        self.check_tracker()?;
        self.update_timestamps(event.timestamp_ns)?;

        match event.event_type {
            ControlEventType::Open => self.add_conn_open_event(event),
            ControlEventType::Close => self.add_conn_close_event(event),
        }
        Ok(())
    }

    fn add_conn_open_event(&self, event: &SocketControlEvent) {
        let remote_addr = convert_dst_to_socket_addr(&event);
        if remote_addr.is_none() {
            return;
        }
        let local_addr = convert_src_to_socket_addr(&event);
        if local_addr.is_none() {
            return;
        }
        let role = event.role;

        {
            let mut inner = self.inner.lock();
            if inner.open_info.timestamp_ns != 0 {
                debug!("Clobbering existing ConnOpenEvent.");
            }
            inner.open_info.timestamp_ns = event.timestamp_ns;
        }

        self.set_remote_addr(remote_addr.unwrap(), "Inferred from conn_open.");
        self.set_local_addr(local_addr.unwrap(), "Inferred from conn_open.");
        self.set_role(role, "Inferred from conn_open.");

        debug!("conn_open: {:?}", event);
    }

    fn add_conn_close_event(&self, event: &SocketControlEvent) {
        let mut inner = self.inner.lock();
        if inner.close_info.timestamp_ns != 0 {
            debug!("Clobbering existing ConnCloseEvent.");
        }
        inner.close_info.timestamp_ns = event.timestamp_ns;
        inner.close_info.send_bytes = event.write_bytes;
        inner.close_info.recv_bytes = event.read_bytes;

        if inner.protocol == TrafficProtocol::HTTP {
            let state = protocol_state::<HTTPState>(&mut inner.protocol_state);
            if state.is_none() {
                inner.protocol_state = Box::new(HTTPState::default())
            } else {
                let s = state.unwrap();
                s.global.conn_closed = true;
            }
        }

        inner.send_data.set_conn_closed();
        inner.recv_data.set_conn_closed();

        debug!("conn_close: {:?}", event);

        drop(inner);

        self.mark_for_death(0);
    }

    pub(crate) fn add_data_event(&self, event: Box<SocketDataEvent>) -> Result<()> {
        self.set_role(event.inner.role, "inferred from data_event");
        self.set_protocol(event.inner.protocol, "inferred from data_event");
        self.set_ssl(
            event.inner.ssl,
            SslSource::None, // TODO: handle ssl source.
            "inferred from data_event",
        );

        self.check_tracker()?;
        self.update_timestamps(event.inner.timestamp_ns)?;
        self.update_data_stats(&event);

        let mut inner = self.inner.lock();
        info!("Data event: {:?}", event);

        if event.inner.protocol == TrafficProtocol::Unknown {
            return Ok(());
        }

        if event.inner.protocol != inner.protocol {
            return Ok(());
        }

        if inner.state == TrackerState::Disabled {
            return Ok(());
        }

        match event.inner.direction {
            TrafficDirection::Egress => inner.send_data.add_data(event),
            TrafficDirection::Ingress => inner.recv_data.add_data(event),
        }
        Ok(())
    }

    pub(crate) fn add_conn_stats(&self, event: ConnStatsEvent) -> Result<()> {
        self.set_role(event.role, "inferred from conn_stats event");
        let remote_addr = convert_dst_to_socket_addr(&event)
            .ok_or_else(|| anyhow!("Unsupported address family"))?;
        self.set_remote_addr(remote_addr, "conn_stats event");
        let local_addr = convert_src_to_socket_addr(&event)
            .ok_or_else(|| anyhow!("Unsupported address family"))?;
        self.set_local_addr(local_addr, "conn_stats event");
        self.update_timestamps(event.timestamp_ns)?;

        debug!(
            "ConnStats timestamp={} wr={} rd={} close={}",
            event.timestamp_ns,
            event.write_bytes,
            event.read_bytes,
            event.event_flags & CONN_CLOSE
        );

        let mut inner = self.inner.lock();
        if event.timestamp_ns == inner.last_conn_stats_update {
            return Err(anyhow!("Timestamp is the same as the last update"));
        }

        if event.timestamp_ns > inner.last_conn_stats_update {
            if (event.event_flags & CONN_CLOSE != 0) < inner.conn_stats.closed() {
                return Err(anyhow!(
                    "Event close flag is less than connection closed status"
                ));
            }
            if event.read_bytes < inner.conn_stats.bytes_recv() {
                return Err(anyhow!(
                    "Event read bytes are less than connection received bytes"
                ));
            }
            if event.write_bytes < inner.conn_stats.bytes_sent() {
                return Err(anyhow!(
                    "Event write bytes are less than connection sent bytes"
                ));
            }

            inner.conn_stats.set_bytes_recv(event.read_bytes);
            inner.conn_stats.set_bytes_sent(event.write_bytes);
            inner
                .conn_stats
                .set_closed(event.event_flags & CONN_CLOSE != 0);

            inner.last_conn_stats_update = event.timestamp_ns;
        } else {
            if (event.event_flags & CONN_CLOSE != 0) > inner.conn_stats.closed() {
                return Err(anyhow!(
                    "Event close flag is greater than connection closed status"
                ));
            }
            if event.read_bytes > inner.conn_stats.bytes_recv() {
                return Err(anyhow!(
                    "Event read bytes are greater than connection received bytes"
                ));
            }
            if event.write_bytes > inner.conn_stats.bytes_sent() {
                return Err(anyhow!(
                    "Event write bytes are greater than connection sent bytes"
                ));
            }
        }

        Ok(())
    }

    pub(crate) fn process_to_records<P: ProtocolTrait>(&self) -> Vec<P::RecordType> {
        let mut inner = self.inner.lock();
        let mut result = RecordsWithErrorCount::new();
        info!("Processed records, count={}", result.records.len());

        self.update_result_stats::<P>(&result);

        result.records
    }

    pub(crate) fn reset(&self) {
        let mut inner = self.inner.lock();
        inner.send_data.reset();
        inner.recv_data.reset();
        inner.protocol_state = Box::new(NoState);
    }

    pub(crate) fn disable(&self, reason: &str) {
        let mut inner = self.inner.lock();
        if inner.state != TrackerState::Disabled {
            // TODO: Disables the connection tracker and also not accept any future data (update ebpf map )
            // if let Some(manager) = &self.manager {
            //     manager
            //     manager.lock().disable(self.conn_id);
            // }
            debug!(
                "Disabling connection dest={} reason={}",
                inner.open_info.remote_addr, reason
            );
        }

        inner.state = TrackerState::Disabled;
        inner.disable_reason = reason.to_string();

        self.reset();
    }

    pub(crate) fn all_events_received(&self) -> bool {
        let inner = self.inner.lock();
        inner.close_info.timestamp_ns != 0
            && inner.stats.get(TrackerStats::BytesSent) == inner.close_info.send_bytes as u64
            && inner.stats.get(TrackerStats::BytesRecv) == inner.close_info.recv_bytes as u64
    }

    pub(crate) fn set_conn_id(&self, conn_id: ConnId) -> Result<()> {
        let mut inner = self.inner.lock();
        if inner.conn_id.uid.tgid != 0 && inner.conn_id.uid.tgid != conn_id.uid.tgid {
            return Err(anyhow!("TGID mismatch"));
        }
        if inner.conn_id.fd != 0 && inner.conn_id.fd != conn_id.fd {
            return Err(anyhow!("FD mismatch"));
        }
        if inner.conn_id.tsid != 0 && inner.conn_id.tsid != conn_id.tsid {
            return Err(anyhow!("TSID mismatch"));
        }
        if inner.conn_id.uid.start_time_ticks != 0
            && inner.conn_id.uid.start_time_ticks != conn_id.uid.start_time_ticks
        {
            return Err(anyhow!("Start time ticks mismatch"));
        }

        if inner.conn_id != conn_id {
            inner.conn_id = conn_id;

            inner.creation_timestamp = Instant::now();

            info!("New connection tracker");
        }
        Ok(())
    }

    pub(crate) fn set_remote_addr(&self, addr: SocketAddr, reason: &str) {
        let mut inner = self.inner.lock();
        if is_unspecified(&inner.open_info.remote_addr) {
            inner.open_info.remote_addr = addr;
            info!(
                "RemoteAddr updated {}, reason=[{}]",
                inner.open_info.remote_addr, reason
            );
        }
    }

    pub(crate) fn set_local_addr(&self, addr: SocketAddr, reason: &str) {
        let mut inner = self.inner.lock();
        if is_unspecified(&inner.open_info.local_addr) {
            inner.open_info.local_addr = addr;
            info!(
                "LocalAddr updated {}, reason=[{}]",
                inner.open_info.local_addr, reason
            );
        }
    }

    pub(crate) fn set_role(&self, role: EndpointRole, reason: &str) -> bool {
        let mut inner = self.inner.lock();
        if inner.role != EndpointRole::Unknown {
            if role != EndpointRole::Unknown && inner.role != role {
                error!(
                    "Not allowed to change the role of an active ConnTracker: old role: {:?}, new role: {:?}",
                    inner.role, role
                );
            }
            return false;
        }

        if role != EndpointRole::Unknown {
            info!(
                "Role updated {:?} -> {:?}, reason=[{}]",
                inner.role, role, reason
            );
            inner.role = role;
            return true;
        }

        false
    }

    pub(crate) fn set_protocol(&self, protocol: TrafficProtocol, reason: &str) -> bool {
        let mut inner = self.inner.lock();
        if inner.protocol == protocol {
            return true;
        }

        if inner.protocol != TrafficProtocol::Unknown {
            error!(
                "Not allowed to change the protocol of an active ConnTracker: {:?} -> {:?}, reason=[{}]",
                inner.protocol, protocol, reason
            );
            return false;
        }

        let old_protocol = inner.protocol;
        inner.protocol = protocol;
        info!(
            "Protocol changed: {:?} -> {:?}, reason=[{}]",
            old_protocol, protocol, reason
        );
        inner.send_data.set_protocol(protocol);
        inner.recv_data.set_protocol(protocol);
        true
    }

    pub(crate) fn set_ssl(&self, ssl: bool, ssl_source: SslSource, reason: &str) -> bool {
        let mut inner = self.inner.lock();
        if inner.ssl == ssl {
            return true;
        }

        if inner.ssl {
            error!(
                "Not allowed to change the SSL state of an active ConnTracker: {} -> {}, reason=[{}] source=[{:?}]",
                inner.ssl, ssl, reason, inner.ssl_source
            );
            return false;
        }

        let old_ssl = inner.ssl;
        inner.ssl = ssl;
        inner.ssl_source = ssl_source;
        inner.send_data.set_ssl_source(ssl_source);
        inner.recv_data.set_ssl_source(ssl_source);

        info!(
            "SSL state changed: {} -> {}, reason=[{}]",
            old_ssl, ssl, reason
        );
        true
    }

    pub(crate) fn update_timestamps(&self, bpf_timestamp: u64) -> Result<()> {
        let mut inner = self.inner.lock();
        inner.last_bpf_timestamp_ns = inner.last_bpf_timestamp_ns.max(bpf_timestamp);
        inner.last_activity_timestamp = Some(inner.current_time);
        inner.idle_iteration = false;
        Ok(())
    }

    pub(crate) fn check_tracker(&self) -> Result<()> {
        let inner = self.inner.lock();
        if inner.conn_id.fd == -1 {
            return Err(anyhow!("Invalid file descriptor"));
        }

        if inner.death_countdown >= 0 && inner.death_countdown < DEATH_COUNTDOWN_ITERS - 1 {
            error!(
                "Did not expect new event more than 1 sampling iteration after Close. Connection={:?}.",
                inner.conn_id
            );
        }
        Ok(())
    }

    pub(crate) fn mark_for_death(&self, countdown: i32) {
        if countdown < 0 {
            return;
        }

        let mut inner = self.inner.lock();

        if inner.death_countdown == -1 {
            info!("Marked for death, countdown={}", countdown);
        }

        if inner.death_countdown >= 0 {
            inner.death_countdown = inner.death_countdown.min(countdown);
        } else {
            inner.death_countdown = countdown;
        }
    }

    pub(crate) fn is_zombie(&self) -> bool {
        let inner = self.inner.lock();
        inner.death_countdown >= 0
    }

    pub(crate) fn ready_for_destruction(&self) -> bool {
        let inner = self.inner.lock();
        inner.death_countdown == 0 && inner.final_conn_stats_reported
    }

    pub(crate) fn update_state(&self) {
        let mut inner = self.inner.lock();
        if inner.state == TrackerState::Disabled {
            return;
        }

        if should_trace_protocol_role(&inner.protocol, &inner.role) {
            inner.state = TrackerState::Transferring;
            return;
        }

        match inner.role {
            EndpointRole::Server => {}
            EndpointRole::Client => {
                inner.state = TrackerState::Transferring;
            }
            EndpointRole::Unknown => {
                if !inner.idle_iteration {
                    info!("Protocol role was not inferred from BPF, waiting for user space inference result.");
                }
            }
        }
    }

    pub(crate) fn update_result_stats<P: ProtocolTrait>(
        &self,
        result: &RecordsWithErrorCount<P::RecordType>,
    ) {
        let mut inner = self.inner.lock();
        inner
            .stats
            .increment(TrackerStats::InvalidRecords, result.error_count);
        inner
            .stats
            .increment(TrackerStats::ValidRecords, result.records.len() as u64);
    }

    pub(crate) fn update_data_stats(&self, event: &SocketDataEvent) {
        let mut inner = self.inner.lock();
        match event.inner.direction {
            TrafficDirection::Egress => {
                inner.stats.increment(TrackerStats::DataEventSent, 1);
                inner
                    .stats
                    .increment(TrackerStats::BytesSent, event.inner.msg_size as u64);
                inner.stats.increment(
                    TrackerStats::BytesSentTransferred,
                    event.inner.msg_buf_size as u64,
                );
            }
            TrafficDirection::Ingress => {
                inner.stats.increment(TrackerStats::DataEventRecv, 1);
                inner
                    .stats
                    .increment(TrackerStats::BytesRecv, event.inner.msg_size as u64);
                inner.stats.increment(
                    TrackerStats::BytesRecvTransferred,
                    event.inner.msg_buf_size as u64,
                );
            }
        }
    }

    pub(crate) fn iteration_pre_tick(&self, iteration_time: Instant) -> Result<()> {
        let mut inner = self.inner.lock();
        self.set_current_time(iteration_time)?;

        inner.idle_iteration = true;

        if inner.state == TrackerState::Disabled {
            return Ok(());
        }

        self.update_state();
        Ok(())
    }

    pub(crate) fn iteration_post_tick(&self) {
        let mut inner = self.inner.lock();
        if inner.death_countdown > 0 {
            inner.death_countdown -= 1;
            info!("Death countdown={}", inner.death_countdown);
        }

        self.handle_inactivity();

        if inner.state == TrackerState::Disabled {
            return;
        }

        if inner.send_data.is_eos() || inner.recv_data.is_eos() {
            self.disable("End-of-stream");
        }

        if inner.send_data.parse_failure_rate() > PARSE_FAILURE_RATE_THRESHOLD
            || inner.recv_data.parse_failure_rate() > PARSE_FAILURE_RATE_THRESHOLD
        {
            self.disable(&format!(
                "Connection does not appear parseable as protocol {:?}",
                inner.protocol
            ));
        }

        if self.stitch_failure_rate() > STITCH_FAILURE_RATE_THRESHOLD {
            self.disable(&format!(
                "Connection does not appear to produce valid records of protocol {:?}",
                inner.protocol
            ));
        }
    }

    pub(crate) fn check_proc_for_conn_close(&self) {
        let mut inner = self.inner.lock();
        let fd_file_path = format!("/proc/{}/fd/{}", inner.conn_id.uid.tgid, inner.conn_id.fd);

        if !std::path::Path::new(&fd_file_path).exists() {
            self.mark_for_death(0);
        }
    }

    pub(crate) fn handle_inactivity(&self) {
        let mut inner = self.inner.lock();
        inner.idle_iteration_count = if inner.idle_iteration {
            inner.idle_iteration_count + 1
        } else {
            0
        };

        if self.is_zombie() {
            return;
        }

        if inner.idle_iteration_count >= inner.idle_iteration_threshold {
            self.check_proc_for_conn_close();

            const MIN_CHECK_PERIOD: i32 = 100;
            inner.idle_iteration_threshold += inner.idle_iteration_threshold.min(MIN_CHECK_PERIOD);
        }

        if inner.current_time > inner.last_activity_timestamp.unwrap() + inner.inactivity_duration {
            self.reset();
            inner.last_activity_timestamp = Some(inner.current_time);
        }
    }

    pub(crate) fn stitch_failure_rate(&self) -> f64 {
        let inner = self.inner.lock();
        let total_attempts = inner.stats.get(TrackerStats::InvalidRecords)
            + inner.stats.get(TrackerStats::ValidRecords);

        if total_attempts <= 5 {
            return 0.0;
        }

        inner.stats.get(TrackerStats::InvalidRecords) as f64 / total_attempts as f64
    }
}

pub(crate) fn protocol_state<T: StateType>(state: &mut Box<dyn StateType>) -> Option<&mut T> {
    if state.as_any().is::<NoState>() {
        None
    } else {
        state.as_any_mut().downcast_mut::<T>()
    }
}
