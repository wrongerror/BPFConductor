use aya_ebpf::{
    macros::map,
    maps::{HashMap, PerCpuArray, PerfEventArray},
};

use socket_tracer_common::{
    ConnInfo, ConnStatsEvent, ControlValueIndex, SocketControlEvent, SocketDataEvent,
    TrafficProtocol,
};

use crate::{helpers::MyPerfEventArray, types};

pub const MAX_MAP_ENTRIES: u32 = 128 * 1024;

#[map(name = "sk_ctrl_events")]
pub static mut SOCKET_CONTROL_EVENTS: PerfEventArray<SocketControlEvent> =
    PerfEventArray::<SocketControlEvent>::pinned(0, 0);

#[map(name = "sk_data_events")]
pub static mut SOCKET_DATA_EVENTS: MyPerfEventArray<SocketDataEvent> =
    MyPerfEventArray::<SocketDataEvent>::pinned(0, 0);

#[map(name = "conn_stat_events")]
pub static mut CONN_STATS_EVENTS: PerfEventArray<ConnStatsEvent> =
    PerfEventArray::<ConnStatsEvent>::pinned(0, 0);

#[map(name = "ctrl_map")]
pub static mut CONTROL_MAP: PerCpuArray<u64> =
    PerCpuArray::<u64>::pinned(TrafficProtocol::NumProtocols as u32, 0);

#[map(name = "ctrl_values")]
pub static mut CONTROL_VALUES: PerCpuArray<i64> =
    PerCpuArray::<i64>::pinned(ControlValueIndex::NumControlValues as u32, 0);

#[map(name = "sock_data_buf")]
pub static mut SOCKET_DATA_EVENT_BUFFER: PerCpuArray<SocketDataEvent> =
    PerCpuArray::<SocketDataEvent>::pinned(1, 0);

#[map(name = "conn_stats_buf")]
pub static mut CONN_STATS_EVENT_BUFFER: PerCpuArray<ConnStatsEvent> =
    PerCpuArray::<ConnStatsEvent>::pinned(1, 0);

#[map(name = "conn_info")]
pub static mut CONN_INFO_MAP: HashMap<u64, ConnInfo> =
    HashMap::<u64, ConnInfo>::pinned(MAX_MAP_ENTRIES, 0);

#[map(name = "conn_disabled")]
pub static mut CONN_DISABLED_MAP: HashMap<u64, u64> =
    HashMap::<u64, u64>::pinned(MAX_MAP_ENTRIES, 0);

#[map(name = "accept_args")]
pub static mut ACTIVE_ACCEPT_MAP: HashMap<u64, types::AcceptArgs> =
    HashMap::<u64, types::AcceptArgs>::pinned(MAX_MAP_ENTRIES, 0);

#[map(name = "conn_args")]
pub static mut ACTIVE_CONNECT_MAP: HashMap<u64, types::ConnectArgs> =
    HashMap::<u64, types::ConnectArgs>::pinned(MAX_MAP_ENTRIES, 0);

#[map(name = "write_args")]
pub static mut ACTIVE_WRITE_MAP: HashMap<u64, types::DataArgs> =
    HashMap::<u64, types::DataArgs>::pinned(MAX_MAP_ENTRIES, 0);

#[map(name = "read_args")]
pub static mut ACTIVE_READ_MAP: HashMap<u64, types::DataArgs> =
    HashMap::<u64, types::DataArgs>::pinned(MAX_MAP_ENTRIES, 0);

#[map(name = "sendfile_args")]
pub static mut ACTIVE_SENDFILE_MAP: HashMap<u64, types::SendfileArgs> =
    HashMap::<u64, types::SendfileArgs>::pinned(MAX_MAP_ENTRIES, 0);

#[map(name = "close_args")]
pub static mut ACTIVE_CLOSE_MAP: HashMap<u64, types::CloseArgs> =
    HashMap::<u64, types::CloseArgs>::pinned(MAX_MAP_ENTRIES, 0);
