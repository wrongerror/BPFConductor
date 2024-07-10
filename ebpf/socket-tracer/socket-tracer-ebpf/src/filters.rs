use socket_tracer_common::{
    AF_INET, AF_INET6, AF_UNKNOWN, ConnInfo, ControlValueIndex, TrafficProtocol,
};

use crate::maps::{CONTROL_MAP, CONTROL_VALUES};

pub fn should_trace_sockaddr_family(sa_family: u32) -> bool {
    return sa_family == AF_UNKNOWN || sa_family == AF_INET || sa_family == AF_INET6;
}

pub fn should_trace_conn(conn_info: &ConnInfo) -> bool {
    return should_trace_sockaddr_family(conn_info.sa_family);
}

pub fn should_trace_protocol_data(conn_info: ConnInfo) -> bool {
    match conn_info.protocol {
        // TrafficProtocol::Unknown => false,
        TrafficProtocol::Unknown => true, // for test
        _ => {
            let protocol = conn_info.protocol as u32;
            let idx: u64 = 0;
            let control_val = match unsafe { CONTROL_MAP.get(protocol) } {
                Some(&val) => val,
                None => idx,
            };
            control_val & conn_info.role as u64 != 0
        }
    }
}

pub fn is_self_tgid(tgid: u32) -> bool {
    let idx = ControlValueIndex::SelfTGIDIndex as u32;
    let agent_tgid_val = unsafe { CONTROL_VALUES.get(idx) };
    match agent_tgid_val {
        Some(&agent_tgid) => agent_tgid as u32 == tgid,
        None => false,
    }
}
