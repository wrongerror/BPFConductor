use std::any::Any;

use ahash::HashMap;

use socket_tracer_common::MessageType;

use crate::progs::socket_tracer::protocols::core::types::{
    FrameType, KeyType, ProtocolTrait, StateType,
};

pub(crate) type HTTPFrameId = u32;

impl KeyType for HTTPFrameId {}

#[derive(Clone, Eq, PartialEq, Default)]
pub(crate) struct HTTPMessage {
    type_: MessageType,
    minor_version: i32,
    headers: HashMap<String, String>,
    req_method: String,
    req_path: String,
    resp_status: i32,
    req_message: String,
    body: String,
    headers_byte_size: usize,
    timestamp_ns: u64,
}

impl FrameType for HTTPMessage {
    fn get_timestamp_ns(&self) -> u64 {
        self.timestamp_ns
    }

    fn set_timestamp_ns(&mut self, timestamp: u64) {
        self.timestamp_ns = timestamp
    }

    fn byte_size(&self) -> usize {
        size_of::<HTTPMessage>() + self.headers_byte_size + self.body.len() + self.req_message.len()
    }
}

pub(crate) struct HTTPRecord {
    req: HTTPMessage,
    resp: HTTPMessage,
}
#[derive(Default, Debug)]
pub(crate) struct ConnState {
    pub(crate) conn_closed: bool,
}

#[derive(Default, Debug)]
pub(crate) struct HTTPState {
    pub(crate) global: ConnState,
    send: (),
    recv: (),
}

impl StateType for HTTPState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub(crate) struct HTTPProtocol {}

impl ProtocolTrait for HTTPProtocol {
    type KeyType = HTTPFrameId;
    type FrameType = HTTPMessage;
    type StateType = HTTPState;
    type RecordType = HTTPRecord;

    fn supports_stream() -> bool {
        true
    }
}
