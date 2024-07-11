use std::cell::{RefCell, RefMut};
use std::cmp::PartialEq;
use std::collections::HashMap;
use std::ops::DerefMut;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::{debug, info};
use parking_lot::{Mutex, MutexGuard};

use socket_tracer_common::{MessageType, SocketDataEvent, TrafficProtocol};

use crate::progs::socket_tracer::protocols::core::dataframe::{DataFrame, Frame, FrameId};
use crate::progs::socket_tracer::protocols::parse_frames;

use super::datastream_buffer::DataStreamBuffer;
use super::parse::{ParseResult, ParseState};
use super::types::{FrameType, KeyType, StateType};

#[derive(Default, Debug, Clone, Copy)]
pub(crate) enum SslSource {
    #[default]
    None,
    Unspecified,
}

pub(crate) struct DataStream {
    data_buffer: DataStreamBuffer,
    frames: DataFrame,
    has_new_events: bool,
    current_time: Instant,
    last_progress_time: Option<Instant>,
    conn_closed: bool,
    ssl_source: SslSource,
    stat_valid_frames: i32,
    stat_invalid_frames: i32,
    stat_raw_data_gaps: i32,
    last_parse_state: ParseState,
    last_processed_pos: usize,
    protocol: TrafficProtocol,
}

impl std::fmt::Debug for DataStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DataStream")
            .field("has_new_events", &self.has_new_events)
            .field("current_time", &self.current_time)
            .field("last_progress_time", &self.last_progress_time)
            .field("conn_closed", &self.conn_closed)
            .field("ssl_source", &self.ssl_source)
            .field("stat_valid_frames", &self.stat_valid_frames)
            .field("stat_invalid_frames", &self.stat_invalid_frames)
            .field("stat_raw_data_gaps", &self.stat_raw_data_gaps)
            .field("last_parse_state", &self.last_parse_state)
            .field("last_processed_pos", &self.last_processed_pos)
            .field("protocol", &self.protocol)
            .finish()
    }
}

impl DataStream {
    pub(crate) fn new(
        spike_capacity: usize,
        max_gap_size: usize,
        allow_before_gap_size: usize,
    ) -> Self {
        Self {
            data_buffer: DataStreamBuffer::new(spike_capacity, max_gap_size, allow_before_gap_size),
            frames: DataFrame::new(),
            has_new_events: false,
            current_time: Instant::now(),
            last_progress_time: None,
            conn_closed: false,
            ssl_source: SslSource::None,
            stat_valid_frames: 0,
            stat_invalid_frames: 0,
            stat_raw_data_gaps: 0,
            last_parse_state: ParseState::Invalid,
            last_processed_pos: 0,
            protocol: TrafficProtocol::Unknown,
        }
    }

    pub(crate) fn add_data(&mut self, event: Box<SocketDataEvent>) {
        if event.inner.msg_size > event.msg.len() as u32 && !event.msg.is_empty() {
            debug!(
                "Message truncated, original size: {}, transferred size: {}",
                event.inner.msg_size,
                event.msg.len()
            );
        }

        self.data_buffer.add(
            event.inner.position as usize,
            event.msg.as_slice(),
            event.inner.timestamp_ns,
        );
        self.has_new_events = true;
    }

    pub(crate) fn process_bytes_to_frames<K: KeyType, F: FrameType, S: StateType>(
        &mut self,
        msg_type: MessageType,
        state: Option<&mut S>,
    ) {
        if self.is_eos() {
            debug!("DataStream reaches EOS, no more data to process.");
        }
        let orig_pos = self.data_buffer.position();
        let attempt_sync = self.is_sync_required();
        let mut keep_processing = self.has_new_events || attempt_sync || self.conn_closed;

        let mut parse_result = ParseResult::<FrameId>::default();
        parse_result.state = ParseState::NeedsMoreData;
        parse_result.end_position = 0;

        let mut frame_bytes = 0;
        while keep_processing && !self.data_buffer.empty() {
            let contiguous_bytes = self.data_buffer.head().len();
            parse_result = parse_frames::<K, F, S>(
                msg_type,
                &self.data_buffer,
                &self.frames,
                self.is_sync_required(),
                None,
            );

            if contiguous_bytes != self.data_buffer.size() {
                self.data_buffer.remove_prefix(contiguous_bytes);
                self.data_buffer.trim();
                keep_processing = parse_result.state != ParseState::EOS;
            } else {
                if parse_result.end_position != 0 {
                    self.data_buffer.remove_prefix(parse_result.end_position);
                }
                keep_processing = false;
            }

            for (_, positions) in &parse_result.frame_positions {
                self.stat_valid_frames += positions.len() as i32;
            }
            self.stat_invalid_frames += parse_result.invalid_frames;
            self.stat_raw_data_gaps += keep_processing as i32;

            frame_bytes += parse_result.frame_bytes;
        }

        let made_progress = self.data_buffer.empty() || (self.data_buffer.position() != orig_pos);
        if made_progress {
            self.update_last_progress_time();
        }

        if parse_result.state == ParseState::EOS {
            assert!(made_progress);
        }

        if parse_result.state == ParseState::Invalid {
            self.data_buffer.remove_prefix(self.data_buffer.size());
            self.update_last_progress_time();
        }

        self.last_processed_pos = self.data_buffer.position();

        self.last_parse_state = parse_result.state;
        self.has_new_events = false;
    }

    pub(crate) fn reset(&mut self) {
        self.data_buffer.reset();
        self.has_new_events = false;
        self.update_last_progress_time();
        // self.frames.clean_up();
    }

    pub(crate) fn is_eos(&self) -> bool {
        self.last_parse_state == ParseState::EOS
    }

    pub(crate) fn is_sync_required(&self) -> bool {
        let sync_timeout = Duration::from_secs(5);
        let last_progress_time = self.last_progress_time.unwrap();
        self.current_time.duration_since(last_progress_time) >= sync_timeout
    }

    pub(crate) fn set_current_time(&mut self, time: Instant) {
        self.current_time = time;

        if self.last_progress_time.is_none() {
            self.update_last_progress_time();
        }
    }

    pub(crate) fn update_last_progress_time(&mut self) {
        self.last_progress_time = Some(self.current_time);
    }

    pub(crate) fn empty(&mut self) -> bool {
        self.data_buffer.empty() || self.frames.empty()
    }

    pub(crate) fn cleanup_events(
        &mut self,
        size_limit_bytes: usize,
        expiry_timestamp: Instant,
    ) -> bool {
        if self.last_progress_time.unwrap() < expiry_timestamp {
            self.data_buffer.reset();
            self.has_new_events = false;
            self.update_last_progress_time();
            return true;
        }

        if self.data_buffer.size() > size_limit_bytes {
            self.data_buffer
                .remove_prefix(self.data_buffer.size() - size_limit_bytes);
        }

        self.data_buffer.shrink_to_fit();
        false
    }

    pub(crate) fn set_protocol(&mut self, protocol: TrafficProtocol) {
        self.protocol = protocol;
    }

    pub(crate) fn set_ssl_source(&mut self, ssl_source: SslSource) {
        self.ssl_source = ssl_source;
    }

    pub(crate) fn stat_invalid_frames(&self) -> i32 {
        self.stat_invalid_frames
    }

    pub(crate) fn stat_valid_frames(&self) -> i32 {
        self.stat_valid_frames
    }

    pub(crate) fn stat_raw_data_gaps(&self) -> i32 {
        self.stat_raw_data_gaps
    }

    pub(crate) fn parse_failure_rate(&self) -> f64 {
        let total_attempts = self.stat_invalid_frames + self.stat_valid_frames;

        // 避免在事件数量太少时报告比率
        // - 避免除以零
        // - 避免调用者基于太少的数据做出决策
        if total_attempts <= 5 {
            return 0.0;
        }

        self.stat_invalid_frames as f64 / total_attempts as f64
    }

    pub(crate) fn set_conn_closed(&mut self) {
        self.conn_closed = true
    }
}
