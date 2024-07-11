use std::collections::{HashMap, VecDeque};
use std::str;

use log::debug;

use socket_tracer_common::MessageType;

use crate::progs::socket_tracer::protocols::core::dataframe::{DataFrame, Frame, FrameId};
use crate::progs::socket_tracer::protocols::http::types::HTTPMessage;

use super::datastream_buffer::DataStreamBuffer;
use super::parse::{ParseResult, ParseState, StartEndPos};
use super::types::{FrameType, KeyType, StateType};

pub(crate) fn parse_frames<K: KeyType, F: FrameType, S: StateType>(
    msg_type: MessageType,
    data_stream_buffer: &DataStreamBuffer,
    frames: &DataFrame,
    resync: bool,
    state: Option<&mut S>,
) -> ParseResult<FrameId> {
    let mut buf = data_stream_buffer.head();

    let mut start_pos = 0;
    if resync {
        debug!("Finding next frame boundary");
        // 实现查找帧边界的逻辑
        start_pos = 1; // 示例值
        buf = (&buf[start_pos..]).to_string();
    }

    let mut prev_sizes = HashMap::new();
    for (stream_id, deque) in frames.iter() {
        prev_sizes.insert(stream_id, deque.len());
    }

    let mut result = parse_frames_loop::<K, F, S>(msg_type, buf, frames, state);

    let mut total_new_frames = 0;
    for (stream_id, positions) in result.frame_positions.iter() {
        total_new_frames += positions.len();
        if let Some(prev_size) = prev_sizes.get(stream_id) {
            total_new_frames -= prev_size;
        }
    }

    debug!("Parsed {} new frames", total_new_frames);

    for (stream_id, positions) in result.frame_positions.iter_mut() {
        let mut offset = *prev_sizes.get(stream_id).unwrap_or(&0);

        for f in positions.iter_mut() {
            f.start += start_pos;
            f.end += start_pos;

            if let Some(mut deque) = frames.get_mut(stream_id) {
                let msg = &mut deque[offset];
                offset += 1;
                match data_stream_buffer.get_timestamp(data_stream_buffer.position() + f.end) {
                    Ok(timestamp_ns) => msg.set_timestamp_ns(timestamp_ns),
                    Err(e) => debug!("Error: {}", e),
                }
            }
        }
    }
    result.end_position += start_pos;
    result
}

fn parse_frames_loop<K: KeyType, F: FrameType, S: StateType>(
    msg_type: MessageType,
    mut buf: String,
    frames: &DataFrame,
    mut state: Option<&mut S>,
) -> ParseResult<FrameId> {
    let mut frame_positions = HashMap::new();
    let buf_size = buf.len();
    let mut s = ParseState::Success;
    let mut bytes_processed = 0;
    let mut frame_bytes = 0;
    let mut invalid_count = 0;

    while !buf.is_empty() && s != ParseState::EOS {
        let mut frame = Frame::new::<F>();
        s = parse_frame(msg_type, &mut buf, &mut frame, state.as_deref_mut());

        let mut stop = false;
        let mut push = false;
        match s {
            ParseState::NeedsMoreData => {
                stop = true;
            }
            ParseState::Invalid => {
                // 实现查找帧边界的逻辑
                let pos = 1; // 示例值
                if pos != 0 {
                    buf = buf[pos..].to_string();
                    stop = false;
                    push = false;
                } else {
                    stop = true;
                    push = false;
                }
                invalid_count += 1;
            }
            ParseState::Ignored => {
                stop = false;
                push = false;
            }
            ParseState::EOS | ParseState::Success => {
                stop = false;
                push = true;
            }
            _ => panic!("Unexpected parse state"),
        }

        if stop {
            break;
        }

        let start_position = bytes_processed;
        bytes_processed = buf_size - buf.len();
        let end_position = bytes_processed - 1;

        if push {
            let key = get_stream_id(&frame);
            frame_positions
                .entry(key)
                .or_insert_with(Vec::new)
                .push(StartEndPos {
                    start: start_position,
                    end: end_position,
                });
            if let Some(mut deque) = frames.get_mut(&key) {
                deque.push_back(frame);
            } else {
                let mut new_deque = VecDeque::new();
                new_deque.push_back(frame.clone());
                frames.get_mut(&key).unwrap().push_back(frame);
            }
            frame_bytes += end_position - start_position + 1;
        }
    }
    ParseResult {
        frame_positions,
        end_position: bytes_processed,
        state: s,
        invalid_frames: invalid_count,
        frame_bytes,
    }
}

pub(crate) fn parse_frame<S: StateType>(
    _type: MessageType,
    buf: &mut String,
    frame: &mut Frame,
    _state: Option<&mut S>,
) -> ParseState {
    // 实现解析帧的逻辑
    match frame {
        Frame::HttpFrame(http_frame) => {
            // 解析 HTTP 帧的逻辑
            ParseState::Success
        }
    }
}

pub(crate) fn get_stream_id(frame: &Frame) -> FrameId {
    // match frame {
    //     Frame::HttpFrame(http_frame) => {
    //         // 获取 HTTP 帧的流 ID 的逻辑
    //         FrameId::HttpFrameId(http_frame.get_stream_id())
    //     }
    // }
    todo!()
}
