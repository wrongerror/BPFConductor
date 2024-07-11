use std::collections::HashMap;

use crate::progs::socket_tracer::protocols::core::types::KeyType;

#[derive(Debug, Default, PartialEq)]
pub(crate) enum ParseState {
    #[default]
    Unknown,
    Invalid,
    NeedsMoreData,
    Ignored,
    EOS,
    Success,
}

#[derive(Debug, Default)]
pub(crate) struct StartEndPos {
    pub(crate) start: usize,
    pub(crate) end: usize,
}

#[derive(Debug, Default)]
pub(crate) struct ParseResult<K: KeyType> {
    pub(crate) frame_positions: HashMap<K, Vec<StartEndPos>>,
    pub(crate) end_position: usize,
    pub(crate) state: ParseState,
    pub(crate) invalid_frames: i32,
    pub(crate) frame_bytes: usize,
}

impl<K: KeyType> ParseResult<K> {
    fn new() -> Self {
        Self {
            frame_positions: HashMap::new(),
            end_position: 0,
            state: ParseState::Invalid,
            invalid_frames: 0,
            frame_bytes: 0,
        }
    }
}
