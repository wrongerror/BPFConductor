use std::any::TypeId;
use std::collections::{HashMap, VecDeque};
use std::collections::hash_map::IterMut;
use std::sync::Arc;
use std::time::{Duration, Instant};

use log::debug;
use parking_lot::Mutex;

use crate::progs::socket_tracer::protocols::core::types::{FrameType, KeyType};
use crate::progs::socket_tracer::protocols::http::types::{HTTPFrameId, HTTPMessage};

#[derive(Copy, Clone, Eq, Hash, PartialEq)]
pub(crate) enum FrameId {
    HttpFrameId(HTTPFrameId),
}

impl Default for FrameId {
    fn default() -> Self {
        FrameId::HttpFrameId(0)
    }
}

impl KeyType for FrameId {}

#[derive(Clone, Eq, PartialEq)]
pub(crate) enum Frame {
    HttpFrame(HTTPMessage),
}

impl Frame {
    pub(crate) fn new<F: FrameType>() -> Self {
        if TypeId::of::<F>() == TypeId::of::<HTTPMessage>() {
            Frame::HttpFrame(HTTPMessage::default())
        } else {
            // 处理其他变体...
            unimplemented!()
        }
    }
}

impl FrameType for Frame {
    fn get_timestamp_ns(&self) -> u64 {
        match self {
            Frame::HttpFrame(frame) => frame.get_timestamp_ns(),
        }
    }

    fn set_timestamp_ns(&mut self, timestamp: u64) {
        match self {
            Frame::HttpFrame(frame) => frame.set_timestamp_ns(timestamp),
        }
    }

    fn byte_size(&self) -> usize {
        match self {
            Frame::HttpFrame(frame) => frame.byte_size(),
        }
    }
}

pub struct DataFrame {
    inner: Arc<Mutex<HashMap<FrameId, VecDeque<Frame>>>>,
}

impl DataFrame {
    pub fn new() -> Self {
        DataFrame {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn empty(&self) -> bool {
        let inner = self.inner.lock();
        inner.values().all(|deque| deque.is_empty())
    }

    pub fn insert(&self, key: FrameId, frame: Frame) {
        let mut inner = self.inner.lock();
        inner
            .entry(key)
            .or_insert_with(VecDeque::new)
            .push_back(frame);
    }

    pub fn get(&self, key: &FrameId) -> Option<VecDeque<Frame>> {
        let inner = self.inner.lock();
        inner.get(key).map(|deque| deque.iter().cloned().collect())
    }

    pub fn get_mut(&self, key: &FrameId) -> Option<VecDeque<Frame>> {
        let mut inner = self.inner.lock();
        inner
            .get_mut(key)
            .map(|deque| deque.iter_mut().map(|frame| frame.clone()).collect())
    }

    pub fn iter(&self) -> Vec<(FrameId, VecDeque<Frame>)> {
        let inner = self.inner.lock();
        inner
            .iter()
            .map(|(k, v)| (*k, v.iter().cloned().collect()))
            .collect()
    }

    pub fn frames_size(&self) -> usize {
        let inner = self.inner.lock();
        inner
            .values()
            .map(|deque| deque.iter().map(|frame| frame.byte_size()).sum::<usize>())
            .sum()
    }

    pub fn cleanup_frames(&mut self, size_limit_bytes: usize, expiry_timestamp: Instant) {
        let size = self.frames_size();
        if size > size_limit_bytes {
            debug!(
                "Messages cleared due to size limit ({} > {}).",
                size, size_limit_bytes
            );
            for (_, mut frame_deque) in self.inner.lock().iter_mut() {
                frame_deque.clear();
            }
        }
        self.erase_expired_frames(expiry_timestamp);
    }

    pub fn erase_expired_frames(&mut self, expiry_timestamp: Instant) {
        let mut inner = self.inner.lock();
        for (_, mut deque) in inner.iter_mut() {
            let mut iter = deque.iter();
            while let Some(frame) = iter.next() {
                let frame_timestamp =
                    Instant::now() - Duration::from_nanos(frame.get_timestamp_ns());
                if expiry_timestamp < frame_timestamp {
                    break;
                }
            }
            deque.retain(|frame| {
                Instant::now() - Duration::from_nanos(frame.get_timestamp_ns()) < expiry_timestamp
            });
        }
    }
}
