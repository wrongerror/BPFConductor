use std::collections::BTreeMap;
use std::sync::Arc;

use parking_lot::Mutex;

pub trait DataStreamBufferTrait {
    fn add(&mut self, pos: usize, data: &[u8], timestamp: u64);
    fn head(&self) -> &str;
    fn get_timestamp(&self, pos: usize) -> Result<u64, String>;
    fn remove_prefix(&mut self, n: usize);
    fn trim(&mut self);
    fn size(&self) -> usize;
    fn capacity(&self) -> usize;
    fn empty(&self) -> bool;
    fn position(&self) -> usize;
    fn reset(&mut self);
    fn shrink_to_fit(&mut self);
}

pub struct DataStreamBuffer {
    inner: Arc<Mutex<dyn DataStreamBufferTrait + Send>>,
}

impl DataStreamBuffer {
    pub fn new(max_capacity: usize, max_gap_size: usize, allow_before_gap_size: usize) -> Self {
        let inner = Arc::new(Mutex::new(ContiguousDataStreamBuffer::new(
            max_capacity,
            max_gap_size,
            allow_before_gap_size,
        )));
        DataStreamBuffer { inner }
    }

    pub fn add(&self, pos: usize, data: &[u8], timestamp: u64) {
        self.inner.lock().add(pos, data, timestamp);
    }

    pub fn head(&self) -> String {
        self.inner.lock().head().to_string()
    }

    pub fn get_timestamp(&self, pos: usize) -> Result<u64, String> {
        self.inner.lock().get_timestamp(pos)
    }

    pub fn remove_prefix(&self, n: usize) {
        self.inner.lock().remove_prefix(n);
    }

    pub fn trim(&self) {
        self.inner.lock().trim();
    }

    pub fn size(&self) -> usize {
        self.inner.lock().size()
    }

    pub fn capacity(&self) -> usize {
        self.inner.lock().capacity()
    }

    pub fn empty(&self) -> bool {
        self.inner.lock().empty()
    }

    pub fn position(&self) -> usize {
        self.inner.lock().position()
    }

    pub fn reset(&self) {
        self.inner.lock().reset();
    }

    pub fn shrink_to_fit(&self) {
        self.inner.lock().shrink_to_fit()
    }
}

pub struct ContiguousDataStreamBuffer {
    buffer: Vec<u8>,
    chunks: BTreeMap<usize, usize>,
    timestamps: BTreeMap<usize, u64>,
    position: usize,
    capacity: usize,
    max_gap_size: usize,
    allow_before_gap_size: usize,
    prev_timestamp: u64,
}

impl ContiguousDataStreamBuffer {
    pub fn new(capacity: usize, max_gap_size: usize, allow_before_gap_size: usize) -> Self {
        ContiguousDataStreamBuffer {
            buffer: Vec::with_capacity(capacity),
            chunks: BTreeMap::new(),
            timestamps: BTreeMap::new(),
            position: 0,
            capacity,
            max_gap_size,
            allow_before_gap_size,
            prev_timestamp: 0,
        }
    }

    fn check_overlap(&self, pos: usize, size: usize) -> bool {
        let mut left_overlap = false;
        let mut right_overlap = false;

        let r_iter = self.chunks.range(pos..).next();

        if let Some((&r_pos, &r_size)) = r_iter {
            right_overlap = pos + size > r_pos;
            assert!(!right_overlap, "New chunk overlaps with right chunk.");
        }

        if let Some((&l_pos, &l_size)) = self.chunks.range(..pos).next_back() {
            left_overlap = pos < l_pos + l_size;
            assert!(!left_overlap, "New chunk overlaps with left chunk.");
        }

        left_overlap || right_overlap
    }

    fn add_new_chunk(&mut self, pos: usize, size: usize) {
        let (left_fuse, right_fuse, r_pos) = {
            let r_iter = self.chunks.range(pos..).next();
            let l_iter = self.chunks.range(..pos).next_back();

            let left_fuse = if let Some((&l_pos, &l_size)) = l_iter {
                l_pos + l_size == pos
            } else {
                false
            };

            let right_fuse = if let Some((&r_pos, _)) = r_iter {
                pos + size == r_pos
            } else {
                false
            };

            let r_pos = r_iter.map(|(&r_pos, &r_size)| (r_pos, r_size));

            (left_fuse, right_fuse, r_pos)
        };

        if left_fuse && right_fuse {
            if let Some((l_pos, l_size)) = self
                .chunks
                .range(..pos)
                .next_back()
                .map(|(&l_pos, &l_size)| (l_pos, l_size))
            {
                if let Some((r_pos, r_size)) = r_pos {
                    self.chunks.insert(l_pos, l_size + size + r_size);
                    self.chunks.remove(&r_pos);
                }
            }
        } else if left_fuse {
            if let Some((l_pos, l_size)) = self
                .chunks
                .range(..pos)
                .next_back()
                .map(|(&l_pos, &l_size)| (l_pos, l_size))
            {
                self.chunks.insert(l_pos, l_size + size);
            }
        } else if right_fuse {
            if let Some((r_pos, r_size)) = r_pos {
                self.chunks.remove(&r_pos);
                self.chunks.insert(pos, size + r_size);
            }
        } else {
            self.chunks.insert(pos, size);
        }
    }

    fn add_new_timestamp(&mut self, pos: usize, timestamp: u64) {
        self.timestamps.insert(pos, timestamp);
    }

    fn get_chunk_for_pos(&self, pos: usize) -> Option<(&usize, &usize)> {
        self.chunks
            .range(..=pos)
            .next_back()
            .filter(|(&chunk_pos, &chunk_size)| pos >= chunk_pos && pos < chunk_pos + chunk_size)
    }

    fn enforce_timestamp_monotonicity(&mut self, pos: usize, chunk_end: usize) {
        let mut it = self.timestamps.range_mut(pos..chunk_end);

        while let Some((_, timestamp)) = it.next() {
            if self.prev_timestamp > 0 && *timestamp < self.prev_timestamp {
                *timestamp = self.prev_timestamp + 1;
            }
            self.prev_timestamp = *timestamp;
        }
    }

    fn cleanup_metadata(&mut self) {
        self.cleanup_chunks();
        self.cleanup_timestamps();
    }

    fn cleanup_chunks(&mut self) {
        let iter = self.chunks.range(..=self.position).next_back();

        if let Some((&chunk_pos, &chunk_size)) = iter {
            let available = chunk_size as isize - (self.position as isize - chunk_pos as isize);
            if available <= 0 {
                self.chunks = self.chunks.split_off(&self.position);
            } else {
                self.chunks = self.chunks.split_off(&self.position);
                self.chunks.insert(self.position, available as usize);
            }
        }
    }

    fn cleanup_timestamps(&mut self) {
        let pos = {
            let iter = self.timestamps.range(..=self.position).next_back();
            iter.map(|(pos, _)| *pos)
        };

        if let Some(pos) = pos {
            self.timestamps = self.timestamps.split_off(&pos);
        }
    }

    fn end_position(&self) -> usize {
        self.chunks
            .iter()
            .next_back()
            .map_or(self.position, |(&pos, &size)| pos + size)
    }
}

impl DataStreamBufferTrait for ContiguousDataStreamBuffer {
    fn add(&mut self, mut pos: usize, mut data: &[u8], timestamp: u64) {
        if data.len() > self.capacity {
            let oversize_amount = data.len() - self.capacity;
            data = &data[oversize_amount..];
            pos = pos + oversize_amount;
        }

        let ppos_front = pos as isize - self.position as isize;
        let ppos_back = pos as isize + data.len() as isize - self.position as isize;

        let mut run_metadata_cleanup = false;

        if ppos_back <= 0 {
            return;
        } else if ppos_front < 0 {
            let prefix = -ppos_front;
            data = &data[prefix as usize..];
            pos = pos + prefix as usize;
        } else if ppos_back > self.buffer.len() as isize {
            if pos > self.end_position() + self.max_gap_size {
                self.position = pos - self.allow_before_gap_size;
                run_metadata_cleanup = true;
            }

            if pos > self.position + self.capacity {
                let logical_size = pos + data.len() - self.position;
                if logical_size > self.capacity {
                    let remove_count = logical_size - self.capacity;
                    self.remove_prefix(remove_count);
                }
            }

            self.buffer.resize(ppos_back as usize, 0);
        }

        if self.check_overlap(pos, data.len()) {
            return;
        }

        let ppos_front = ppos_front as usize;
        self.buffer[ppos_front..ppos_front + data.len()].copy_from_slice(data);

        self.add_new_chunk(pos, data.len());
        self.add_new_timestamp(pos, timestamp);

        if run_metadata_cleanup {
            self.cleanup_metadata();
        }
    }

    fn head(&self) -> &str {
        std::str::from_utf8(&self.buffer).unwrap()
    }

    fn get_timestamp(&self, pos: usize) -> Result<u64, String> {
        if self.get_chunk_for_pos(pos).is_none() {
            return Err("Specified position not found".to_string());
        }

        self.timestamps.range(..=pos).next_back().map_or_else(
            || Err("Specified position not found.".to_string()),
            |(_, &timestamp)| Ok(timestamp),
        )
    }

    fn remove_prefix(&mut self, n: usize) {
        if n < 0 {
            return;
        }

        self.buffer.drain(0..n);
        self.position += n;

        self.cleanup_metadata();
    }

    fn trim(&mut self) {
        if let Some((&chunk_pos, _)) = self.chunks.iter().next() {
            let trim_size = chunk_pos - self.position;
            self.buffer.drain(0..trim_size);
            self.position += trim_size;
        }
    }

    fn size(&self) -> usize {
        self.buffer.len()
    }

    fn capacity(&self) -> usize {
        self.buffer.capacity()
    }

    fn empty(&self) -> bool {
        self.buffer.is_empty()
    }

    fn position(&self) -> usize {
        self.position
    }

    fn reset(&mut self) {
        self.buffer.clear();
        self.chunks.clear();
        self.timestamps.clear();
        self.position = 0;
        self.shrink_to_fit();
    }

    fn shrink_to_fit(&mut self) {
        self.buffer.shrink_to_fit();
    }
}
