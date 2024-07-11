use std::any::Any;
use std::fmt::Debug;
use std::hash::Hash;

pub(crate) trait KeyType: Eq + Default + Hash + Copy + Send {}

pub(crate) trait FrameType: Clone + Eq + Send + 'static {
    fn get_timestamp_ns(&self) -> u64;
    fn set_timestamp_ns(&mut self, timestamp: u64);
    fn byte_size(&self) -> usize;
}

pub(crate) trait StateType: Any + Debug + Send {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

#[derive(Default, Debug)]
pub(crate) struct NoState;

impl StateType for NoState {
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

pub(crate) trait ProtocolTrait {
    type KeyType: KeyType;
    type FrameType: FrameType;
    type StateType: StateType;
    type RecordType;

    fn supports_stream() -> bool {
        false
    }
}

pub(crate) struct RecordsWithErrorCount<T> {
    pub records: Vec<T>,
    pub error_count: u64,
}

impl<T> RecordsWithErrorCount<T> {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            error_count: 0,
        }
    }

    pub fn add_record(&mut self, record: T) {
        self.records.push(record);
    }

    pub fn increment_error_count(&mut self) {
        self.error_count += 1;
    }
}
