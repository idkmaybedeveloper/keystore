use crate::error::ResponseCode;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, SystemTime};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationState {
    Unknown,
    Success,
    Abort,
    Dropped,
    Pruned,
    Error(ResponseCode),
}

pub struct Operation {
    key_id: i64,
    state: Mutex<OperationState>,
    last_usage: Mutex<SystemTime>,
}

impl Operation {
    pub fn new(key_id: i64) -> Self {
        Self {
            key_id,
            state: Mutex::new(OperationState::Unknown),
            last_usage: Mutex::new(SystemTime::now()),
        }
    }

    pub fn key_id(&self) -> i64 {
        self.key_id
    }

    pub fn state(&self) -> OperationState {
        *self.state.lock().unwrap()
    }

    pub fn set_state(&self, state: OperationState) {
        *self.state.lock().unwrap() = state;
    }

    pub fn update_usage(&self) {
        *self.last_usage.lock().unwrap() = SystemTime::now();
    }

    pub fn last_usage(&self) -> SystemTime {
        *self.last_usage.lock().unwrap()
    }

    pub fn age(&self) -> Duration {
        self.last_usage().elapsed().unwrap_or(Duration::from_secs(0))
    }
}

pub struct OperationDb {
    operations: Mutex<Vec<Weak<Operation>>>,
}

impl OperationDb {
    pub fn new() -> Self {
        Self { operations: Mutex::new(Vec::new()) }
    }

    pub fn add_operation(&self, operation: &Arc<Operation>) {
        let mut ops = self.operations.lock().unwrap();
        ops.retain(|w| w.strong_count() > 0);
        ops.push(Arc::downgrade(operation));
    }

    pub fn prune_oldest(&self) -> Option<Arc<Operation>> {
        let mut ops = self.operations.lock().unwrap();
        ops.retain(|w| w.strong_count() > 0);

        if ops.is_empty() {
            return None;
        }

        let mut candidates: Vec<_> = ops
            .iter()
            .filter_map(|w| w.upgrade())
            .map(|op| {
                let age = op.age();
                (op, age)
            })
            .collect();

        if candidates.is_empty() {
            return None;
        }

        candidates.sort_by_key(|(_, age)| *age);
        let (oldest, _) = candidates.remove(0);
        oldest.set_state(OperationState::Pruned);

        ops.retain(|w| w.strong_count() > 0);
        Some(oldest)
    }

    pub fn count(&self) -> usize {
        let ops = self.operations.lock().unwrap();
        ops.iter().filter(|w| w.strong_count() > 0).count()
    }
}

impl Default for OperationDb {
    fn default() -> Self {
        Self::new()
    }
}
