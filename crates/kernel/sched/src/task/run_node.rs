use alloc::sync::Arc;

use super::Task;

/// Task-owned linkage for one allocation-free class ready tree.
pub(crate) struct TreeRunNode {
    pub(crate) left: Option<Arc<Task>>,
    pub(crate) right: Option<Arc<Task>>,
    pub(crate) parent: usize,
    pub(crate) height: u16,
}

impl TreeRunNode {
    pub(crate) const fn new() -> Self {
        Self { left: None, right: None, parent: 0, height: 1 }
    }
}

/// Task-owned linkage for one allocation-free RT priority FIFO.
pub(crate) struct RtRunNode {
    pub(crate) next: Option<Arc<Task>>,
    pub(crate) prev: usize,
}

impl RtRunNode {
    pub(super) const fn new() -> Self { Self { next: None, prev: 0 } }
}
