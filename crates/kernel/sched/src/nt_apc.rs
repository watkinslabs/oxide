//! Per-thread native NT APC queue ownership.
//!
//! An APC is retained by its target thread until the NT user-return path
//! dequeues it.  Keeping this state on `Task` mirrors the ownership boundary
//! used by Wine's server thread object; syscall adapters only validate ABI
//! values and enqueue typed records here.

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};

const MAX_QUEUED: usize = 4096;

/// Windows `NtQueueApcThreadEx2` flag values owned by the native APC path.
pub const QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC: u32 = 0x0000_0001;
pub const QUEUE_USER_APC_CALLBACK_DATA_CONTEXT: u32 = 0x0001_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueFlagsError { Unknown, CallbackDataContext }

/// Admit only flag forms whose callback frame is owned by the native return
/// path; callback-data delivery needs a distinct Windows frame layout.
pub fn validate_queue_flags(flags: u32) -> Result<(), QueueFlagsError> {
    let known = QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC | QUEUE_USER_APC_CALLBACK_DATA_CONTEXT;
    if flags & !known != 0 { return Err(QueueFlagsError::Unknown); }
    if flags & QUEUE_USER_APC_CALLBACK_DATA_CONTEXT != 0 { return Err(QueueFlagsError::CallbackDataContext); }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Apc {
    pub routine: u64,
    pub argument1: u64,
    pub argument2: u64,
    pub argument3: u64,
    pub flags: u32,
}

pub struct Queue {
    records: Spinlock<VecDeque<Apc>, TaskListClass>,
    delivery_requested: AtomicBool,
}

impl Queue {
    pub const fn new() -> Self {
        Self {
            records: Spinlock::new(VecDeque::new()),
            delivery_requested: AtomicBool::new(false),
        }
    }

    /// Queue one APC, preserving FIFO order and applying the NT per-thread
    /// bounded-resource policy before mutating the queue.
    pub fn push(&self, apc: Apc) -> Result<(), Apc> {
        let mut queue = self.records.lock();
        if queue.len() >= MAX_QUEUED || queue.try_reserve(1).is_err() {
            return Err(apc);
        }
        queue.push_back(apc);
        Ok(())
    }

    /// Remove the oldest APC at a user APC delivery point.
    pub fn pop(&self) -> Option<Apc> {
        let mut queue = self.records.lock();
        let apc = queue.pop_front();
        if queue.is_empty() { self.delivery_requested.store(false, Ordering::Release); }
        apc
    }

    pub fn peek(&self) -> Option<Apc> {
        self.records.lock().front().copied()
    }

    pub fn len(&self) -> usize {
        self.records.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Observe queued records without arming user-return delivery. # C: O(1)
    pub fn has_pending(&self) -> bool { !self.is_empty() }

    /// Mark APCs already queued on this thread as deliverable by the next
    /// return-to-user pass. A request against an empty queue does not arm a
    /// future APC; a later enqueue needs its own alertable delivery point.
    pub fn request_delivery(&self) -> bool {
        let queued = !self.records.lock().is_empty();
        self.delivery_requested.store(queued, Ordering::Release);
        queued
    }

    pub fn delivery_pending(&self) -> bool {
        self.delivery_requested.load(Ordering::Acquire) && !self.records.lock().is_empty()
    }

    pub fn peek_deliverable(&self) -> Option<Apc> {
        if !self.delivery_requested.load(Ordering::Acquire) { return None; }
        self.records.lock().front().copied()
    }
}

impl Default for Queue {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_is_fifo_and_retains_all_callback_arguments() {
        let queue = Queue::new();
        let first = Apc { routine: 1, argument1: 2, argument2: 3, argument3: 4, flags: 5 };
        let second = Apc { routine: 6, argument1: 7, argument2: 8, argument3: 9, flags: 10 };
        assert!(queue.push(first).is_ok());
        assert!(queue.push(second).is_ok());
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop(), Some(first));
        assert_eq!(queue.pop(), Some(second));
        assert!(queue.is_empty());
    }

    #[test]
    fn queued_callbacks_require_an_alertable_delivery_point() {
        let queue = Queue::new();
        let first = Apc { routine: 1, argument1: 2, argument2: 3, argument3: 4, flags: 5 };
        assert!(!queue.request_delivery());
        assert!(queue.push(first).is_ok());
        assert!(!queue.delivery_pending());
        assert_eq!(queue.peek_deliverable(), None);
        assert!(queue.request_delivery());
        assert!(queue.delivery_pending());
        assert_eq!(queue.peek_deliverable(), Some(first));
        assert_eq!(queue.pop(), Some(first));
        assert!(!queue.delivery_pending());
    }

    #[test]
    fn alertable_observation_does_not_consume_target_owned_record() {
        let queue = Queue::new();
        let apc = Apc { routine: 0x1000, argument1: 11, argument2: 12, argument3: 13, flags: 0 };
        assert!(queue.push(apc).is_ok());
        assert!(queue.has_pending());
        assert!(queue.request_delivery());
        assert_eq!(queue.peek_deliverable(), Some(apc));
        assert_eq!(queue.len(), 1, "only the return dispatcher may dequeue");
    }

    #[test]
    fn queue_flags_reject_unowned_callback_frame_and_unknown_bits() {
        assert!(validate_queue_flags(0).is_ok());
        assert!(validate_queue_flags(QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC).is_ok());
        assert_eq!(validate_queue_flags(QUEUE_USER_APC_CALLBACK_DATA_CONTEXT),
            Err(QueueFlagsError::CallbackDataContext));
        assert_eq!(validate_queue_flags(0x8000_0000), Err(QueueFlagsError::Unknown));
    }
}
