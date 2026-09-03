//! Per-thread native NT APC queue ownership.
//!
//! An APC is retained by its target thread until the NT user-return path
//! dequeues it.  Keeping this state on `Task` mirrors the ownership boundary
//! used by Wine's server thread object; syscall adapters only validate ABI
//! values and enqueue typed records here.

use alloc::collections::VecDeque;

use sync::{Spinlock, TaskList as TaskListClass};

const MAX_QUEUED: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Apc {
    pub routine: u64,
    pub argument1: u64,
    pub argument2: u64,
    pub argument3: u64,
    pub flags: u32,
}

pub struct Queue(Spinlock<VecDeque<Apc>, TaskListClass>);

impl Queue {
    pub const fn new() -> Self {
        Self(Spinlock::new(VecDeque::new()))
    }

    /// Queue one APC, preserving FIFO order and applying the NT per-thread
    /// bounded-resource policy before mutating the queue.
    pub fn push(&self, apc: Apc) -> Result<(), Apc> {
        let mut queue = self.0.lock();
        if queue.len() >= MAX_QUEUED || queue.try_reserve(1).is_err() {
            return Err(apc);
        }
        queue.push_back(apc);
        Ok(())
    }

    /// Remove the oldest APC at a user APC delivery point.
    pub fn pop(&self) -> Option<Apc> {
        self.0.lock().pop_front()
    }

    pub fn peek(&self) -> Option<Apc> {
        self.0.lock().front().copied()
    }

    pub fn len(&self) -> usize {
        self.0.lock().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
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
}
