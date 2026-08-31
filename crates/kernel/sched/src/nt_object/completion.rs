//! NT I/O completion-port queue.

extern crate alloc;

use alloc::collections::VecDeque;
use crate::live::WaitList;
use sync::{Spinlock, TaskList as TaskListClass};

/// One completion notification retained until an NT thread removes it.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtCompletionPacket {
    pub key: u64,
    pub overlapped: u64,
    pub status: u32,
    pub information: u64,
}

/// Queue-backed NT completion port. # C: O(1) post, O(N) wake
pub struct NtCompletionPort {
    packets: Spinlock<VecDeque<NtCompletionPacket>, TaskListClass>,
    waiters: WaitList,
    concurrency: u32,
}

impl NtCompletionPort {
    pub fn new(concurrency: u32) -> Self {
        Self { packets: Spinlock::new(VecDeque::new()), waiters: WaitList::new(), concurrency }
    }

    pub fn post(&self, packet: NtCompletionPacket) {
        self.packets.lock().push_back(packet);
        self.waiters.wake_one();
    }

    pub fn try_remove(&self) -> Option<NtCompletionPacket> { self.packets.lock().pop_front() }

    pub fn is_signaled(&self) -> bool { !self.packets.lock().is_empty() }

    pub fn concurrency(&self) -> u32 { self.concurrency }

    /// Sleep until a packet is available or the supplied deadline expires.
    pub unsafe fn wait(&self, deadline_ns: u64, now: impl Fn() -> u64) -> crate::WaitOutcome {
        // SAFETY: caller is process context and the queue predicate owns no
        // caller lock while the scheduler parks the current task.
        unsafe { crate::live::wait_event_interruptible_until(&self.waiters, deadline_ns, now, || self.is_signaled()) }
    }
}
