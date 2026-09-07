//! Thread input attachment: which threads share one input record, and so one
//! set of message-time key state.
//!
//! Every thread is its own input by default. Attaching moves a thread onto
//! another thread's input; detaching gives it a fresh one again.

use alloc::vec::Vec;
use super::WindowManager;

/// Why an attach or detach request was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachError {
    /// A thread cannot attach to or detach from itself, and a detach of two
    /// threads that do not share an input is refused the same way.
    AccessDenied,
    /// One of the named threads has no queue to attach.
    InvalidParameter,
}

/// Thread-to-input assignment for one desktop.
#[derive(Default)]
pub struct ThreadInputs { links: Vec<(u64, u64)> }

impl ThreadInputs {
    /// # C: O(1)
    pub const fn new() -> Self { Self { links: Vec::new() } }

    /// Input record a thread reads. Unattached threads are their own input.
    /// # C: O(N_links)
    pub fn input_of(&self, tid: u64) -> u64 {
        self.links.iter().find(|(from, _)| *from == tid).map_or(tid, |(_, to)| *to)
    }

    /// # C: O(N_links)
    pub fn attached(&self, tid: u64) -> bool { self.links.iter().any(|(from, _)| *from == tid) }

    /// Move `from` onto `to`'s input, or off it. Threads already sharing an
    /// input are the only ones a detach admits. # C: O(N_links)
    pub fn set(&mut self, from: u64, to: u64, attach: bool, has_queue: impl Fn(u64) -> bool) -> Result<(), AttachError> {
        if from == to { return Err(AttachError::AccessDenied); }
        if attach {
            if !has_queue(from) || !has_queue(to) { return Err(AttachError::InvalidParameter); }
            let target = self.input_of(to);
            // Every thread already on `from`'s input follows it, so an input
            // record never splits behind the moving thread.
            let previous = self.input_of(from);
            for (_, input) in self.links.iter_mut().filter(|(_, input)| *input == previous) { *input = target; }
            self.links.retain(|(source, _)| *source != from);
            self.links.try_reserve(1).map_err(|_| AttachError::InvalidParameter)?;
            self.links.push((from, target));
            return Ok(());
        }
        if !has_queue(from) || !has_queue(to) { return Err(AttachError::AccessDenied); }
        if self.input_of(from) != self.input_of(to) { return Err(AttachError::AccessDenied); }
        self.links.retain(|(source, _)| *source != from);
        Ok(())
    }
}

impl WindowManager {
    /// # C: O(N_links)
    pub fn thread_input(&self, tid: u64) -> u64 { self.inputs.input_of(tid) }

    /// Attach or detach one thread's input. # C: O(N_queues + N_links)
    pub fn attach_thread_input(&mut self, from: u64, to: u64, attach: bool) -> Result<(), AttachError> {
        let queues = &self.queues;
        let has_queue = |tid: u64| queues.iter().any(|(owner, _)| *owner == tid);
        self.inputs.set(from, to, attach, has_queue)
    }
}

#[cfg(test)]
#[path = "tests/thread_input.rs"]
mod tests;
