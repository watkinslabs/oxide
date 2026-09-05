// Native NT per-thread metadata owned by the Linux-shaped task descriptor.
// The UTF-16 value is canonical; Linux comm is only a bounded diagnostic view.

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use sync::{Spinlock, TaskList as TaskListClass};

use crate::Task;

/// Native NT state whose lifetime is exactly the lifetime of one scheduler task.
pub struct State {
    description: Spinlock<Vec<u16>, TaskListClass>,
    debugger_hidden: AtomicBool,
}

impl State {
    /// Create the default native thread state. # C: O(1)
    pub fn new() -> Self {
        Self { description: Spinlock::new(Vec::new()), debugger_hidden: AtomicBool::new(false) }
    }

    /// Snapshot the canonical UTF-16 thread description. # C: O(description units)
    pub fn description(&self) -> Vec<u16> { self.description.lock().clone() }

    /// Replace the canonical UTF-16 thread description. # C: O(description units)
    pub fn replace_description(&self, description: &[u16]) {
        *self.description.lock() = description.to_vec();
    }

    /// Set the one-way NT debugger-hidden state. # C: O(1)
    pub fn hide_from_debugger(&self) { self.debugger_hidden.store(true, Ordering::Release); }

    /// Read the NT debugger-hidden state. # C: O(1)
    pub fn debugger_hidden(&self) -> bool { self.debugger_hidden.load(Ordering::Acquire) }
}

impl Default for State {
    fn default() -> Self { Self::new() }
}

impl Task {
    /// Update NT name and its lossy Linux diagnostic projection atomically by owner.
    /// # C: O(description units)
    pub fn set_nt_description(&self, description: &[u16]) {
        self.nt_thread_info.replace_description(description);
        let projection = String::from_utf16_lossy(description);
        self.set_comm_raw(projection.as_bytes());
    }
}

#[cfg(test)]
#[path = "nt_thread_info/tests.rs"]
mod tests;
