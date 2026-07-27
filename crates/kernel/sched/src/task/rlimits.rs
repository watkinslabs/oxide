// Task rlimit accessors. The table itself lives on the shared `ThreadGroup`
// (Linux `signal_struct.rlim`), so every thread of a process reads and writes
// ONE table; these are the per-task entry points that resolve to it
// (`docs/53` hollow-shell owner: sched).

use super::Task;
use crate::rlimit::rlim;

impl Task {
    /// Read one `RLIMIT_*` slot (Linux `task_rlimit`). Out-of-range indices are
    /// rejected by the syscall shim before reaching here.
    /// # C: O(1); # Lk: TaskList (thread group, momentary)
    pub fn rlimit(&self, idx: usize) -> (u64, u64) {
        self.thread_group.rlimits.lock()[idx]
    }

    /// Write one `RLIMIT_*` slot for the whole thread group.
    /// # C: O(1); # Lk: TaskList (thread group, momentary)
    pub fn set_rlimit(&self, idx: usize, pair: (u64, u64)) {
        self.thread_group.rlimits.lock()[idx] = pair;
    }

    /// Snapshot the whole rlimit table (fork inheritance, `/proc/<pid>/limits`).
    /// # C: O(1); # Lk: TaskList (thread group, momentary)
    pub fn all_rlimits(&self) -> [(u64, u64); rlim::COUNT] {
        *self.thread_group.rlimits.lock()
    }

    /// Replace the whole rlimit table — `copy_signal`'s fork inheritance, run on
    /// an unpublished child that already owns its own `ThreadGroup`.
    /// # C: O(1); # Lk: TaskList (thread group, momentary)
    pub fn set_all_rlimits(&self, all: [(u64, u64); rlim::COUNT]) {
        *self.thread_group.rlimits.lock() = all;
    }
}
