// Task rlimit accessors: spinlock-guarded `[(cur, max); 16]` array, safe
// for `prlimit64(2)`/`sched_setattr(2)`'s cross-task reads and writes
// (`docs/53` hollow-shell owner: sched).

use super::Task;

impl Task {
    /// Read one `RLIMIT_*` slot.
    /// # C: O(1); # Lk: TaskList (target task, momentary)
    pub fn rlimit(&self, idx: usize) -> (u64, u64) {
        self.rlimits.lock()[idx]
    }

    /// Write one `RLIMIT_*` slot.
    /// # C: O(1); # Lk: TaskList (target task, momentary)
    pub fn set_rlimit(&self, idx: usize, pair: (u64, u64)) {
        self.rlimits.lock()[idx] = pair;
    }

    /// Snapshot the whole rlimit table (fork inheritance, `/proc/<pid>/limits`).
    /// # C: O(1); # Lk: TaskList (self, momentary)
    pub fn all_rlimits(&self) -> [(u64, u64); 16] {
        *self.rlimits.lock()
    }

    /// Replace the whole rlimit table — used by fork on an unpublished child.
    /// # C: O(1); # Lk: TaskList (target task, momentary)
    pub fn set_all_rlimits(&self, all: [(u64, u64); 16]) {
        *self.rlimits.lock() = all;
    }
}
