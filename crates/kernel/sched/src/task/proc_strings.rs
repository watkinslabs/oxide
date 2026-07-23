// Task cmdline/environ accessors: spinlock-guarded `/proc/<pid>/cmdline`
// and `/proc/<pid>/environ` strings, safe for foreign-CPU readers racing
// this task's own execve writer (`docs/53` hollow-shell owner: sched).

extern crate alloc;
use alloc::string::String;

use super::Task;

impl Task {
    /// Clone the current argv string under the lock.
    /// # C: O(n) string clone; # Lk: TaskList (self, momentary)
    pub fn cmdline(&self) -> Option<String> {
        self.cmdline.lock().clone()
    }

    /// Replace the argv string — used by `execve`.
    /// # C: O(1); # Lk: TaskList (self, momentary)
    pub fn set_cmdline(&self, cmdline: Option<String>) {
        *self.cmdline.lock() = cmdline;
    }

    /// Clone the current envp string under the lock.
    /// # C: O(n) string clone; # Lk: TaskList (self, momentary)
    pub fn environ(&self) -> Option<String> {
        self.environ.lock().clone()
    }

    /// Replace the envp string — used by `execve`.
    /// # C: O(1); # Lk: TaskList (self, momentary)
    pub fn set_environ(&self, environ: Option<String>) {
        *self.environ.lock() = environ;
    }
}
