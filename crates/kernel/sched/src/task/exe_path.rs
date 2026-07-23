// Task exe_path accessors: spinlock-guarded `/proc/<pid>/exe` string,
// safe for foreign-CPU readers racing this task's own execve writer
// (`docs/53` hollow-shell owner: sched).

extern crate alloc;
use alloc::string::String;

use super::Task;

impl Task {
    /// Clone the current exec path under the lock. Covers call sites that
    /// previously did `(*task.exe_path.get()).clone()` or
    /// `.as_ref().map(|s| s.clone())`.
    /// # C: O(n) string clone; # Lk: TaskList (self, momentary)
    pub fn exe_path(&self) -> Option<String> {
        self.exe_path.lock().clone()
    }

    /// Borrow the exec path as `Option<&str>` for the lock's duration.
    /// Covers `.as_ref().map(...)`, `.contains(...)`, `.ends_with(...)`,
    /// `.is_some()`, `.as_deref()` call sites without cloning.
    /// # C: O(1) + `f`; # Lk: TaskList (self, held across `f`)
    pub fn with_exe_path<R>(&self, f: impl FnOnce(Option<&str>) -> R) -> R {
        let guard = self.exe_path.lock();
        f(guard.as_deref())
    }

    /// Replace the exec path — used by `execve` and by fork to copy the
    /// parent's path. Covers `*task.exe_path.get() = ...` sites.
    /// # C: O(1); # Lk: TaskList (self, momentary)
    pub fn set_exe_path(&self, path: Option<String>) {
        *self.exe_path.lock() = path;
    }
}
