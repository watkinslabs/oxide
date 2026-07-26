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

    /// Non-blocking `with_exe_path`, for callers that run in HARD-IRQ context.
    ///
    /// The sysrq dump reads this from the serial ISR while process context —
    /// `execve`, `WaitList::park_with_deadline` — takes the same lock plainly.
    /// A spinning read there would wedge the CPU (`06§3.1`, `skizm.md` Step
    /// 3h). Making every process-side access irqsave to serve a diagnostic is
    /// the wrong trade: the diagnostic is the odd one out, so it yields instead
    /// and reports that it could not read, exactly as `registry::try_snapshot`
    /// already does for the task list.
    /// # C: O(1) + `f`
    /// # Ctx: any, including hard IRQ
    pub fn try_with_exe_path<R>(&self, f: impl FnOnce(Option<&str>) -> R) -> Option<R> {
        let guard = self.exe_path.try_lock()?;
        Some(f(guard.as_deref()))
    }

    /// Non-blocking `exe_path`, same contract as `try_with_exe_path`.
    /// # C: O(n) string clone
    /// # Ctx: any, including hard IRQ
    pub fn try_exe_path(&self) -> Option<Option<String>> {
        Some(self.exe_path.try_lock()?.clone())
    }

    /// Replace the exec path — used by `execve` and by fork to copy the
    /// parent's path. Covers `*task.exe_path.get() = ...` sites.
    /// # C: O(1); # Lk: TaskList (self, momentary)
    pub fn set_exe_path(&self, path: Option<String>) {
        *self.exe_path.lock() = path;
    }
}
