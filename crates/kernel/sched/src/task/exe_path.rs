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

impl Task {
    /// Linux `replace_mm_exe_file`: install `inode` as the
    /// running image, taking a `deny_write_access` on it and releasing the one
    /// held on the previous image. That deny is what makes `ETXTBSY` real —
    /// `open(O_WRONLY)` and `truncate` of a live binary must fail while it runs.
    ///
    /// Returns `Etxtbsy` if the new image is currently open for write, and
    /// leaves the old image installed — Linux fails the exec in that case
    /// rather than running a file someone is writing.
    /// # C: O(1); # Lk: TaskList (self, momentary)
    pub fn set_exe_inode(&self, inode: Option<vfs::InodeRef>) -> vfs::KResult<()> {
        if let Some(new) = inode.as_ref() { new.deny_write_access()?; }
        let old = core::mem::replace(&mut *self.exe_inode.lock(), inode);
        if let Some(old) = old { old.allow_write_access(); }
        Ok(())
    }

    /// Release the exec-time write deny — task teardown, or an mm swap that
    /// leaves no image. Linux `exe_file_allow_write_access` on the old file.
    /// # C: O(1)
    pub fn clear_exe_inode(&self) {
        if let Some(old) = self.exe_inode.lock().take() { old.allow_write_access(); }
    }

    /// True iff this task's running image is `inode` — the `ETXTBSY` test a
    /// truncate/open-for-write consults. # C: O(1)
    pub fn exe_inode_is(&self, ino: vfs::Ino) -> bool {
        self.exe_inode.lock().as_ref().is_some_and(|i| i.ino() == ino)
    }
}
