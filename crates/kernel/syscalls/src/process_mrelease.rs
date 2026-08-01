// `process_mrelease(2)` admission (Linux `mm/oom_kill.c`
// `SYSCALL_DEFINE2(process_mrelease)` and `task_will_free_mem`).
//
// Ungated: the slot file is `#![cfg(target_os = "oxide-kernel")]`, so the
// "is this mm actually about to be freed" ladder — the whole safety argument
// for letting one process tear down another's memory — would otherwise never
// be exercised hosted.

use syscall::errno::Errno;

/// One task's exit state, as `__task_will_free_mem` reads it. Collected per
/// task by the shim so the decision below is pure.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ExitState {
    /// `signal->core_state` — a core dump is being written. Such a task can
    /// sleep for a long time before it releases anything, so it does NOT count
    /// as about to free its memory even though it is dying.
    pub coredumping: bool,
    /// `SIGNAL_GROUP_EXIT` — the whole thread group is on its way out.
    pub group_exit: bool,
    /// `thread_group_empty(task)` — this is the group's only remaining thread.
    pub thread_group_empty: bool,
    /// `PF_EXITING` — the task is past the point of no return in its own exit.
    pub exiting: bool,
}

/// `__task_will_free_mem` for ONE task. A group exit settles it; otherwise a
/// lone exiting thread does, because nothing else holds the mm.
/// # C: O(1)
pub fn task_will_free_mem_one(s: ExitState) -> bool {
    if s.coredumping { return false; }
    if s.group_exit { return true; }
    s.thread_group_empty && s.exiting
}

/// `task_will_free_mem` for the whole mm: the named task must be about to
/// free it, the mm must not already have been drained, and — when the mm has
/// more than one user — every OTHER task sharing it must be dying too.
/// A single surviving sharer keeps the memory pinned, so reaping it would take
/// pages out from under a live process.
///
/// `sharers` carries the tasks that share this mm but are NOT in the named
/// task's thread group; same-group threads are covered by `named`'s own group
/// exit state.
/// # C: O(N_sharers)
pub fn task_will_free_mem(named: ExitState, oom_skip: bool, mm_users: u64, sharers: &[ExitState]) -> bool {
    if !task_will_free_mem_one(named) { return false; }
    if oom_skip { return false; }
    if mm_users <= 1 { return true; }
    sharers.iter().copied().all(task_will_free_mem_one)
}

/// What the syscall does after the ladder: reap, or return this result.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Disposition {
    /// Walk the mm and release its anonymous pages.
    Reap,
    /// Nothing to do — the mm was already drained, so the caller's intent is
    /// already satisfied and the syscall succeeds.
    AlreadyDrained,
    /// The target is not dying: releasing its memory would corrupt a live
    /// process.
    Refuse(Errno),
}

/// `process_mrelease`'s decision once `task_will_free_mem` has been evaluated.
/// The error is reported ONLY when the work has not already been done, which
/// is what makes a second call on an already-reaped mm succeed rather than
/// look like a caller error.
/// # C: O(1)
pub fn disposition(will_free: bool, oom_skip: bool) -> Disposition {
    if will_free { return Disposition::Reap; }
    if oom_skip { return Disposition::AlreadyDrained; }
    Disposition::Refuse(Errno::Einval)
}

#[cfg(test)]
mod tests;
