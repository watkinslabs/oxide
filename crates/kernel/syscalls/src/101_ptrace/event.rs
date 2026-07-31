// `PTRACE_EVENT_*` policy: which event a clone reports, whether an event is
// enabled, what a new child inherits from its parent's tracer, and the two
// eventless options (EXITKILL, the legacy exec SIGTRAP).
//
// UNGATED (`CLAUDE.md` phantom-test rule): every rule here is a decision, so
// it must be reachable from `cargo test`. The live glue that actually stops a
// tracee lives in the kernel-only sibling `101_ptrace/stop.rs`.

use crate::s101_ptrace_uapi as uapi;

/// `PTRACE_EVENTMSG_SYSCALL_ENTRY` / `_EXIT` — the `ptrace_message` a
/// syscall-stop records so `PTRACE_GET_SYSCALL_INFO` can tell the two apart.
pub const EVENTMSG_SYSCALL_ENTRY: u64 = 1;
pub const EVENTMSG_SYSCALL_EXIT:  u64 = 2;

/// `SIGCHLD` — the `exit_signal` that distinguishes a fork from a clone for
/// the purpose of choosing between `PTRACE_EVENT_FORK` and
/// `PTRACE_EVENT_CLONE`.
pub const SIGCHLD: u64 = 17;

/// Which event a clone reports, before the enable test. Linux picks on the
/// SHAPE of the call, not on what the tracer asked for: `CLONE_VFORK` is a
/// vfork whatever else is set, then any `exit_signal` other than `SIGCHLD`
/// makes it a clone, and everything else is a fork. A thread spawn therefore
/// reports `PTRACE_EVENT_CLONE` because glibc passes `exit_signal == 0`, not
/// because `CLONE_THREAD` is set.
/// # C: O(1)
pub fn clone_event(clone_flags: u64, exit_signal: u64) -> u32 {
    if clone_flags & CLONE_VFORK != 0 { return uapi::EVENT_VFORK; }
    if exit_signal != SIGCHLD { return uapi::EVENT_CLONE; }
    uapi::EVENT_FORK
}

/// `CLONE_VFORK` / `CLONE_UNTRACED`, needed here for the event choice and the
/// kernel-thread suppression. Duplicating the numbers would be a split source
/// of truth, so they come from the clone ABI owner.
pub use crate::clone_abi::{CLONE_UNTRACED, CLONE_VFORK};

/// Linux `ptrace_event_enabled(task, event)` — `task->ptrace &
/// PT_EVENT_FLAG(event)`, which is `PTRACE_O_TRACE<event>` because every
/// option bit is `1 << event`.
/// # C: O(1)
pub fn event_enabled(opts: u32, event: u32) -> bool {
    if event == 0 || event > uapi::EVENT_SECCOMP { return false; }
    opts & (1u32 << event) != 0
}

/// The event a clone actually reports, or `None` when it reports nothing:
/// `CLONE_UNTRACED` (kernel threads) suppresses reporting outright, an
/// untraced parent has no tracer to report to, and an enabled-event test
/// gates the rest.
/// # C: O(1)
pub fn clone_event_reported(clone_flags: u64, exit_signal: u64, traced: bool, opts: u32)
    -> Option<u32>
{
    if !traced { return None; }
    if clone_flags & CLONE_UNTRACED != 0 { return None; }
    let ev = clone_event(clone_flags, exit_signal);
    if event_enabled(opts, ev) { Some(ev) } else { None }
}

/// What Linux `ptrace_init_task` installs on a NEW child. The child is
/// auto-attached to the SAME tracer — Linux links it to `current->parent`,
/// which for a traced task is its tracer — and inherits the whole option
/// word, so a tracer that set `PTRACE_O_TRACEFORK` keeps tracing the tree it
/// forks.
///
/// The auto-attach happens only when the fork itself is being reported:
/// `copy_process`'s `trace` argument is the already-enable-tested event.
/// `None` means the child starts untraced.
/// # C: O(1)
pub fn inherited_trace(reported_event: Option<u32>, tracer: u32, parent_opts: u32, seized: bool)
    -> Option<InheritedTrace>
{
    if reported_event.is_none() || tracer == 0 { return None; }
    Some(InheritedTrace { tracer, opts: parent_opts, seized })
}

/// The ptrace state a new child inherits, plus how it must come to rest.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct InheritedTrace {
    pub tracer: u32,
    pub opts:   u32,
    /// `child->ptrace & PT_SEIZED`. A SEIZED child is trapped through
    /// `JOBCTL_TRAP_STOP` (a `PTRACE_EVENT_STOP`); a non-seized one gets a
    /// plain `SIGSTOP` added to its pending set.
    pub seized: bool,
}

impl InheritedTrace {
    /// Stop code the auto-attached child comes to rest at. A SEIZED child
    /// reports `PTRACE_EVENT_STOP`; a classically-attached one reports the
    /// bare `SIGSTOP` its pending set carries.
    /// # C: O(1)
    pub fn child_stop_code(&self) -> i32 {
        if self.seized { uapi::event_stop_code(uapi::EVENT_STOP) } else { SIGSTOP }
    }
}

/// `SIGSTOP`, the signal `ptrace_init_task` adds to a non-seized new tracee's
/// pending set.
pub const SIGSTOP: i32 = 19;

/// Linux `ptrace_event`'s `else if (event == PTRACE_EVENT_EXEC)` arm: a
/// classically-ATTACHED tracee whose tracer did NOT set
/// `PTRACE_O_TRACEEXEC` still gets a bare `SIGTRAP` after a successful
/// `execve`, which is how pre-`PTRACE_O_TRACEEXEC` debuggers detect an exec.
/// A SEIZED tracee gets nothing — `(ptrace & (PT_PTRACED|PT_SEIZED)) ==
/// PT_PTRACED` is false for it.
/// # C: O(1)
pub fn legacy_exec_sigtrap(traced: bool, seized: bool, opts: u32) -> bool {
    if !traced { return false; }
    if event_enabled(opts, uapi::EVENT_EXEC) { return false; }
    !seized
}

/// Linux `exit_ptrace`: a tracer dying sends `SIGKILL` to every tracee whose
/// link carries `PT_EXITKILL`, then detaches them all regardless.
/// # C: O(1)
pub fn exitkill(opts: u32) -> bool { opts & uapi::O_EXITKILL != 0 }

#[cfg(test)]
#[path = "event/tests.rs"] mod tests;
