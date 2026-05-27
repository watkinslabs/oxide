// F167: per-task signal-pending bitmap helpers. Kernel-side ABI
// matches Linux's sigset_t bit layout: signal N sets bit (N - 1)
// of the u64 `Task::sigpending`. Signum is a typed enum so callers
// outside this crate (net, fs, etc.) don't open-code raw signal
// numbers — per docs/07§5 R04 ("no magic numbers for typed ABI
// constants"). Kept narrow on purpose; ipc::signal::Signal is the
// richer set used by sigaction / kill / signalfd.

use core::sync::atomic::Ordering;

/// Subset of Linux signal numbers the kernel raises against the
/// current task directly (peer-closed write → SIGPIPE; child exit
/// → SIGCHLD; alarm timer → SIGALRM; etc.). Numeric values match
/// Linux uapi.
/// Full POSIX-1.2024 standard signal set per Linux signal(7) — the
/// numeric values match the Linux uapi `<asm-generic/signal.h>` so
/// these can serve as the kernel-internal typed alternative to raw
/// signo integer literals (CLAUDE.md `07§5` rule). NEVER add a new
/// case without checking it against signal(7) — silent off-by-one
/// would mis-route signal handlers.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub enum Signum {
    Sighup    = 1,
    Sigint    = 2,
    Sigquit   = 3,
    Sigill    = 4,
    Sigtrap   = 5,
    Sigabrt   = 6,        // also SIGIOT
    Sigbus    = 7,
    Sigfpe    = 8,
    Sigkill   = 9,
    Sigusr1   = 10,
    Sigsegv   = 11,
    Sigusr2   = 12,
    Sigpipe   = 13,
    Sigalrm   = 14,
    Sigterm   = 15,
    Sigstkflt = 16,
    Sigchld   = 17,
    Sigcont   = 18,
    Sigstop   = 19,
    Sigtstp   = 20,
    Sigttin   = 21,
    Sigttou   = 22,
    Sigurg    = 23,
    Sigxcpu   = 24,
    Sigxfsz   = 25,
    Sigvtalrm = 26,
    Sigprof   = 27,
    Sigwinch  = 28,
    Sigio     = 29,        // also SIGPOLL
    Sigpwr    = 30,
    Sigsys    = 31,        // also SIGUNUSED
}

impl Signum {
    /// Linux signo (1-based).
    /// # C: O(1)
    pub const fn as_u8(self) -> u8 { self as u8 }
    /// Bit index in the sigpending u64 (0-based).
    /// # C: O(1)
    pub const fn bit(self) -> u64 { 1u64 << (self.as_u8() - 1) }
}

/// Raise `sig` against the currently-running task. No-op if no
/// task is current (boot path, no runqueue installed). Default
/// disposition + handler dispatch happen in the per-syscall-return
/// sig path; this only sets the pending bit.
/// # C: O(1)
pub fn send_signal_self(sig: Signum) {
    if let Some(cur) = super::schedule::current() {
        cur.sigpending.fetch_or(sig.bit(), Ordering::Release);
    }
}

/// F168: bits in `task.sigpending` that are not masked by
/// `task.sigmask`. Zero when every pending signal is currently
/// blocked. Blocking syscalls treat a non-zero result as "wake
/// up and surface -EINTR" (Linux semantic).
/// # C: O(1)
pub fn deliverable_signals(task: &crate::Task) -> u64 {
    task.sigpending.load(Ordering::Acquire) & !task.sigmask.load(Ordering::Acquire)
}

/// F168: convenience for the running task. None when no task
/// is current.
/// # C: O(1)
pub fn deliverable_signals_self() -> u64 {
    super::schedule::current().map(deliverable_signals).unwrap_or(0)
}

/// F168: if `task` is currently Sleeping (parked on some
/// WaitList), transition to Runnable and enqueue so the parked
/// helper observes the just-set pending signal on its next
/// re-check. No-op for other states. Mirrors `wake_if_stopped`.
/// # C: O(log N) under runqueue inner lock
pub fn wake_if_sleeping(task: &alloc::sync::Arc<crate::Task>) {
    if task.state() != crate::TaskState::Sleeping { return; }
    task.set_state(crate::TaskState::Runnable);
    if let Some(rq) = super::runqueue::global() {
        let mut inner = rq.inner.lock();
        task.lift_vruntime(inner.cfs.min_vruntime());
        inner.enqueue(alloc::sync::Arc::clone(task));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
        crate::preempt::set_need_resched();
    }
}
