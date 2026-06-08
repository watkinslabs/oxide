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
    // Enqueue onto the task's OWNER-CPU runqueue (its last-run CPU, stamped by
    // swap_current), not the waker's `global()` — a remote wake must not move
    // the task onto the wrong CPU's runqueue. Fall back to local for a
    // never-run task (cpu still u16::MAX) or an unknown owner.
    let owner = task.cpu.load(Ordering::Acquire);
    let rq_opt = if owner != u16::MAX {
        // SAFETY: global_for indexes the per-CPU runqueue table by cpu id;
        // owner was stamped from a live runqueue's cpu field.
        unsafe { super::runqueue::global_for(owner as u32) }.or_else(super::runqueue::global)
    } else {
        super::runqueue::global()
    };
    if let Some(rq) = rq_opt {
        let mut inner = rq.inner.lock();
        // F211: sleeper credit on wake. See Task::set_vruntime_to_floor.
        task.set_vruntime_to_floor(inner.cfs.min_vruntime());
        inner.enqueue(alloc::sync::Arc::clone(task));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
        crate::preempt::set_need_resched();
    }
}

/// F412 Stage G: cross-thread/CPU signal nudge. After a sender sets a
/// pending bit on `task` (kill/tgkill/sigqueue), call this to make the
/// target observe + deliver the signal PROMPTLY:
///  - parked (Sleeping) ⇒ wake it (re-checks deliverable on resume),
///  - running/runnable on a DIFFERENT CPU ⇒ send a resched IPI/SGI so
///    it takes an IRQ exit and hits the Stage-E async-delivery hook.
/// This is what makes Go's cross-thread SIGURG (async preempt) prompt:
/// the target thread spinning in USER code has no syscall return to ride
/// on, so the IPI-forced IRQ exit is its delivery point. On UP (or when
/// the target is the caller's own CPU) the IPI is skipped — the next
/// local tick delivers. No-op if the target is the running CURRENT task
/// (it'll see the signal at its own next syscall/IRQ exit).
/// # C: O(1) + O(log N) wake path
pub fn nudge_task(task: &alloc::sync::Arc<crate::Task>) {
    // Parked target: wake so it re-checks pending on resume.
    wake_if_sleeping(task);
    // Don't IPI ourselves — the caller delivers at its own return.
    let self_cpu: u32 = {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() }
        #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
        { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() }
        #[cfg(not(target_os = "oxide-kernel"))]
        { 0 }
    };
    let tgt_cpu = task.cpu.load(Ordering::Acquire) as u32;
    if tgt_cpu == self_cpu { return; }
    // Only IPI a target that is running/runnable on its CPU (Runnable
    // covers both queued and currently-executing in this scheduler).
    if task.state() == crate::TaskState::Runnable {
        // SAFETY: send_resched_ipi is a non-blocking IPI/SGI to an
        // online CPU; hook installed at boot (no-op if unset / UP).
        unsafe { let _ = super::send_resched_ipi(tgt_cpu); }
    }
}

/// cgroup v2 freezer (`cgroup.freeze=1`): mark `task` frozen and pull it
/// off the runqueue. A running task yields on the next `need_resched` and
/// the enqueue chokepoint won't re-add it; a sleeping task stays parked
/// (the chokepoint blocks its wake-enqueue) until thawed.
/// # C: O(N) runqueue remove
pub fn freeze_task(task: &alloc::sync::Arc<crate::Task>) {
    task.frozen.store(true, Ordering::Release);
    if let Some(rq) = super::runqueue::global() {
        let mut inner = rq.inner.lock();
        let _ = inner.remove(task.tid);
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
    }
    crate::preempt::set_need_resched();
}

/// cgroup v2 thaw (`cgroup.freeze=0`): clear the frozen flag and
/// re-enqueue if the task is runnable (a still-blocked task re-enqueues on
/// its own wake, now that the chokepoint admits it).
/// # C: O(log N) enqueue
pub fn unfreeze_task(task: &alloc::sync::Arc<crate::Task>) {
    task.frozen.store(false, Ordering::Release);
    if task.state() != crate::TaskState::Runnable { return; }
    if let Some(rq) = super::runqueue::global() {
        let mut inner = rq.inner.lock();
        inner.enqueue(alloc::sync::Arc::clone(task));
        rq.nr_running.store(inner.nr_running(), Ordering::Release);
        crate::preempt::set_need_resched();
    }
}
