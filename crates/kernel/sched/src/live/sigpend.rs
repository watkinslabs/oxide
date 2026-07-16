// F167: per-task signal-pending bitmap helpers. Kernel-side ABI
// matches Linux's sigset_t bit layout: signal N sets bit (N - 1)
// of the u64 `Task::sigpending`. Signum is a typed enum so callers
// outside this crate (net, fs, etc.) don't open-code raw signal
// numbers — per docs/07§5 R04 ("no magic numbers for typed ABI
// constants"). Kept narrow on purpose; ipc::signal::Signal is the
// richer set used by sigaction / kill / signalfd.

use core::sync::atomic::Ordering;

// `Signum` moved to the non-gated `crate::signum` module so the signal(7)
// default-disposition policy is hosted-testable (`live` is kernel-only). Kept
// re-exported here so every `sched::live::sigpend::Signum` call site resolves
// unchanged.
pub use crate::signum::Signum;

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

/// Linux `zap_other_threads` (kernel/signal.c): on `exit_group(2)` or a
/// fatal signal, EVERY thread in the caller's thread-group dies — the whole
/// process terminates, not just the calling thread. We post an unblockable
/// SIGKILL to each sibling (same `tgid`, excluding self) and wake it, so the
/// sibling runs its own SIG_DFL-terminate at the next signal-delivery point.
/// Without this, a fatal signal (SIGSEGV/SIGABRT) in one thread of a
/// multi-threaded process leaves the siblings alive — and any libc-internal
/// lock the dying thread held leaks, deadlocking a sibling that waits on it.
/// # C: O(N_threads)
pub fn zap_other_threads() {
    let cur = match super::schedule::current() { Some(c) => c, None => return };
    let tgid = cur.tgid.load(Ordering::Acquire);
    let self_tid = cur.tid;
    for (_vtid, tid) in crate::registry::thread_entries(tgid) {
        if tid == self_tid { continue; }
        if let Some(t) = crate::registry::lookup(tid) {
            t.sigpending.fetch_or(Signum::Sigkill.bit(), Ordering::Release);
            signal_wake_up(&t);
        }
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
    // Route through try_to_wake_up (Linux ttwu): atomic Sleeping→Runnable claim,
    // select_task_rq placement, on_cpu handshake + wake_list deferral, sleeper
    // credit, and a remote RESCHED IPI. Replaces the old raw LOCAL-rq enqueue,
    // which had NO on_cpu handshake (a task still on_cpu on another CPU could be
    // enqueued and run on two CPUs) and NO select_task_rq. Process-context
    // callers (signal post, IPC, fasync) reach the local fast path on UP; the
    // timer-ISR scanner uses `ttwu::ttwu_deferred` directly (never the rq lock).
    // SAFETY: wake-site (signal / IPC / fasync) context; the Arc keeps it alive.
    unsafe { super::try_to_wake_up(alloc::sync::Arc::clone(task)); }
}

/// Linux `signal_wake_up`: wake an interruptible sleeper and kick the CPU
/// owning an already-runnable target so it reaches a signal-delivery point.
/// # C: O(log N)
pub fn signal_wake_up(task: &alloc::sync::Arc<crate::Task>) {
    wake_if_sleeping(task);
    if task.state() != crate::TaskState::Runnable { return; }
    let target_cpu = task.cpu.load(Ordering::Acquire);
    if target_cpu == u16::MAX || target_cpu as usize >= cpu::MAX_CPUS { return; }
    super::resched_curr(target_cpu as u32);
}

/// vfork completion (Linux `vfork_done`): clear the departing child's
/// `vfork_pending` and, if it was actually set (a genuine CLONE_VFORK child),
/// wake the parent parked in `sys_clone`'s vfork wait. The `swap` gates the
/// wake — a non-vfork child, or a second departure event, never spuriously
/// wakes its parent. Called from EVERY child-departure site: execve-success,
/// exit / exit_group, and signal-death — so a vfork child that dies any way
/// (not just via the exit syscall) still releases the parent. Replaces the
/// old busy-yield model where the parent spun Runnable and starved a vfork
/// child that blocked in a syscall (UP deadlock, dead timer).
/// # C: O(1) + one wake
pub fn vfork_done(child: &crate::Task) {
    use core::sync::atomic::Ordering;
    if child.vfork_pending.swap(false, Ordering::AcqRel) {
        // SAFETY: `parent_arc` is written once at spawn under the per-task
        // single-mutator invariant (`13§5`) and only read here; upgrading the
        // Weak yields the live parent Arc (or None if already reaped).
        let parent = unsafe {
            (*child.parent_arc.get()).as_ref().and_then(|w| w.upgrade())
        };
        if let Some(p) = parent { wake_if_sleeping(&p); }
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

/// VFS fasync (`O_ASYNC`) SIGIO delivery (Linux `send_sigio` -> `do_send_sig_info`
/// -> `kill_pid_info`). Posts `sig` to the `F_SETOWN` target and wakes it:
///   `owner > 0` — that vpid (task or, for `F_OWNER_TID`, thread) in the init
///                 pid namespace, mirroring how `F_SETOWN` records a pid.
///   `owner < 0` — every member of process group `-owner`.
///   `owner == 0` — no target; no-op.
/// `_uid`/`_euid` are the `F_SETOWN`-time credential snapshot reserved for the
/// `sigio_perm` check (deliver only if the owner could `kill(2)` the target);
/// the basic post path delivers unconditionally for now (the perm gate rides
/// the same follow-up as the cross-NS owner translation). Installed into the
/// VFS via `set_sigio_hook` so `vfs` need not depend on `sched`. # C: O(N_tasks)
/// for a pgrp fan; O(1) for a single owner.
pub fn send_sigio(owner: i32, sig: i32, _uid: u32, _euid: u32) {
    if owner == 0 || !(1..=64).contains(&sig) { return; }
    let bit = 1u64 << (sig - 1);
    if owner > 0 {
        let namespace = namespace_identity::initial(namespace_identity::NamespaceKind::Pid);
        if let Some(t) = crate::registry::lookup_in_namespace(&namespace, owner as u32)
            .or_else(|| crate::registry::lookup(owner as u32))
        {
            t.sigpending.fetch_or(bit, Ordering::Release);
            signal_wake_up(&t);
        }
    } else {
        for t in crate::registry::tasks_in_pgrp((-owner) as u32) {
            t.sigpending.fetch_or(bit, Ordering::Release);
            signal_wake_up(&t);
        }
    }
}

/// Install [`send_sigio`] as the VFS fasync delivery hook (idempotent; a plain
/// atomic store). Called from the fcntl path the first time an `F_SETOWN` /
/// `O_ASYNC` is requested, so a kernel that never uses async-I/O pays nothing.
/// # C: O(1)
pub fn install_sigio_hook() {
    vfs::file::set_sigio_hook(send_sigio);
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
