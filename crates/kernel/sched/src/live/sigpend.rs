// F167: per-task signal-pending bitmap helpers. Kernel-side ABI
// matches Linux's sigset_t bit layout: signal N sets bit (N - 1)
// of the u64 `Task::sigpending`. Signum is a typed enum so callers
// outside this crate (net, fs, etc.) don't open-code raw signal
// numbers — per docs/07§5 R04 ("no magic numbers for typed ABI
// constants"). Kept narrow on purpose; ipc::signal::Signal is the
// richer set used by sigaction / kill / signalfd.

use core::sync::atomic::Ordering;

const SIG_DFL: u64 = 0;
const SIG_IGN: u64 = 1;

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

/// Task holding the PROCESS-directed pending set for `task`'s thread group —
/// Linux `signal_struct::shared_pending`. `kill(2)`/`sigqueue(3)` resolve a
/// tgid to the group LEADER and post there, so the leader's `sigpending` IS
/// the shared set; a thread that only ever inspects its own set is blind to
/// every process-directed signal (`sigwaitinfo` in a worker thread would hang
/// forever). `None` when `task` is itself the leader — its own set already
/// covers both, and a union must not double-count.
/// # C: O(1)
pub fn group_signal_target(task: &crate::Task) -> Option<alloc::sync::Arc<crate::Task>> {
    let leader = task.thread_group.leader_task()?;
    if leader.tid == task.tid { None } else { Some(leader) }
}

/// Process-directed pending bits visible to `task` (Linux
/// `signal->shared_pending.signal`). Zero for a group leader, whose own
/// `sigpending` already is that set. # C: O(1)
pub fn shared_pending(task: &crate::Task) -> u64 {
    match group_signal_target(task) {
        Some(l) => l.sigpending.load(Ordering::Acquire),
        None    => 0,
    }
}

/// Linux `do_sigpending`'s union: thread-private pending OR process-directed
/// pending. What `rt_sigpending(2)` reports and what `rt_sigtimedwait(2)` /
/// `rt_sigsuspend(2)` must wait on. # C: O(1)
pub fn all_pending(task: &crate::Task) -> u64 {
    task.sigpending.load(Ordering::Acquire) | shared_pending(task)
}

/// Dequeue one queued record for `sig` from `t` and clear the pending bit when
/// the queue drains, claiming the signal so exactly ONE consumer gets it.
/// `None` = the bit was not set, or a concurrent consumer won the claim.
/// `Some(None)` = claimed a bitmap-only signal with no queued siginfo.
/// # C: O(1)
fn claim_from(t: &crate::Task, sig: u32, bit: u64) -> Option<Option<crate::SigInfo>> {
    if t.sigpending.load(Ordering::Acquire) & bit == 0 { return None; }
    let (rec, empty) = t.dequeue_siginfo(sig);
    if rec.is_some() {
        // Popping a record IS the claim — no other consumer can pop the same one.
        if empty { t.sigpending.fetch_and(!bit, Ordering::Release); }
        return Some(rec);
    }
    // Bitmap-only signal: the bit itself is the token. Exactly one clearer
    // observes it set in the prior value, so two `sigwaitinfo` threads racing
    // for one `kill(2)` can never both return it.
    if t.sigpending.fetch_and(!bit, Ordering::AcqRel) & bit != 0 { Some(None) } else { None }
}

/// Linux `dequeue_signal`: consume `sig` for `task`, preferring the
/// thread-private queue and falling back to the process-directed one, exactly
/// as `__dequeue_signal(&tsk->pending, ...)` then `&tsk->signal->shared_pending`.
/// `None` when neither set held it.
/// # C: O(1)
pub fn dequeue_signal(task: &crate::Task, sig: u32) -> Option<Option<crate::SigInfo>> {
    let Some(bit) = crate::signum::bit_for(sig) else { return None };
    if let Some(rec) = claim_from(task, sig, bit) { return Some(rec); }
    let shared = group_signal_target(task)?;
    claim_from(&shared, sig, bit)
}

/// F168: bits in `task.sigpending` that are not masked by
/// `task.sigmask`. Zero when every pending signal is currently
/// blocked. Blocking syscalls treat a non-zero result as "wake
/// up and surface -EINTR" (Linux semantic).
/// # C: O(1)
pub fn deliverable_signals(task: &crate::Task) -> u64 {
    let pending = task.sigpending.load(Ordering::Acquire);
    let unmasked = pending & !task.sigmask.load(Ordering::Acquire);
    let mut actionable = 0u64;
    for sig in 1..=64u32 {
        let bit = 1u64 << (sig - 1);
        if unmasked & bit == 0 { continue; }
        // Linux only interrupts a blocking syscall for a signal that would
        // actually be delivered. SIG_DFL signals whose default action is
        // ignore (notably SIGCHLD) and explicit SIG_IGN remain pending until
        // the normal return-to-user signal path consumes them, but must not
        // turn an empty pipe read into EINTR.
        let act = task.sigactions_ref().get(sig);
        let ignored = act.handler == SIG_IGN
            || act.handler == SIG_DFL && matches!(crate::signum::default_action(sig),
                crate::signum::DefaultAction::Ign | crate::signum::DefaultAction::Cont);
        if !ignored || crate::signum::is_unblockable(sig) {
            actionable |= bit;
        }
    }
    actionable
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
        if let Some(p) = child.parent() { wake_if_sleeping(&p); }
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
