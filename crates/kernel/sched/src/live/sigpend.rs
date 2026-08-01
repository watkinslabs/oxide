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

/// Raise a kernel-generated, thread-directed `sig` against the running task —
/// Linux `send_sig(sig, current, 1)` (`SEND_SIG_PRIV`). The SIGPIPE / SIGXFSZ
/// producers. Routed through the ONE enqueue so the record carries
/// `si_code = SI_KERNEL` and a SIG_IGN disposition cannot swallow it.
/// # C: O(1)
pub fn send_signal_self(sig: Signum) { super::send::send_sig_priv_self(sig); }

/// Linux `zap_other_threads` (kernel/signal.c): on `exit_group(2)` or a
/// fatal signal, EVERY thread in the caller's thread-group dies — the whole
/// process terminates, not just the calling thread. We post an unblockable
/// SIGKILL to each sibling (same `tgid`, excluding self) and wake it, so the
/// sibling runs its own SIG_DFL-terminate at the next signal-delivery point.
/// Without this, a fatal signal (SIGSEGV/SIGABRT) in one thread of a
/// multi-threaded process leaves the siblings alive — and any libc-internal
/// lock the dying thread held leaks, deadlocking a sibling that waits on it.
///
/// A job-control-STOPPED sibling must be resumed too. Linux passes
/// `resume = 1` here (`signal_wake_up(t, 1)` → `wake_up_state(t,
/// TASK_WAKEKILL | TASK_INTERRUPTIBLE)`, and `TASK_STOPPED` carries
/// `TASK_WAKEKILL`), having first cleared the thread's `JOBCTL_PENDING_MASK`.
/// `signal_wake_up` alone only claims a `Sleeping` task, so a `SIGSTOP`ed
/// thread stayed stopped forever — and because the group leader's zombie is
/// published only once EVERY member has retired, the parent's `wait4` then
/// blocked forever on a process that had already called `exit_group`.
/// # C: O(N_threads)
pub fn zap_other_threads() {
    let cur = match super::schedule::current() { Some(c) => c, None => return };
    let tgid = cur.tgid.load(Ordering::Acquire);
    let self_tid = cur.tid;
    for (_vtid, tid) in crate::registry::thread_entries(tgid) {
        if tid == self_tid { continue; }
        if let Some(t) = crate::registry::lookup(tid) {
            t.sigpending.fetch_or(Signum::Sigkill.bit(), Ordering::Release);
            // Linux `task_clear_jobctl_pending(t, JOBCTL_PENDING_MASK)` runs
            // BEFORE the wake: a queued group-stop or ptrace trap must not
            // re-stop (or re-trap) a thread we just killed.
            t.jobctl.store(crate::jobctl::clear_pending(t.jobctl.load(Ordering::Acquire),
                crate::jobctl::PENDING_MASK | crate::jobctl::LISTENING), Ordering::Release);
            super::registry::wake_if_stopped(&t, crate::jobctl::WakeKind::Kill);
            // Resuming a thread so it can die is not a `wait4(WCONTINUED)`
            // event either.
            t.stop_pending.store(false, Ordering::Release);
            t.cont_pending.store(false, Ordering::Release);
            signal_wake_up(&t);
        }
    }
}

/// Linux `group_send_sig_info(sig, info, p, PIDTYPE_TGID)`: queue `sig` on the
/// TARGET PROCESS' shared pending set (never on one thread's private set) and
/// wake a thread that can take it. `target` may be any thread of that process —
/// the group is what is signalled.
///
/// A thin spelling of `send::send_signal` with the process target pinned, kept
/// because `kill(2)`, the pgrp fan and the broadcast all name it.
/// # C: O(N_threads)
pub fn post_group_signal(target: &alloc::sync::Arc<crate::Task>, sig: u32,
                         src: crate::sigsend::SigSource) -> Result<(), super::send::SendErr> {
    super::send::send_signal(target, sig, src, crate::sigsend::SigTarget::Process)
}

/// Linux `complete_signal` (`kernel/signal.c`): once a process-directed signal
/// is queued, find a thread that `wants_signal()` — one that does not have it
/// blocked — and wake THAT thread so it reaches a delivery point.
///
/// The leader is tried first (Linux tries the task the sender named, which for
/// `PIDTYPE_TGID` is the group leader), then the rest of the group. When no
/// thread wants the signal Linux wakes nothing and the signal simply waits in
/// `shared_pending` until some thread unblocks it, so `false` is returned
/// rather than rousing a thread that could not take it.
///
/// `leader_tid` is the group's INTERNAL leader tid (`Task::tgid`), which is how
/// the registry keys threads. The mask rule itself lives ungated in
/// `thread_group::shared_signal::wants_signal` so it is hosted-tested; only the
/// registry walk is here.
/// # C: O(N_threads)
pub fn complete_signal(leader_tid: u32, sig: u32) -> bool {
    use crate::thread_group::shared_signal::wants_signal;
    let Some(bit) = crate::signum::bit_for(sig) else { return false };
    let unblockable = crate::signum::is_unblockable(sig);
    let wake = |t: &alloc::sync::Arc<crate::Task>| {
        if !wants_signal(t.sigmask.load(Ordering::Acquire), bit, unblockable) { return false; }
        // `signal_wake_up(t, sig == SIGKILL)` — see `send::publish`. A STOPPED
        // task is only resumed by the kill; every other signal waits for the
        // SIGCONT (or, for a tracee, for the tracer) that ends the stop.
        if sig == Signum::Sigkill as u32 {
            super::registry::wake_if_stopped(t, crate::jobctl::WakeKind::Kill);
        }
        signal_wake_up(t);
        true
    };
    if let Some(l) = crate::registry::lookup(leader_tid) { if wake(&l) { return true; } }
    for (_vtid, tid) in crate::registry::thread_entries(leader_tid) {
        if tid == leader_tid { continue; }
        if let Some(t) = crate::registry::lookup(tid) { if wake(&t) { return true; } }
    }
    false
}

/// Linux `signalfd_notify(t, sig)`: a signal that no thread can take by
/// HANDLER is still an event for the process' `signalfd` / `sigwaitinfo` /
/// `rt_sigtimedwait` consumers — and those are exactly the threads that BLOCK
/// it, which is why `complete_signal`'s `wants_signal` filter skips them.
///
/// Linux keeps a dedicated `sighand->signalfd_wqh` waitqueue and wakes it on
/// every send. This kernel's signalfd readers park as ordinary interruptible
/// sleepers, so the equivalent is to rouse the blocking threads themselves;
/// they re-check their queues and re-park if the signal was not theirs.
///
/// Runs only when `complete_signal` woke nobody: a thread that can take the
/// signal outright has already been roused, and a signalfd consumer in the
/// same process is reached by that thread's own delivery work.
/// # C: O(N_threads)
pub fn signalfd_notify(leader_tid: u32, sig: u32) {
    let Some(bit) = crate::signum::bit_for(sig) else { return };
    let notify = |t: &alloc::sync::Arc<crate::Task>| {
        if t.sigmask.load(Ordering::Acquire) & bit == 0 { return; }
        wake_if_sleeping(t);
    };
    if let Some(l) = crate::registry::lookup(leader_tid) { notify(&l); }
    for (_vtid, tid) in crate::registry::thread_entries(leader_tid) {
        if tid == leader_tid { continue; }
        if let Some(t) = crate::registry::lookup(tid) { notify(&t); }
    }
}

/// Process-directed pending bits visible to `task` — Linux
/// `signal->shared_pending.signal`, owned by the thread group
/// (`thread_group/shared_signal.rs`). Identical for every thread of a process,
/// which is the whole point: a worker inspecting only its own set used to be
/// blind to every `kill(2)`. # C: O(1)
pub fn shared_pending(task: &crate::Task) -> u64 {
    task.thread_group.shared_pending()
}

/// Linux `do_sigpending`'s union: thread-private pending OR process-directed
/// pending. What `rt_sigpending(2)` reports and what `rt_sigtimedwait(2)` /
/// `rt_sigsuspend(2)` must wait on. # C: O(1)
pub fn all_pending(task: &crate::Task) -> u64 {
    task.sigpending.load(Ordering::Acquire) | shared_pending(task)
}

/// Linux `dequeue_signal`. Delegates to `Task::dequeue_pending`, which owns
/// the private-then-shared claim protocol so crates without the kernel-only
/// `live` module (signalfd) use the same one.
/// # C: O(1)
pub fn dequeue_signal(task: &crate::Task, sig: u32) -> Option<Option<crate::SigInfo>> {
    task.dequeue_pending(sig)
}

/// F168: bits in `task.sigpending` that are not masked by
/// `task.sigmask`. Zero when every pending signal is currently
/// blocked. Blocking syscalls treat a non-zero result as "wake
/// up and surface -EINTR" (Linux semantic).
/// # C: O(1)
pub fn deliverable_signals(task: &crate::Task) -> u64 { task.deliverable_signals() }

/// F168: convenience for the running task. None when no task
/// is current.
/// # C: O(1)
pub fn deliverable_signals_self() -> u64 {
    super::schedule::current().map(deliverable_signals).unwrap_or(0)
}

/// Whether an UNSURVIVABLE kill is pending for `task` — a `SIGKILL` in either
/// the thread-private or the process-directed set. Distinct from
/// [`deliverable_signals`]: a signal being deliverable means an ordinary
/// blocking operation should give up so the handler can run, whereas this means
/// the task will not run user code again no matter what.
///
/// The blocking mask is deliberately NOT consulted: `SIGKILL` cannot be blocked,
/// caught or ignored.
/// # C: O(1)
pub fn fatal_kill_pending(task: &crate::Task) -> bool {
    let Some(bit) = crate::signum::bit_for(crate::signum::Signum::Sigkill as u32) else { return false };
    all_pending(task) & bit != 0
}

/// Whether an unsurvivable kill is pending for the running task. The core
/// dumper's stop condition: it keeps writing through the fatal signal it is
/// already delivering, and stops only for this.
/// # C: O(1)
pub fn fatal_kill_pending_self() -> bool {
    super::schedule::current().map(|t| fatal_kill_pending(&t)).unwrap_or(false)
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
/// Dequeued from the runqueue it is ACTUALLY on (`rq_locate`, Linux
/// `task_rq_lock`): the caller's CPU is not necessarily the task's, and
/// removing from the wrong tree left a frozen task runnable elsewhere.
/// # C: O(N_cpus · N) runqueue remove
pub fn freeze_task(task: &alloc::sync::Arc<crate::Task>) {
    task.frozen.store(true, Ordering::Release);
    let found = super::rq_locate::dequeue_from_owning_rq_with(
        // SAFETY: `global_for` is sound for any index; it yields `None` for a
        // CPU that has not completed `install_global`, which the walk skips.
        &|c| unsafe { super::runqueue::global_for(c) }, task.tid);
    if let Some((_, cpu)) = found { super::resched_curr(cpu); }
    crate::preempt::set_need_resched();
}

/// VFS fasync (`O_ASYNC`) SIGIO delivery (Linux `send_sigio` -> `do_send_sig_info`
/// -> `kill_pid_info`). Posts `sig` to the `F_SETOWN` target and wakes it:
///   `owner > 0` — that vpid (task or, for `F_OWNER_TID`, thread) in the init
///                 pid namespace, mirroring how `F_SETOWN` records a pid.
///   `owner < 0` — every member of process group `-owner`.
///   `owner == 0` — no target; no-op.
/// `uid`/`euid` are the `F_SETOWN`-time credential snapshot Linux gates every
/// delivery on (`sigio_perm`): `F_SETOWN` lets one process name ANOTHER as the
/// recipient, so without the gate any unprivileged process could point a pipe's
/// `O_ASYNC` owner at a root daemon and drive SIGIO — or, with `F_SETSIG`, a
/// signal of its choosing — into it. The ladder itself is ungated in
/// `crate::sigio`. Installed into the VFS via `set_sigio_hook` so `vfs` need not
/// depend on `sched`. # C: O(N_tasks) for a pgrp fan; O(1) for a single owner.
pub fn send_sigio(ev: vfs::file::AsyncSignal) {
    use vfs::file::owner_type::{F_OWNER_PGRP, F_OWNER_TID};
    if ev.owner <= 0 || !(1..=64).contains(&ev.sig) { return; }
    let creds = crate::sigio::FileOwnerCreds { uid: ev.uid, euid: ev.euid };
    // Linux `send_sigio_to_task`: the record is a full `_sigpoll` siginfo —
    // si_code = the POLL_* reason, si_band = `band_table[reason - POLL_IN]`,
    // si_fd = the `fasync_struct.fa_fd` recorded when `O_ASYNC` was enabled.
    // Without it an `F_SETSIG` handler cannot tell WHICH descriptor fired,
    // which is the only reason to ask for a queued signal instead of SIGIO.
    let info = crate::task::SigInfo {
        signo: ev.sig as u32, code: ev.code, pid: 0, uid: 0, value: 0,
        sys: None, fault: None,
        poll: if ev.queued { Some(hal::SigPoll { band: ev.band, fd: ev.fd }) } else { None },
    };
    if ev.ty == F_OWNER_PGRP {
        // `kill_pgrp` fans out per member, and `sigio_perm` is per RECIPIENT —
        // one unsignalable member of the group does not suppress the rest.
        for t in crate::registry::tasks_in_pgrp(ev.owner as u32) {
            send_sigio_to_task(&t, info, creds, false);
        }
        return;
    }
    let namespace = namespace_identity::initial(namespace_identity::NamespaceKind::Pid);
    if let Some(t) = crate::registry::lookup_in_namespace(&namespace, ev.owner as u32)
        .or_else(|| crate::registry::lookup(ev.owner as u32))
    {
        // `PIDTYPE_PID` (`F_OWNER_TID`) is THREAD-directed: the record joins
        // that one thread's private set, so a sibling cannot consume it.
        send_sigio_to_task(&t, info, creds, ev.ty == F_OWNER_TID);
    }
}

/// Linux `send_sigio_to_task`: `sigio_perm` first, then the send. # C: O(N_threads)
fn send_sigio_to_task(t: &alloc::sync::Arc<crate::Task>, info: crate::task::SigInfo,
    creds: crate::sigio::FileOwnerCreds, thread_directed: bool)
{
    let target = crate::sigio::TargetCreds {
        uid:  t.creds.ruid.load(Ordering::Acquire),
        suid: t.creds.suid.load(Ordering::Acquire),
    };
    if !crate::sigio::sigio_perm(creds, target) { return; }
    // `switch (signum)`: `case 0` (no `F_SETSIG`) is a bare `SEND_SIG_PRIV`
    // SIGIO with no queued record; the `default` arm queues the `_sigpoll`
    // record and, if the queue rejects it, FALLS THROUGH to that same bare
    // SIGIO so readiness is never lost outright.
    let target = if thread_directed { crate::sigsend::SigTarget::Thread }
                 else { crate::sigsend::SigTarget::Process };
    if info.poll.is_some() {
        let queued = super::send::send_signal(t, info.signo,
            crate::sigsend::SigSource::Info(info), target);
        if queued.is_ok() { return; }
    }
    let _ = super::send::send_signal(t, crate::signum::Signum::Sigio as u32,
        crate::sigsend::SigSource::Kernel, target);
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
///
/// Placement goes through `place_runnable` (Linux `ttwu`'s `select_task_rq` +
/// `on_cpu` handshake), NOT a raw enqueue onto the caller's runqueue: the
/// thawed task may be `on_cpu` on another CPU (thaw races a `need_resched`
/// yield it has not finished), and only `select_task_rq` honours
/// `cpus_allowed`. `try_to_wake_up` is the wrong entry point here — the task is
/// already Runnable, so its Sleeping->Runnable claim would drop the placement.
/// # C: O(N_cpus + log N)
pub fn unfreeze_task(task: &alloc::sync::Arc<crate::Task>) {
    task.frozen.store(false, Ordering::Release);
    if task.state() != crate::TaskState::Runnable { return; }
    // SAFETY: thaw site in process context; the caller's Arc keeps `task` alive
    // across placement.
    unsafe { super::ttwu::place_runnable(alloc::sync::Arc::clone(task), false); }
    crate::preempt::set_need_resched();
}
