// Zombie task registry per `13§5` lifecycle. After a task calls
// `sys_exit`, the kernel marks it Zombie and pushes a strong-ref
// `Arc<Task>` here so its parent can `wait4` it later.
//
// Without this registry, the runqueue's swap_current drops the
// only Arc to a Zombie task as soon as `schedule()` picks the
// next runnable, freeing it before the parent has a chance to
// reap. wait4 needs the exit_status + tid which both live in the
// Task.
//
// v1 single-CPU UP. SMP would partition this per-CPU + add lock
// hierarchy; is a follow-up.


use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::{Task, TaskState};
use sync::{Spinlock, TaskList as TaskListClass};

mod reparent;
pub use reparent::{reap_orphans, reparent_children};
#[cfg(test)]
mod tests;

/// Registry of Zombie tasks awaiting `wait4`. Pushed to by
/// `sys_exit`; popped by `sys_wait4`. v1 single-CPU
/// — single global Vec under a spinlock at lock class `TaskList`
/// (`06§3.6`); the registry is the moral equivalent of Linux's
/// global task list for v1's reaping path.
static ZOMBIES: Spinlock<Vec<Arc<Task>>, TaskListClass>
    = Spinlock::new(Vec::new());

/// Parents currently parked in `wait4` waiting for any of their
/// children to enter the Zombie state. Each entry is the parent's
/// own Arc<Task> with state==Sleeping. Pushed by
/// `park_for_wait4`; popped by `park_zombie` when an exiting child
/// announces SIGCHLD to its parent. v1 single-CPU; SMP would shard
/// per-CPU.
static WAITERS: Spinlock<Vec<Arc<Task>>, TaskListClass>
    = Spinlock::new(Vec::new());

/// Build the child-exit `SigInfo` for SIGCHLD or a real-time clone exit
/// signal. `si_pid`
/// is the child's VPID (vtgid — the value waitpid/fork return, NOT
/// the opaque internal tid); `si_uid` is the child's real uid;
/// `si_status` + `si_code` are decoded from the child's wait4-encoded
/// `exit_status` per siginfo(7): bit 8 (0x100) set ⇒ killed by signal
/// (CLD_KILLED / CLD_DUMPED if the core bit 0x80 is set on the signo),
/// else exited (CLD_EXITED, si_status = exit code).
/// # C: O(1)
fn child_exit_info(child: &Task, signo: u32) -> crate::task::SigInfo {
    // CLD_* si_code values (siginfo(7) / asm-generic/siginfo.h).
    const CLD_EXITED: i32 = 1;
    const CLD_KILLED: i32 = 2;
    const CLD_DUMPED: i32 = 3;
    let raw = child.exit_status.load(Ordering::Acquire);
    let (code, status) = if raw & 0x100 != 0 {
        let signo = raw & 0x7f;
        // 0x80 bit in the encoded byte marks a core dump (mirrors the
        // SIG_DFL / SIGSEGV terminate encoders that set 0x100|signo).
        let cld = if raw & 0x80 != 0 { CLD_DUMPED } else { CLD_KILLED };
        (cld, signo)
    } else {
        (CLD_EXITED, raw & 0xff)
    };
    crate::task::SigInfo {
        signo,
        code,
        pid:   child.vtgid.load(Ordering::Acquire),
        uid:   child.creds.ruid.load(Ordering::Acquire),
        value: status as u64,
    }
}

/// Queue a reparented child as SIGCHLD for init. Linux reparenting changes the
/// wait parent and uses the reaper's SIGCHLD notification contract. # C: O(1)
fn push_child_event(child: &Task, parent: &Task) {
    parent.child_sigq_push(child_exit_info(child, super::sigpend::Signum::Sigchld.as_u8() as u32));
}

/// Roll the dying child's CPU time into the parent's cumulative-children
/// counters for `getrusage(RUSAGE_CHILDREN)` / `times().tms_c[us]time`:
/// the child's tick-sampled user/kernel time (`utime_ns`/`stime_ns`) and,
/// for back-compat, its wall-clock elapsed into `cumulative_child_ns`.
/// Called once per child from `signal_child_exit` (the live exit path).
/// # C: O(1)
fn accrue_child_time(child: &Task, parent: &Task) {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    let now = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let now = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let elapsed = now.saturating_sub(child.spawn_ns.load(Ordering::Acquire));
    parent.cumulative_child_ns.fetch_add(elapsed, Ordering::AcqRel);
    parent.cumulative_child_utime_ns
        .fetch_add(child.utime_ns.load(Ordering::Acquire), Ordering::AcqRel);
    parent.cumulative_child_stime_ns
        .fetch_add(child.stime_ns.load(Ordering::Acquire), Ordering::AcqRel);
}

/// Mark the exit path for deferred parent publication. The switch tail owns the
/// Arc and calls `enqueue_zombie`, which must make the child waitable before
/// exposing SIGCHLD to signalfd or a handler. # C: O(1)
pub fn signal_child_exit(_task: &Task) {
    #[cfg(feature = "debug-ssh")]
    {
        klog::write_raw(b"[INFO]  ssh-trace: defer signal_child_exit child=");
        klog::write_dec_u64(_task.tid as u64);
        klog::write_raw(b"\n");
    }
}

/// Push `task` onto the ZOMBIES list. Used by `schedule()` when it
/// detects that prev's state is Zombie: rather than leaking the Arc
/// returned by `swap_current` on the dying task's about-to-be-orphaned
/// kernel stack, transfer ownership here so reap_one can release it.
/// Parent publication order is strict: ZOMBIES first, queued siginfo second,
/// pending bit and signalfd notification third, waiter wakeups last. # C: O(1)
pub fn enqueue_zombie(task: Arc<Task>) {
    let parent = task.parent();
    let parent_tid = task.parent_tid.load(Ordering::Acquire);
    #[cfg(feature = "debug-displaystack")]
    {
        klog::write_raw(b"[zombie publish] child=");
        klog::write_dec_u64(task.tid as u64);
        klog::write_raw(b" vpid=");
        klog::write_dec_u64(task.vtgid.load(Ordering::Acquire) as u64);
        klog::write_raw(b" parent=");
        klog::write_dec_u64(parent_tid as u64);
        klog::write_raw(b" exit_signal=");
        klog::write_dec_u64(task.exit_signal.load(Ordering::Acquire) as u64);
        klog::write_raw(b" status=");
        klog::write_hex_u64(task.exit_status.load(Ordering::Acquire) as u32 as u64);
        klog::write_raw(b" parent_live=");
        klog::write_dec_u64(if parent.is_some() { 1 } else { 0 });
        klog::write_raw(b"\n");
    }
    ZOMBIES.lock().push(Arc::clone(&task));
    let mut signal_parent = false;
    if let Some(ref p) = parent {
        accrue_child_time(&task, p);
        if let Some(signo) = crate::clone_exit_signal(task.exit_signal.load(Ordering::Acquire)) {
            if signo == super::sigpend::Signum::Sigchld.as_u8() as u32 {
                p.child_sigq_push(child_exit_info(&task, signo));
            } else if crate::signum::is_realtime(signo) {
                p.rt_reserve(signo);
                let _ = p.rt_push(child_exit_info(&task, signo));
            }
            if let Some(bit) = crate::bit_for(signo) { p.sigpending.fetch_or(bit, Ordering::Release); }
            signal_parent = true;
        }
    }
    wake_wait4_parent(parent_tid);
    if signal_parent { if let Some(p) = parent { wake_task_for_signal(&p); } }
}

/// Park the current task in WAITERS, marking it Sleeping. Caller
/// (sys_wait4) must call `schedule()` immediately after; the
/// task only resumes when `wake_wait4_parent` re-enqueues it.
///
/// Dedups on the task's own tid before pushing, mirroring
/// `WaitList::park_with_deadline`: an unrelated signal wake
/// (`wake_if_sleeping`/`try_to_wake_up`) rouses a parked waiter
/// WITHOUT popping its WAITERS entry (that list has no idea about
/// WAITERS). If the woken task doesn't reap (its pid filter didn't
/// match, or the wake was unrelated) and loops back into wait4, a
/// second park without this guard would leave TWO entries for the
/// same tid — `wake_wait4_parent` would then run its post-claim
/// placement against a task that already resumed running (see
/// `claim_wake` below), which is exactly the stale-waiter class this
/// codebase has hit repeatedly on other wait/wake lists.
/// # SAFETY: caller is the running task on this CPU; preempt-off;
/// runqueue installed.
/// # C: O(N_waiters)
/// # Lk: WAITERS (TaskList class)
pub unsafe fn park_for_wait4() {
    let rq = match super::runqueue::global() { Some(r) => r, None => return };
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: rq.current is non-null after install_global; bump strong count to materialise an Arc the WAITERS list can hold across schedule.
    unsafe { Arc::increment_strong_count(raw); }
    // SAFETY: matching Arc::from_raw consumes the bumped ref.
    let arc = unsafe { Arc::from_raw(raw) };
    arc.set_state(TaskState::Sleeping);
    let mut waiters = WAITERS.lock();
    waiters.retain(|a| a.tid != arc.tid);
    waiters.push(arc);
}

/// F143: undo `park_for_wait4` for the current task — used when
/// `sys_wait4`'s post-park reap recheck found a Zombie that was
/// added between the loop-top reap and the park (missed-wakeup
/// race). Removes self from WAITERS and restores Runnable state.
/// # SAFETY: caller is the running task on this CPU; preempt-off.
/// # C: O(N_waiters)
pub fn unpark_self_from_wait4() {
    let rq = match super::runqueue::global() { Some(r) => r, None => return };
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() { return; }
    let cur_tid = {
        // SAFETY: rq.current is non-null after install_global; we read tid without bumping the strong count.
        let t: &Task = unsafe { &*raw };
        t.tid
    };
    let mut waiters = WAITERS.lock();
    let mut i = waiters.len();
    while i > 0 {
        i -= 1;
        if waiters[i].tid == cur_tid {
            let arc = waiters.swap_remove(i);
            arc.set_state(TaskState::Runnable);
            return;
        }
    }
    // SAFETY: rq.current is non-null after install_global; we are sole writer to state via the single-mutator invariant for the running task on this CPU.
    let t: &Task = unsafe { &*raw };
    t.set_state(TaskState::Runnable);
}

/// Wake any parent task waiting in `wait4(-1, ...)` for `parent_tid`'s
/// children to exit. Called from `park_zombie` after the child has
/// been added to the ZOMBIES registry. The woken parent re-runs the
/// reap_one filter; if no zombie matches its specific pid filter,
/// it falls back through the wait4 retry loop and re-parks.
///
/// Placement is gated by `Task::claim_wake` (the same Sleeping->Runnable
/// CAS `try_to_wake_up` uses), NOT an unconditional `set_state` + enqueue.
/// A WAITERS entry can go stale without being removed (an unrelated signal
/// wake resumed the task without popping it — `park_for_wait4` dedups the
/// NEXT park, but a wake racing between that resume and the next park still
/// finds the old entry here first). Without the claim, a stale entry for a
/// task that is now `current` (Runnable, on_cpu=true, on_rq=false) would be
/// force-set Runnable (harmless, already is) and unconditionally enqueued —
/// `RunqueueInner::enqueue`'s on_rq guard would accept it (on_rq is false
/// while it's executing), landing a task that is ACTIVELY RUNNING into the
/// ready tree too. `claim_wake` requires the observed state to be exactly
/// `Sleeping`, so a task that already resumed (Runnable) or died (Zombie)
/// fails the claim and is safely dropped instead of re-placed.
/// # C: O(N_waiters)
/// # Lk: WAITERS, then runqueue inner
fn wake_wait4_parent(parent_tid: u32) {
    let mut waiters = WAITERS.lock();
    #[cfg(feature = "debug-ssh")]
    {
        let n = waiters.iter().filter(|t| t.tid == parent_tid).count();
        klog::write_raw(b"[INFO]  ssh-trace: wake_wait4_parent parent_tid=");
        klog::write_dec_u64(parent_tid as u64);
        klog::write_raw(b" wait4_waiters_found=");
        klog::write_dec_u64(n as u64);
        klog::write_raw(b" (0 => parent not in wait4 - reap relies on its SIGCHLD handler)\n");
    }
    if waiters.is_empty() { return; }
    let rq = match super::runqueue::global() {
        Some(r) => r,
        None    => { waiters.clear(); return; }
    };
    // Walk in reverse so swap_remove preserves earlier indices.
    let mut i = waiters.len();
    let mut woken: Vec<Arc<Task>> = Vec::new();
    while i > 0 {
        i -= 1;
        if waiters[i].tid == parent_tid {
            woken.push(waiters.swap_remove(i));
        }
    }
    drop(waiters);
    if woken.is_empty() { return; }
    let mut inner = rq.inner.lock();
    let mut placed = false;
    for t in woken {
        // Exclusive Sleeping->Runnable claim (see fn doc): a task that isn't
        // genuinely Sleeping anymore (already woken elsewhere, or exited) is
        // dropped here rather than force-placed.
        if !t.claim_wake() { continue; }
        // F211: sleeper credit. Reset vruntime to min so a long-running
        // task that blocked on wait4 doesn't lose the pick to a freshly-
        // spawned child with vruntime=0. See Task::set_vruntime_to_floor.
        t.set_vruntime_to_floor(inner.cfs.min_vruntime());
        inner.enqueue(t);
        placed = true;
    }
    if !placed { return; }
    rq.nr_running.store(inner.nr_running(), Ordering::Release);
    crate::preempt::set_need_resched();
}

/// Wake `task` from an interruptible sleep (epoll_wait/poll on a
/// signalfd, blocking read, etc.) because a signal was just posted to
/// it: CAS `Sleeping → Runnable` and enqueue so its wait loop re-runs,
/// re-scans, and observes the pending signal. Linux wakes interruptible
/// sleeps on signal delivery; without this, PID1 (systemd) parked in
/// `epoll_wait` on its SIGCHLD signalfd never notices a child exit while
/// otherwise idle — so the console getty never respawns after logout.
///
/// No-op if the CAS fails (the task is running/runnable, or
/// `wake_wait4_parent` already made it Runnable) — which is what keeps
/// this from double-enqueueing a wait4-parked parent. Call AFTER
/// `wake_wait4_parent`.
/// # C: O(1)
/// # Lk: runqueue inner
fn wake_task_for_signal(task: &Arc<Task>) {
    // Route through the canonical waker so a signal-wake of a task still
    // finishing its context-switch-off on another CPU is deferred through that
    // CPU's wake-list (on_cpu) instead of enqueued live. try_to_wake_up does
    // the Sleeping->Runnable CAS claim itself, so a non-Sleeping task is a
    // no-op — matching the old cas_state guard.
    super::signal_wake_up(task);
}

/// Reap one Zombie child matching the `wait4` filter
/// (`wait_pid_matches`). Returns `Some((tid, exit_code))` and drops
/// the strong-ref so the Task is freed. `None` if no matching Zombie
/// is queued.
/// # C: O(N_zombies)
/// True iff any queued zombie has `parent_tid == parent`. Used
/// by `sys_wait4` to decide whether to clear the SIGCHLD pending
/// bit after a reap (F237 — keeps a signal_dispatch SIGCHLD
/// from firing after wait4 already drained the zombies, which
/// would make the shell's handler re-wait → ECHILD → $?=255).
/// # C: O(N_zombies)
pub fn has_zombies(parent: u32) -> bool {
    use core::sync::atomic::Ordering;
    ZOMBIES.lock().iter().any(|t| t.parent_tid.load(Ordering::Acquire) == parent)
}

use crate::registry::{self, wait_candidate_matches, WaitChildSnapshot};
use crate::wait_select::{Candidate, Waiter};

/// # C: O(N_tasks)
fn zombie_candidate(t: &Task) -> Candidate {
    let parent_tid = t.parent_tid.load(Ordering::Acquire);
    let parent_tgid = registry::lookup(parent_tid)
        .map(|p| p.tgid.load(Ordering::Acquire))
        .unwrap_or(0);
    Candidate {
        parent_tid,
        parent_tgid,
        vpid:        t.vtgid.load(Ordering::Acquire),
        pgid:        t.pgid.load(Ordering::Acquire),
        exit_signal: t.exit_signal.load(Ordering::Acquire),
    }
}

/// Peek one Zombie child matching the `wait4` filter WITHOUT removing
/// it — the `waitid(2)` `WNOWAIT` contract (leave the child in a
/// waitable state). Same filter as `reap_one`. systemd's SIGCHLD
/// handler peeks with `WEXITED|WNOHANG|WNOWAIT` to learn which unit a
/// pid belongs to, then reaps separately; if the peek reaped, that
/// second wait would get ECHILD and systemd mis-supervises the service.
/// # C: O(N_zombies)
pub fn peek_one(parent: u32, parent_tgid: u32, pid: i32, parent_pgid: u32, options: u64) -> Option<(WaitChildSnapshot, i32)> {
    use core::sync::atomic::Ordering;
    let q = ZOMBIES.lock();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    let t = q.iter().find(|t| wait_candidate_matches(zombie_candidate(t), waiter, pid, options))?;
    Some((WaitChildSnapshot::from_task(t), t.exit_status.load(Ordering::Acquire)))
}

/// # C: O(N_zombies)
pub fn reap_one(parent: u32, parent_tgid: u32, pid: i32, parent_pgid: u32, options: u64) -> Option<(WaitChildSnapshot, i32)> {
    use core::sync::atomic::Ordering;
    let mut q = ZOMBIES.lock();
    #[cfg(feature = "debug-ssh")]
    {
        let total = q.len();
        let mine = q.iter().filter(|t| t.parent_tid.load(Ordering::Acquire) == parent).count();
        klog::write_raw(b"[INFO]  ssh-trace: reap_one parent=");
        klog::write_dec_u64(parent as u64);
        klog::write_raw(b" pid=");
        klog::write_dec_u64(pid as i64 as u64);
        klog::write_raw(b" zombies_total=");
        klog::write_dec_u64(total as u64);
        klog::write_raw(b" zombies_for_parent=");
        klog::write_dec_u64(mine as u64);
        klog::write_raw(b"\n");
        // Show each zombie's (tid, parent_tid) so a parent/pid mismatch is visible.
        for t in q.iter() {
            klog::write_raw(b"[INFO]  ssh-trace:   zombie tid=");
            klog::write_dec_u64(t.tid as u64);
            klog::write_raw(b" parent_tid=");
            klog::write_dec_u64(t.parent_tid.load(Ordering::Acquire) as u64);
            klog::write_raw(b"\n");
        }
    }
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    let pos = q.iter().position(|t| wait_candidate_matches(zombie_candidate(t), waiter, pid, options))?;
    let t = q.remove(pos);
    // Return the child's vpid (vtgid) — the PID userspace waited on — NOT the
    // opaque internal tid. Single pid identity (Linux): waitpid returns the
    // same value fork() returned.
    let child = WaitChildSnapshot::from_task(&t);
    let code = t.exit_status.load(Ordering::Acquire);
    drop(q);
    // Linux release_task: a reaped process leaves /proc immediately, even if a
    // pidfd still pins the task_struct. Mark it so procfs enumeration drops it —
    // otherwise a pidfd-pinned reaped child lingers as a visible zombie in
    // ps/htop (the strong Arc keeps the registry Weak alive).
    registry::mark_reaped(&t);
    drop(t);  // strong-ref released; Task freed if no other holders
    Some((child, code))
}

/// # C: O(N_zombies × N_tasks)
pub fn has_wait_zombies(parent: u32, parent_tgid: u32, pid: i32, parent_pgid: u32, options: u64) -> bool {
    let q = ZOMBIES.lock();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    q.iter().any(|t| wait_candidate_matches(zombie_candidate(t), waiter, pid, options))
}

/// Terminate the CURRENT task as if killed by signal `sig` (default fatal
/// action) and schedule away — DIVERGES. The page-fault handler calls this
/// when a USER-mode fault is unresolvable: Linux delivers SIGSEGV/SIGBUS whose
/// default action terminates the faulting process; the kernel must kill that
/// ONE task, never halt the machine. Mirrors `sys_exit`'s teardown so the
/// parent reaps it (wait status = `sig | 0x100`, "killed by signal") and the
/// system keeps running past a single service's bad-pointer crash.
/// # SAFETY: caller is the exception handler running on the faulting task's
/// kernel stack, IRQs off, runqueue installed.
/// # C: O(N_tasks) reparent + O(log N) schedule
pub fn terminate_current_with_signal(sig: u8) -> ! {
    // Linux fatal default actions are group-fatal. Post SIGKILL to every
    // sibling before dismantling the current task so no thread survives with
    // resources or userspace locks owned by the faulting thread.
    if let Some(current) = crate::live::current() {
        crate::timers::clear_process_timers(current);
    }
    super::zap_other_threads();
    if let Some(rq) = crate::live::global() {
        let raw = rq.current.load(Ordering::Acquire);
        if !raw.is_null() {
            // SAFETY: rq.current installed via Arc::into_raw, non-null; we run
            // ON this task so no concurrent freer; reads/atomic-stores only.
            let task: &Task = unsafe { &*raw };
            task.exit_status.store(crate::signum::killed_status(sig as u32), Ordering::Release);
            super::vfork_done(task); // clear + wake a parked vfork parent (signal-death)
            ::cgroup::on_exit(task.tid as u64);
            // Robust-futex recovery (Linux do_exit -> exit_robust_list): a
            // thread killed by a fatal signal while holding a robust mutex must
            // mark it FUTEX_OWNER_DIED and wake a waiter, else a peer blocked on
            // that lock hangs forever. MUST run before replace_mm below (the
            // walk reads the dying task's still-mapped user list). Routed via
            // the sched hook because the walk body lives in `ipc`.
            let rl = task.robust_list_head.load(Ordering::Acquire);
            if rl != 0 {
                let vt = task.vtid.load(Ordering::Acquire);
                let owner_tid = if vt != 0 { vt } else { task.tid };
                crate::live::run_robust_exit(rl, owner_tid);
            }
            // SAFETY: exiting task on this CPU; sole writer per single-mutator.
            unsafe { task.replace_fd_table(None); task.replace_mm(None); reparent_children(task.tid); }
            crate::live::mark_done(task);
            // A non-leader thread is auto-released in the switch tail. The
            // group leader publishes the process exit and SIGCHLD once the
            // group-fatal signal reaches it.
            if task.tid == task.tgid.load(Ordering::Acquire) {
                signal_child_exit(task);
            }
        }
    }
    // SAFETY: exception ctx; preempt-off; Zombie state means no re-enqueue.
    unsafe { crate::live::schedule(); }
    loop { core::hint::spin_loop(); }
}
