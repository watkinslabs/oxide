// Global tid → Weak<Task> registry per `13§5` / `19§4`. Populated
// at task spawn; entries decay naturally via `Weak::upgrade` once
// the runqueue + zombies drop their last `Arc<Task>`.
//
// Used by procfs to enumerate `/proc/<pid>/` and synthesise
// per-pid `status`/`cmdline`/`stat`/`maps`. Lock order: leaf —
// callers hold no other sched locks.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use namespace_identity::{NamespaceKind, NamespaceRef};
use sync::{Spinlock, TaskList as TaskListClass};

use crate::{Task, TaskState};
use crate::wait_select::{self, Candidate, Waiter};

/// Arch IRQ gate for `REG`. Hosted builds have no interrupts to mask.
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub(crate) type RegIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub(crate) type RegIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
pub(crate) type RegIrq = sync::NoopIrq;

/// The task registry (Linux `tasklist_lock`).
///
/// Taken with IRQs masked at EVERY site, because a hard-IRQ handler reaches it:
/// the UART RX ISR delivers `^C` through `KernelFgSignal::raise` ->
/// `tasks_in_pgrp`, which walks this list. A process-context holder that could
/// be interrupted there would be spun on forever by its own CPU (`06§3.1`,
/// `skizm.md` 3.1 #6 / Step 4d). Linux takes the `tasklist_lock` read side with
/// `read_lock_irqsave` for exactly the paths IRQ context reads.
///
/// The walks here are O(N_tasks) with interrupts off, which is the cost Linux
/// pays too; the alternative — leaving one site plain — reinstates the deadlock.
static REG: Spinlock<Vec<(u32, Weak<Task>)>, TaskListClass> = Spinlock::new(Vec::new());

mod pidfd;
pub use pidfd::{
    acquire_pidfd_in_namespace, mark_reaped, pidfd_exit_ready, publish_pidfd_exit,
    PidfdAcquireError, PidfdKind,
};
/// Insert a new entry. Idempotent on `tid` (overwrites stale slot).
/// # C: O(N_tasks)
pub fn insert(task: &Arc<Task>) {
    task.configure_initial_pid_mapping();
    task.pid.attach(task);
    let tid = task.tid;
    let weak = Arc::downgrade(task);
    let mut g = REG.lock_irqsave::<RegIrq>();
    if let Some(slot) = g.iter_mut().find(|(t, _)| *t == tid) {
        slot.1 = weak;
    } else {
        g.push((tid, weak));
    }
}

/// Lookups performed, for the test that pins "no registry scan on the
/// hard-IRQ tick paths" (`06§3.1`). Counting is free in release: an untouched
/// relaxed atomic. Kept always-on so the invariant is testable without a
/// feature flag, which is how it regressed the first time.
pub static LOOKUPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Resolve `tid` → live `Arc<Task>` if still reachable.
///
/// Takes `REG` — a plain lock held by fork/exit/execve with IRQs enabled — and
/// scans O(N). **Never call this from hard-IRQ context** (`06§3.1`); the tick
/// would preempt a holder and wedge the CPU. The timer paths that used to do so
/// now reach process-wide state through `Task::thread_group` instead.
/// # C: O(N_tasks)
pub fn lookup(tid: u32) -> Option<Arc<Task>> {
    LOOKUPS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let g = REG.lock_irqsave::<RegIrq>();
    g.iter()
        .find(|(t, _)| *t == tid)
        .and_then(|(_, w)| w.upgrade())
}

/// Resolve `(ns, vpid)` → live `Arc<Task>`. F109: pid-NS-aware
/// lookup for kill/wait4/tgkill from a task in a non-init pid_ns —
/// caller's vpid arg is interpreted within their NS instead of as a
/// real tid. Init-NS callers (`ns == 0`) match by real tid (the
/// init-NS shortcut).
/// # C: O(N_tasks)
pub fn lookup_in_namespace(ns: &NamespaceRef, vpid: u32) -> Option<Arc<Task>> {
    use core::sync::atomic::Ordering;
    if ns.is_initial() {
        // Init NS: kernel-side callers pass an internal tid; userspace passes
        // the pid it actually sees — a vpid/vtid (getpid/gettid/fork return
        // those, NOT the opaque internal tid; NEXT_TID base is far above the
        // small vpid range so the two never collide). Match internal tid
        // FIRST (preserves every existing kernel caller verbatim), then fall
        // back to vtid/vtgid so userspace signal targeting resolves the Linux
        // way (by the visible pid): e.g. musl raise()→tkill(gettid()) and
        // kill(getpid()) must hit self. Previously only `lookup(vpid)`
        // (internal tid) ran, so raise/abort/pthread_kill silently ESRCH'd and
        // the signal was never posted (verified: the handler never ran).
        if let Some(t) = lookup(vpid) {
            return if t.reaped.load(Ordering::Acquire) { None } else { Some(t) };
        }
    }
    snapshot_tasks_for_pid_lookup().into_iter().find(|t| {
        !t.reaped.load(Ordering::Acquire)
            && t.pid.visible_tid(ns) == Some(vpid)
    })
}

fn snapshot_tasks_for_pid_lookup() -> Vec<Arc<Task>> {
    REG.lock_irqsave::<RegIrq>().iter().filter_map(|(_, weak)| weak.upgrade()).collect()
}

/// Best-effort snapshot of all live tasks for diagnostics (sysrq /
/// liveness-watchdog dump). Uses `try_lock` so a hung holder of `REG`
/// cannot deadlock the dump path itself — returns `None` if the lock
/// is contended (the dumper then reports "registry busy" rather than
/// wedging the whole machine while trying to diagnose a wedge).
/// # C: O(N_tasks)
/// # Lk: REG.try_lock (non-blocking)
pub fn try_snapshot() -> Option<Vec<Arc<Task>>> {
    let g = REG.try_lock()?;
    Some(g.iter().filter_map(|(_, w)| w.upgrade()).collect())
}

/// Snapshot live Task-owned kernel-stack charges.  This is the scheduler's
/// canonical global `KernelStack` input: each Task contributes only the exact
/// memcg charge retained with its owned stack, never a fixed stack-size guess.
/// # C: O(N_tasks)
pub fn kernel_stack_bytes_snapshot() -> u64 {
    REG.lock_irqsave::<RegIrq>().iter().filter_map(|(_, weak)| weak.upgrade())
        .map(|task| task.kernel_stack_bytes()).sum()
}

/// Snapshot live tids for procfs readdir. Skips entries whose
/// `Weak<Task>` has decayed; opportunistically prunes them.
/// # C: O(N_tasks)
pub fn live_tids() -> Vec<u32> {
    use core::sync::atomic::Ordering;
    let mut g = REG.lock_irqsave::<RegIrq>();
    g.retain(|(_, w)| w.strong_count() > 0);
    // Skip reaped-but-pinned tasks (Linux release_task): gone from the process
    // table, and never a valid reparent target / procfs entry.
    g.iter()
        .filter(|(_, w)| w.upgrade().map_or(false, |t| !t.reaped.load(Ordering::Acquire)))
        .map(|(t, _)| *t)
        .collect()
}

/// Return the next live, non-reaped internal tid strictly greater than
/// `after`.  This is the allocation-free iterator primitive for hard-IRQ
/// callers: each call holds the registry only while choosing one tid, so the
/// caller can resolve and wake that task after releasing `REG`.
/// # C: O(N_tasks)
/// # Lk: REG only
pub fn next_live_tid_after(after: u32) -> Option<u32> {
    use core::sync::atomic::Ordering;
    let mut g = REG.lock_irqsave::<RegIrq>();
    g.retain(|(_, w)| w.strong_count() > 0);
    g.iter()
        .filter(|(tid, w)| *tid > after
            && w.upgrade().is_some_and(|task| !task.reaped.load(Ordering::Acquire)))
        .map(|(tid, _)| *tid)
        .min()
}

/// `(total_live, runnable)` — used by `/proc/stat`'s `processes` and
/// `procs_running` lines. Blocked = total - runnable - stopped, which
/// callers can compute if they care; v1 procfs reports only running.
/// # C: O(N_tasks)
pub fn live_counts() -> (u64, u64) {
    use core::sync::atomic::Ordering;
    let mut g = REG.lock_irqsave::<RegIrq>();
    g.retain(|(_, w)| w.strong_count() > 0);
    let mut total = 0u64;
    let mut runnable = 0u64;
    for (_, w) in g.iter() {
        if let Some(t) = w.upgrade() {
            // Skip reaped-but-pidfd-pinned tasks (Linux release_task): they are
            // gone from the process table even though the Arc is still alive.
            if t.reaped.load(Ordering::Acquire) { continue; }
            total += 1;
            if matches!(t.state(), TaskState::Runnable) {
                runnable += 1;
            }
        }
    }
    (total, runnable)
}

/// Snapshot live process vtgids (Linux "PIDs") for procfs readdir.
/// Tasks without a vtgid (kernel threads pre-fork, smokes) are
/// skipped — they don't have a `/proc/N` directory in Linux either.
/// Sorted ascending for stable ordering.
/// # C: O(N_tasks log N_tasks)
pub fn live_vpids() -> Vec<u32> {
    use core::sync::atomic::Ordering;
    let mut g = REG.lock_irqsave::<RegIrq>();
    g.retain(|(_, w)| w.strong_count() > 0);
    let mut out: Vec<u32> = g
        .iter()
        .filter_map(|(_, w)| w.upgrade())
        // Skip reaped tasks (Linux release_task): a pidfd-pinned reaped child is
        // still strong-ref alive but must not appear in /proc (else ps/htop show
        // it as a lingering zombie).
        .filter(|t| !t.reaped.load(Ordering::Acquire))
        .map(|t| t.vtgid.load(Ordering::Acquire))
        .filter(|&v| v != 0)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Resolve a USERSPACE-supplied pid/tid (the value getpid/gettid/fork return)
/// to a Task, interpreted in the CALLER's pid namespace. THIS is the correct
/// primitive for any syscall whose pid arg comes from userspace (kill,
/// sched_*, getpgid/setpgid, …) — NOT `lookup`, which keys the opaque
/// internal tid and so silently fails on a userspace vpid (the
/// pid_identity minefield). `pid == 0` is the caller's responsibility (means
/// "self"/"caller's pgrp" depending on the syscall). # C: O(N_tasks)
pub fn resolve_user_pid(pid: u32) -> Option<Arc<Task>> {
    #[cfg(target_os = "oxide-kernel")]
    let ns = {
        crate::live::current()?.namespace_owner(NamespaceKind::Pid)?
    };
    #[cfg(not(target_os = "oxide-kernel"))]
    let ns = namespace_identity::initial(NamespaceKind::Pid);
    lookup_in_namespace(&ns, pid)
}

/// Resolve a userspace PID (vtgid) to a Task. Different from
/// `lookup` which keys on the kernel-internal TID. Used by procfs's
/// `/proc/<PID>` lookup so `cat /proc/1/status` sees init.
///
/// A process vpid is now shared by EVERY thread of the group (CLONE_THREAD
/// copies the leader's vtgid), so a bare `vtgid == vpid` match is ambiguous.
/// Resolve to the thread-group LEADER — the task whose `vtid == vtgid` — so
/// `/proc/<pid>/…` and `cgroup.procs` writes both land on the single task
/// that owns the process's cgroup membership (its internal tid == its tgid,
/// the key the cgroup tree stores under). Fall back to any group member if
/// the leader has already exited (a non-leader thread keeps the group alive).
/// # C: O(N_tasks)
pub fn lookup_by_vpid(vpid: u32) -> Option<Arc<Task>> {
    use core::sync::atomic::Ordering;
    let g = REG.lock_irqsave::<RegIrq>();
    let mut fallback: Option<Arc<Task>> = None;
    for (_, w) in g.iter() {
        let Some(t) = w.upgrade() else { continue };
        if t.reaped.load(Ordering::Acquire) || t.vtgid.load(Ordering::Acquire) != vpid {
            continue;
        }
        if t.vtid.load(Ordering::Acquire) == vpid {
            return Some(t); // thread-group leader
        }
        fallback.get_or_insert(t);
    }
    fallback
}

/// Namespace PID to display for the task with internal `tid`: its vtgid,
/// falling back to the internal tid for kernel threads / smokes that never
/// got a vpid stamped. procfs stat/status must show this (Linux "PID"),
/// not the opaque internal tid — PID1 is vtgid=1 but tid=0xC0DE….
/// # C: O(1) hash-free vec scan via `lookup`.
pub fn display_vpid(tid: u32) -> u64 {
    use core::sync::atomic::Ordering;
    match lookup(tid) {
        Some(t) => {
            if t.reaped.load(Ordering::Acquire) { return tid as u64; }
            let v = t.vtgid.load(Ordering::Acquire);
            if v != 0 {
                v as u64
            } else {
                tid as u64
            }
        }
        None => tid as u64,
    }
}

/// Namespace thread id to display for the task with internal `tid`:
/// its `vtid`, falling back to the internal tid for init-NS tasks.
/// `/proc/<pid>/task/<tid>` must expose thread ids, not process ids.
/// # C: O(1) hash-free vec scan via `lookup`.
pub fn display_vtid(tid: u32) -> u64 {
    use core::sync::atomic::Ordering;
    match lookup(tid) {
        Some(t) => {
            let v = t.vtid.load(Ordering::Acquire);
            if v != 0 {
                v as u64
            } else {
                tid as u64
            }
        }
        None => tid as u64,
    }
}

/// Parent's namespace PID for the task with internal `tid`: resolve its
/// internal parent_tid to that parent's vtgid. PID1's parent is the kernel
/// → 0 (Linux shows PPid 0 for init).
/// # C: O(N_tasks) — two registry lookups.
pub fn parent_vpid(tid: u32) -> u64 {
    use core::sync::atomic::Ordering;
    let ptid = match lookup(tid) {
        Some(t) => t.parent_tid.load(Ordering::Acquire),
        None => return 0,
    };
    lookup(ptid)
        .map(|p| p.vtgid.load(Ordering::Acquire))
        .filter(|&v| v != 0)
        .unwrap_or(0) as u64
}

/// Flip `task.state` Stopped → Runnable. Returns `true` if the
/// transition actually happened (caller is then responsible for
/// re-enqueueing into the runqueue); `false` if the task wasn't
/// Stopped to begin with. Used by SIGCONT delivery per signal(7):
/// the state-flip half is hosted-testable here, the re-enqueue
/// half lives in kernel-side `wake_if_stopped`.
/// # C: O(1)
pub fn try_wake_stopped(task: &Task) -> bool {
    if task.state() != TaskState::Stopped {
        return false;
    }
    task.cont_pending
        .store(true, core::sync::atomic::Ordering::Release);
    task.set_state(TaskState::Runnable);
    // Per `13§9` wakeup→resched: a newly-runnable task may outrank
    // current; flag a reschedule so the next preempt-enable or
    // syscall-return point picks it up. Cheaper than calling
    // schedule() directly here (registry holds no runqueue lock).
    #[cfg(target_os = "oxide-kernel")]
    crate::live::preempt::set_need_resched();
    true
}

#[derive(Copy, Clone)]
pub struct WaitChildSnapshot {
    pub vpid:     u32,
    pub uid:      u32,
    pub utime_ns: u64,
    pub stime_ns: u64,
}

impl WaitChildSnapshot {
    /// # C: O(1)
    pub fn from_task(t: &Task) -> Self {
        use core::sync::atomic::Ordering;
        Self {
            vpid:     t.vtgid.load(Ordering::Acquire),
            uid:      t.creds.ruid.load(Ordering::Acquire),
            utime_ns: t.utime_ns.load(Ordering::Acquire),
            stime_ns: t.stime_ns.load(Ordering::Acquire),
        }
    }
}

/// # C: O(N_tasks)
fn parent_tgid_locked(g: &[(u32, Weak<Task>)], parent_tid: u32) -> u32 {
    for (tid, w) in g.iter() {
        if *tid == parent_tid {
            if let Some(t) = w.upgrade() {
                return t.tgid.load(core::sync::atomic::Ordering::Acquire);
            }
        }
    }
    0
}

/// # C: O(N_tasks)
fn candidate_locked(g: &[(u32, Weak<Task>)], t: &Task) -> Candidate {
    use core::sync::atomic::Ordering;
    let parent_tid = t.parent_tid.load(Ordering::Acquire);
    Candidate {
        parent_tid,
        parent_tgid: parent_tgid_locked(g, parent_tid),
        vpid:        t.vtgid.load(Ordering::Acquire),
        pgid:        t.pgid.load(Ordering::Acquire),
        exit_signal: t.exit_signal.load(Ordering::Acquire),
    }
}

/// # C: O(N_tasks)
pub(crate) fn wait_candidate_matches(c: Candidate, waiter: Waiter, pid: i32, options: u64) -> bool {
    wait_select::eligible(c, waiter, pid, options)
}

/// wait4(WUNTRACED/WCONTINUED) helper: take first pending stop/cont.
/// `pid` follows wait4 semantics (-1/0/+pid/-pgid). Returns (tid, kind, sig)
/// where kind: 1 = stopped, 2 = continued. `parent_pgid` is the waiter's
/// process group (for the `pid==0` form).
/// # C: O(N_tasks)
/// # Lk: REG.lock
pub fn take_child_stop_event(
    parent: u32,
    parent_tgid: u32,
    pid: i32,
    parent_pgid: u32,
    options: u64,
    want_stop: bool,
    want_cont: bool,
) -> Option<(WaitChildSnapshot, u8, u32)> {
    use core::sync::atomic::Ordering;
    let g = REG.lock_irqsave::<RegIrq>();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    for (_, w) in g.iter() {
        let Some(t) = w.upgrade() else { continue };
        if !wait_candidate_matches(candidate_locked(&g, &t), waiter, pid, options) {
            continue;
        }
        if want_stop && t.stop_pending.swap(false, Ordering::AcqRel) {
            let sig = t.stop_signal.load(Ordering::Acquire);
            return Some((WaitChildSnapshot::from_task(&t), 1, sig as u32));
        }
        if want_cont && t.cont_pending.swap(false, Ordering::AcqRel) {
            return Some((WaitChildSnapshot::from_task(&t), 2, 0));
        }
    }
    None
}

/// waitid(WNOWAIT|WSTOPPED/WCONTINUED) helper: observe the first pending
/// stop/cont event without consuming it. Same scan/filter/order as
/// `take_child_stop_event`.
/// # C: O(N_tasks)
/// # Lk: REG.lock
pub fn peek_child_stop_event(
    parent: u32,
    parent_tgid: u32,
    pid: i32,
    parent_pgid: u32,
    options: u64,
    want_stop: bool,
    want_cont: bool,
) -> Option<(WaitChildSnapshot, u8, u32)> {
    use core::sync::atomic::Ordering;
    let g = REG.lock_irqsave::<RegIrq>();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    for (_, w) in g.iter() {
        let Some(t) = w.upgrade() else { continue };
        if !wait_candidate_matches(candidate_locked(&g, &t), waiter, pid, options) {
            continue;
        }
        if want_stop && t.stop_pending.load(Ordering::Acquire) {
            let sig = t.stop_signal.load(Ordering::Acquire);
            return Some((WaitChildSnapshot::from_task(&t), 1, sig as u32));
        }
        if want_cont && t.cont_pending.load(Ordering::Acquire) {
            return Some((WaitChildSnapshot::from_task(&t), 2, 0));
        }
    }
    None
}

/// Returns true if any live task has `parent_tid == parent`.
/// # C: O(N_tasks)
pub fn has_children(parent: u32) -> bool {
    use core::sync::atomic::Ordering;
    let g = REG.lock_irqsave::<RegIrq>();
    g.iter()
        .filter_map(|(_, w)| w.upgrade())
        .any(|t| t.parent_tid.load(Ordering::Acquire) == parent)
}

/// # C: O(N_tasks²)
pub fn has_wait_children(parent: u32, parent_tgid: u32, pid: i32, parent_pgid: u32, options: u64) -> bool {
    let g = REG.lock_irqsave::<RegIrq>();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    g.iter()
        .filter_map(|(_, w)| w.upgrade())
        .any(|t| {
            !t.reaped.load(core::sync::atomic::Ordering::Acquire)
                && wait_candidate_matches(candidate_locked(&g, &t), waiter, pid, options)
        })
}

/// Snapshot every live task whose pgid matches. Used by tty
/// line discipline + `kill(-pgid)` to fan signals to a process
/// group per `28§4`.
/// # C: O(N_tasks)
pub fn tasks_in_pgrp(pgid: u32) -> Vec<Arc<Task>> {
    use core::sync::atomic::Ordering;
    let g = REG.lock_irqsave::<RegIrq>();
    g.iter()
        .filter_map(|(_, w)| w.upgrade())
        .filter(|t| !t.reaped.load(Ordering::Acquire) && t.pgid.load(Ordering::Acquire) == pgid)
        .collect()
}

/// Snapshot live threads in the real thread-group `tgid`. Returns
/// `(visible_tid, real_tid)` pairs sorted by visible tid so
/// `/proc/<pid>/task` enumeration is stable and Linux-like.
/// # C: O(N_tasks log N_tasks)
pub fn thread_entries(tgid: u32) -> Vec<(u32, u32)> {
    use core::sync::atomic::Ordering;
    let g = REG.lock_irqsave::<RegIrq>();
    let mut out: Vec<(u32, u32)> = g
        .iter()
        .filter_map(|(_, w)| w.upgrade())
        .filter(|t| t.tgid.load(Ordering::Acquire) == tgid)
        .map(|t| {
            let vtid = t.vtid.load(Ordering::Acquire);
            (if vtid != 0 { vtid } else { t.tid }, t.tid)
        })
        .collect();
    out.sort_unstable_by_key(|(vtid, _)| *vtid);
    out.dedup_by_key(|(vtid, _)| *vtid);
    out
}

/// Test-only: drop every registered entry. Hosted tests share the
/// process-global slot, so this resets the table between cases.
/// # C: O(N_tasks)
#[cfg(any(test, feature = "hosted"))]
pub fn clear_for_tests() {
    REG.lock_irqsave::<RegIrq>().clear();
}
