// tid-keyed core operations: insert, point lookup, stop/cont wake flip, and
// the test-only full reset. `lookup` is the hottest path in the registry —
// `display_vpid`/`display_vtid`/`parent_vpid` (`vpid.rs`) and the init-NS
// fast path of `lookup_in_namespace` all route through it.

use alloc::sync::Arc;

use super::core::{hint_upsert, RegIrq, REG};
use crate::{Task, TaskState};

/// Lookups performed, for the test that pins "no registry scan on the
/// hard-IRQ tick paths" (`06§3.1`). Counting is free in release: an untouched
/// relaxed atomic. Kept always-on so the invariant is testable without a
/// feature flag, which is how it regressed the first time.
pub static LOOKUPS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Insert a new entry. Idempotent on `tid` (overwrites stale slot).
/// # C: O(log N_tasks)
pub fn insert(task: &Arc<Task>) {
    task.configure_initial_pid_mapping();
    task.pid.attach(task);
    let tid = task.tid;
    let weak = Arc::downgrade(task);
    let mut g = REG.lock_irqsave::<RegIrq>();
    g.by_tid.insert(tid, weak.clone());
    hint_upsert(&mut g.vpid_hint, task, weak);
}

/// Resolve `tid` → live `Arc<Task>` if still reachable.
///
/// Takes `REG` — a plain lock held by fork/exit/execve with IRQs enabled and
/// masked at every site (`core.rs`) — and does an O(log N) `BTreeMap` point
/// lookup. **Never call this from hard-IRQ context** (`06§3.1`); the tick
/// would preempt a holder and wedge the CPU. The timer paths that used to do
/// so now reach process-wide state through `Task::thread_group` instead.
/// # C: O(log N_tasks)
pub fn lookup(tid: u32) -> Option<Arc<Task>> {
    LOOKUPS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    let mut g = REG.lock_irqsave::<RegIrq>();
    let hit = g.by_tid.get(&tid).and_then(|w| w.upgrade());
    if hit.is_none() && g.by_tid.contains_key(&tid) {
        g.by_tid.remove(&tid); // deterministic prune: confirmed-dead Weak
    }
    hit
}

/// Flip `task.state` Stopped → Runnable. Returns `true` if the
/// transition actually happened (caller is then responsible for
/// re-enqueueing into the runqueue); `false` if the task wasn't
/// Stopped to begin with. Used by SIGCONT delivery per signal(7):
/// the state-flip half is hosted-testable here, the re-enqueue
/// half lives in kernel-side `wake_if_stopped`.
///
/// `wake` is why the task is being resumed, and it decides whether this is a
/// `wait4(WCONTINUED)` event at all. Only a real SIGCONT is: a `PTRACE_CONT`
/// that happens to un-stop a tracee is not a continue, and neither is a
/// kill-wake that only resumes the task so it can run its own death. It is
/// also published into the latch's wake field because the resuming task itself
/// must know, on the way out of its stop, whether it owes its parent a
/// `CLD_CONTINUED` — `cont_pending` cannot serve, since a `wait4` may consume
/// it first.
/// # C: O(1)
pub fn try_wake_stopped(task: &Task, wake: crate::jobctl::WakeKind) -> bool {
    if task.state() != TaskState::Stopped {
        return false;
    }
    let jc = task.jobctl.load(core::sync::atomic::Ordering::Acquire);
    task.jobctl.store(crate::jobctl::with_wake(jc, wake), core::sync::atomic::Ordering::Release);
    if crate::jobctl::records_continued(wake) {
        task.cont_pending
            .store(true, core::sync::atomic::Ordering::Release);
    }
    task.set_state(TaskState::Runnable);
    // Per `13§9` wakeup→resched: a newly-runnable task may outrank
    // current; flag a reschedule so the next preempt-enable or
    // syscall-return point picks it up. Cheaper than calling
    // schedule() directly here (registry holds no runqueue lock).
    #[cfg(target_os = "oxide-kernel")]
    crate::live::preempt::set_need_resched();
    true
}

/// Test-only: drop every registered entry. Hosted tests share the
/// process-global slot, so this resets the table between cases.
/// # C: O(N_tasks)
#[cfg(any(test, feature = "hosted"))]
pub fn clear_for_tests() {
    super::core::clear_locked(&mut REG.lock_irqsave::<RegIrq>());
}
