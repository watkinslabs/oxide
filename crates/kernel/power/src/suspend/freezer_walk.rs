// The system-sleep freeze passes, per `32a§10`.
//
// The decision half — which tasks must freeze, the retry cadence, the timeout,
// what a pass does when it gives up — lives in `power::suspend::freezer` and is
// tested there. This file is the walk: it reads each task's facts, asks that
// decision, and parks the tasks it names using the same mechanism the cgroup
// freezer uses, distinguished by a reason bit so neither thaw resumes the
// other's tasks.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use sched::freeze_reason;
use sched::Task;

use crate::decide::{Error, KResult};
use super::freezer::{self, FreezeOutcome, FreezePhase, TaskFreezeFacts};

/// Read `task`'s freeze-relevant facts. # C: O(1)
pub fn facts_of(task: &Task) -> TaskFreezeFacts {
    TaskFreezeFacts {
        kernel_thread: task.kernel_thread.load(Ordering::Acquire),
        nofreeze: task.nofreeze.load(Ordering::Acquire),
        suspend_task: task.suspend_task.load(Ordering::Acquire),
        frozen: task.frozen.load(Ordering::Acquire),
        oom_victim: task.oom_victim.load(Ordering::Acquire),
    }
}

/// One round of a freeze pass: park every task the decision names, then
/// recount. The recount is what the loop tests, not the number parked — a task
/// the park could not take off its runqueue is still outstanding, and reporting
/// the attempt rather than the result would declare the pass done with tasks
/// still running.
/// # C: O(N_tasks)
fn round(phase: FreezePhase) -> u32 {
    for task in sched::registry::snapshot() {
        if !freezer::freezing(phase, facts_of(&task)) { continue; }
        // Retain the sleep reason even when another freezer already has the
        // task parked, so a concurrent cgroup thaw cannot resume it mid-sleep.
        sched::live::freeze_task_for(&task, freeze_reason::SLEEP);
    }
    sched::registry::snapshot().iter()
        .filter(|t| freezer::counts_outstanding(phase, facts_of(t)))
        .count() as u32
}

fn run_pass(phase: FreezePhase, now_ms: fn() -> u64) -> KResult<()> {
    freezer::set_phase(phase);
    let start = now_ms();
    let mut sleep_us = freezer::FREEZE_SLEEP_MIN_US;
    loop {
        let outstanding = round(phase);
        let elapsed = now_ms().saturating_sub(start);
        match freezer::round_decision(outstanding, elapsed, super::wakeup::pm_wakeup_pending()) {
            Some(FreezeOutcome::Done) => return Ok(()),
            Some(outcome) => {
                if freezer::thaws_on(outcome) { thaw_all(); }
                // The reference reports both a timeout and a wakeup abort as
                // EBUSY; the distinction is in the log, not the errno.
                return Err(Error::Busy);
            }
            None => { back_off(sleep_us); sleep_us = freezer::next_sleep_us(sleep_us); }
        }
    }
}

fn back_off(_us: u64) {
    // The low-level delay remains tracked separately, but a request-based
    // freezer must at least hand the CPU to its targets before recounting.
    sched::preempt::set_need_resched();
    let _ = sched::live::cond_resched();
}

/// Release every system-sleep claim. Tasks the cgroup freezer still holds stay
/// parked, which is what the reason bitmask is for.
/// # C: O(N_tasks)
fn thaw_all() {
    freezer::set_phase(FreezePhase::idle());
    for task in sched::registry::snapshot() {
        sched::live::unfreeze_task_for(&task, freeze_reason::SLEEP);
    }
}

fn boot_ms() -> u64 { timekeeper::monotonic_ns() / NS_PER_MS }

/// Nanoseconds in a millisecond, for the freeze budget's units.
const NS_PER_MS: u64 = 1_000_000;

/// Freeze userspace (`32a§5` step 1). Marks the calling task as the one
/// driving the suspend so it is never frozen itself.
/// # C: O(N_tasks · rounds)
/// # Sleeps: yes
pub fn freeze_processes() -> KResult<()> {
    if let Some(cur) = sched::live::current() { cur.suspend_task.store(true, Ordering::Release); }
    super::wakeup::pm_wakeup_clear(0);
    let r = run_pass(FreezePhase::user(), boot_ms);
    if r.is_err() { clear_suspend_task(); }
    r
}

/// Freeze freezable kernel threads (`32a§5` step 2). On failure the kernel
/// threads thaw and userspace stays frozen for the caller to thaw, which is
/// the contract `power::suspend::run` relies on.
/// # C: O(N_tasks · rounds)
/// # Sleeps: yes
pub fn freeze_kernel_threads() -> KResult<()> {
    match run_pass(FreezePhase::kernel(), boot_ms) {
        Ok(()) => Ok(()),
        Err(e) => { thaw_kernel_threads(); Err(e) }
    }
}

/// Thaw every task frozen for the sleep (`32a§5` undo of steps 1-2).
/// # C: O(N_tasks)
pub fn thaw_processes() {
    thaw_all();
    clear_suspend_task();
}

/// Thaw only the kernel threads, leaving userspace frozen.
/// # C: O(N_tasks)
pub fn thaw_kernel_threads() {
    freezer::set_phase(FreezePhase::user());
    for task in sched::registry::snapshot() {
        if !task.kernel_thread.load(Ordering::Acquire) { continue; }
        sched::live::unfreeze_task_for(&task, freeze_reason::SLEEP);
    }
}

fn clear_suspend_task() {
    if let Some(cur) = sched::live::current() { cur.suspend_task.store(false, Ordering::Release); }
}

/// Mark `task` as one that must keep running across a suspend, Linux
/// `PF_NOFREEZE`. Every kernel thread on the suspend path itself takes this.
/// # C: O(1)
pub fn set_nofreeze(task: &Arc<Task>, on: bool) { task.nofreeze.store(on, Ordering::Release); }

#[cfg(test)]
#[path = "freezer_walk/tests.rs"]
mod tests;
