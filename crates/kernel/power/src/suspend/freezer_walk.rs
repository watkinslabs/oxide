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
        reaped: task.reaped.load(Ordering::Acquire),
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
fn round(phase: FreezePhase, number: u64) -> u32 {
    trace_round_begin(number);
    let mut traced = 0u32;
    for task in sched::registry::snapshot() {
        if !request_needed(phase, facts_of(&task)) { continue; }
        trace_task(number, traced, &task, false);
        // Retain the sleep reason even when another freezer already has the
        // task parked, so a concurrent cgroup thaw cannot resume it mid-sleep.
        sched::live::freeze_task_for(&task, freeze_reason::SLEEP);
        trace_task(number, traced, &task, true);
        traced = traced.saturating_add(1);
    }
    let outstanding = sched::registry::snapshot().iter()
        .filter(|t| freezer::counts_outstanding(phase, facts_of(t)))
        .count() as u32;
    #[cfg(feature = "debug-hibernate")]
    if number == FREEZER_LATE_DETAIL_ROUND {
        let mut detailed = 0u32;
        for task in sched::registry::snapshot() {
            if !freezer::counts_outstanding(phase, facts_of(&task)) { continue; }
            trace_outstanding(&task, detailed);
            detailed = detailed.saturating_add(1);
        }
    }
    trace_round_end(number, outstanding);
    outstanding
}

fn request_needed(phase: FreezePhase, facts: TaskFreezeFacts) -> bool {
    freezer::counts_outstanding(phase, facts)
}

fn run_pass(phase: FreezePhase, now_ms: fn() -> u64) -> KResult<()> {
    freezer::set_phase(phase);
    let start = now_ms();
    let mut sleep_us = freezer::FREEZE_SLEEP_MIN_US;
    let mut number = 1u64;
    loop {
        let outstanding = round(phase, number);
        let elapsed = now_ms().saturating_sub(start);
        trace_decision(number, outstanding, elapsed);
        match freezer::round_decision(outstanding, elapsed, super::wakeup::pm_wakeup_pending()) {
            Some(FreezeOutcome::Done) => return Ok(()),
            Some(outcome) => {
                if freezer::thaws_on(outcome) { thaw_all(); }
                // The reference reports both a timeout and a wakeup abort as
                // EBUSY; the distinction is in the log, not the errno.
                return Err(Error::Busy);
            }
            None => {
                trace_backoff(number, sleep_us, false);
                back_off(sleep_us);
                trace_backoff(number, sleep_us, true);
                sleep_us = freezer::next_sleep_us(sleep_us);
                number = number.saturating_add(1);
            }
        }
    }
}

#[cfg(feature = "debug-hibernate")]
fn traced_round(number: u64) -> bool { number == 1 || number % FREEZER_TRACE_ROUNDS == 0 }

#[cfg(feature = "debug-hibernate")]
const FREEZER_TRACE_ROUNDS: u64 = 128;

#[cfg(feature = "debug-hibernate")]
const FREEZER_TRACE_TASKS: u32 = 64;

#[cfg(feature = "debug-hibernate")]
const FREEZER_LATE_DETAIL_ROUND: u64 = 128;

#[cfg(feature = "debug-hibernate")]
fn trace_round_begin(number: u64) {
    if !traced_round(number) { return; }
    klog::write_raw(b"[hibernate] freezer round="); klog::write_dec_u64(number);
    klog::write_raw(b" begin\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
fn trace_round_begin(_: u64) {}

#[cfg(feature = "debug-hibernate")]
fn trace_task(number: u64, ordinal: u32, task: &Task, after: bool) {
    if number != 1 || ordinal >= FREEZER_TRACE_TASKS { return; }
    let facts = facts_of(task);
    klog::write_raw(b"[hibernate] freezer task="); klog::write_dec_u64(task.tid as u64);
    klog::write_raw(if after { b" after" } else { b" before" });
    klog::write_raw(b" state="); klog::write_raw(&[task.state().linux_char()]);
    klog::write_raw(b" reaped="); klog::write_dec_u64(facts.reaped as u64);
    klog::write_raw(b" kernel="); klog::write_dec_u64(facts.kernel_thread as u64);
    klog::write_raw(b" nofreeze="); klog::write_dec_u64(facts.nofreeze as u64);
    klog::write_raw(b" suspend="); klog::write_dec_u64(facts.suspend_task as u64);
    klog::write_raw(b" frozen="); klog::write_dec_u64(facts.frozen as u64);
    klog::write_raw(b" reasons=");
    klog::write_dec_u64(task.freeze_reasons.load(Ordering::Acquire) as u64);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
fn trace_task(_: u64, _: u32, _: &Task, _: bool) {}

#[cfg(feature = "debug-hibernate")]
fn trace_outstanding(task: &Task, ordinal: u32) {
    if ordinal >= FREEZER_TRACE_TASKS { return; }
    let facts = facts_of(task);
    let comm = task.comm_bytes();
    klog::write_raw(b"[hibernate] freezer outstanding tid=");
    klog::write_dec_u64(task.tid as u64);
    klog::write_raw(b" comm="); klog::write_raw(Task::comm_trim(&comm).as_bytes());
    klog::write_raw(b" state="); klog::write_raw(&[task.state().linux_char()]);
    klog::write_raw(b" reaped="); klog::write_dec_u64(facts.reaped as u64);
    klog::write_raw(b" exiting=");
    klog::write_dec_u64(task.exiting.load(Ordering::Acquire) as u64);
    klog::write_raw(b" frozen="); klog::write_dec_u64(facts.frozen as u64);
    klog::write_raw(b" reasons=");
    klog::write_dec_u64(task.freeze_reasons.load(Ordering::Acquire) as u64);
    klog::write_raw(b" cpu="); klog::write_dec_u64(task.cpu.load(Ordering::Acquire) as u64);
    klog::write_raw(b" on_cpu=");
    klog::write_dec_u64(task.on_cpu.load(Ordering::Acquire) as u64);
    klog::write_raw(b" on_rq=");
    klog::write_dec_u64(task.on_rq.load(Ordering::Acquire) as u64);
    klog::write_raw(b" on_wake=");
    klog::write_dec_u64(task.on_wake_list.load(Ordering::Acquire) as u64);
    klog::write_raw(b" last_syscall=");
    klog::write_dec_u64(task.last_syscall_nr.load(Ordering::Acquire) as u64);
    klog::write_raw(b" nsyscalls=");
    klog::write_dec_u64(task.nsyscalls.load(Ordering::Acquire));
    klog::write_raw(b"\n");
}

#[cfg(feature = "debug-hibernate")]
fn trace_round_end(number: u64, outstanding: u32) {
    if !traced_round(number) { return; }
    klog::write_raw(b"[hibernate] freezer round="); klog::write_dec_u64(number);
    klog::write_raw(b" end outstanding="); klog::write_dec_u64(outstanding as u64);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
fn trace_round_end(_: u64, _: u32) {}

#[cfg(feature = "debug-hibernate")]
fn trace_decision(number: u64, outstanding: u32, elapsed_ms: u64) {
    if !traced_round(number) { return; }
    klog::write_raw(b"[hibernate] freezer round="); klog::write_dec_u64(number);
    klog::write_raw(b" outstanding="); klog::write_dec_u64(outstanding as u64);
    klog::write_raw(b" elapsed_ms="); klog::write_dec_u64(elapsed_ms);
    klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
fn trace_decision(_: u64, _: u32, _: u64) {}

#[cfg(feature = "debug-hibernate")]
fn trace_backoff(number: u64, sleep_us: u64, after: bool) {
    if !traced_round(number) { return; }
    klog::write_raw(b"[hibernate] freezer round="); klog::write_dec_u64(number);
    klog::write_raw(if after { b" backoff_end_us=" } else { b" backoff_begin_us=" });
    klog::write_dec_u64(sleep_us); klog::write_raw(b"\n");
}

#[cfg(not(feature = "debug-hibernate"))]
#[inline(always)]
fn trace_backoff(_: u64, _: u64, _: bool) {}

fn back_off(us: u64) {
    let (earliest, slack) = backoff_window(timekeeper::monotonic_ns(), us);
    // SAFETY: the suspend owner runs in process context, holds no scheduler or
    // timer lock here, and the local timed wait owns its complete lifetime.
    unsafe {
        sched::live::sleep_uninterruptible_range_until(
            earliest, slack, timekeeper::monotonic_ns,
        );
    }
}

/// Linux `usleep_range(us / 2, us)` as an absolute earliest deadline plus its
/// coalescing slack. # C: O(1)
fn backoff_window(now_ns: u64, us: u64) -> (u64, u64) {
    let earliest_delta = (us / 2).saturating_mul(1_000);
    let latest_delta = us.saturating_mul(1_000);
    (now_ns.saturating_add(earliest_delta), latest_delta.saturating_sub(earliest_delta))
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
