// Linux `TIF_NEED_RESCHED` — the per-TASK reschedule request.
//
// Linux keeps this in `thread_info::flags`, i.e. on the task, NEVER per-CPU:
//
//   * `__resched_curr` stamps `rq->curr`'s
//     thread_info — the task that is actually running on the target CPU.
//   * `__schedule` clears it on the OUTGOING task
//     (`clear_tsk_need_resched(prev)`), so the
//     incoming task starts its slice with its own, already-clear flag.
//   * `exit_to_user_mode_loop` re-reads
//     `read_thread_flags()` — the task word — after each pass.
//
// Holding it per-CPU instead breaks the third point: a tick that lands while
// task A is descheduled sets "this CPU wants a reschedule", and when A is
// picked again it inherits a request that was never its own. The
// return-to-user work loop then services it, `schedule()`s away immediately
// after being handed the CPU, comes back to another intervening tick's flag,
// and repeats — a resched ping-pong that terminates only at the loop's pass
// bound (`[BUG] exit_to_user_mode_loop: work never cleared`, B1476).
//
// x86 Linux additionally FOLDS the bit into its per-CPU `__preempt_count`
// (`set_preempt_need_resched` / `clear_preempt_need_resched`) as a pure cache;
// this port does not, so there is exactly one storage location per task and no
// cache to keep coherent.

use core::sync::atomic::{AtomicBool, Ordering};

use cpu::MAX_CPUS;

use crate::Task;

/// Cacheline-padded per-CPU anchor. Used ONLY while this CPU has no current
/// task — boot before `install_default_runqueue`, and hosted unit builds that
/// exercise the preempt API without a runqueue. Linux always has `current`, so
/// this slot has no upstream counterpart and no reader once a task is running.
#[repr(C, align(64))]
struct Pcpu<T>(T);

const ANCHOR_ZERO: Pcpu<AtomicBool> = Pcpu(AtomicBool::new(false));
static ANCHOR: [Pcpu<AtomicBool>; MAX_CPUS] = [ANCHOR_ZERO; MAX_CPUS];

#[cfg(all(not(target_os = "oxide-kernel"), any(test, feature = "hosted")))]
std::thread_local! {
    static HOSTED_ANCHOR: AtomicBool = const { AtomicBool::new(false) };
}

/// The ONE decision of "whose `TIF_NEED_RESCHED` is this": the running task's
/// when a task is running, else this CPU's pre-task anchor. Every set / read /
/// take goes through here, so the two storages can never be consulted
/// inconsistently.
/// # C: O(1)
#[inline]
fn slot<R>(f: impl FnOnce(&AtomicBool) -> R) -> R {
    match current_task() {
        Some(t) => f(&t.need_resched),
        None    => hosted_anchor(f),
    }
}

#[cfg(all(not(target_os = "oxide-kernel"), any(test, feature = "hosted")))]
fn hosted_anchor<R>(f: impl FnOnce(&AtomicBool) -> R) -> R { HOSTED_ANCHOR.with(f) }

#[cfg(not(all(not(target_os = "oxide-kernel"), any(test, feature = "hosted"))))]
fn hosted_anchor<R>(f: impl FnOnce(&AtomicBool) -> R) -> R { f(&ANCHOR[super::this_cpu()].0) }

// ---- Linux's per-task accessors ----

/// Linux `set_tsk_need_resched(tsk)`. Idempotent.
/// # C: O(1)
pub fn set_tsk_need_resched(t: &Task) { t.need_resched.store(true, Ordering::Release); }

/// Linux `clear_tsk_need_resched(tsk)`, returning the prior value so the
/// `preempt_enable` consumer can act on it in the same atomic step.
/// # C: O(1)
pub fn clear_tsk_need_resched(t: &Task) -> bool { t.need_resched.swap(false, Ordering::AcqRel) }

/// Linux `test_tsk_need_resched(tsk)`.
/// # C: O(1)
pub fn test_tsk_need_resched(t: &Task) -> bool { t.need_resched.load(Ordering::Acquire) }

/// Linux `test_tsk_need_resched(current)`.
/// # C: O(1)
pub fn need_resched() -> bool { slot(|s| s.load(Ordering::Acquire)) }

/// Linux `set_tsk_need_resched(rq->curr)` for the LOCAL rq — the tick,
/// `preempt_enable`-side wakeups and every `resched_curr(this_cpu)` caller.
/// Idempotent.
/// # C: O(1)
pub fn set_need_resched() { slot(|s| s.store(true, Ordering::Release)); }

/// Linux `clear_tsk_need_resched(prev)` + the `preempt_enable` consumer:
/// atomically take and clear, returning the prior value.
/// # C: O(1)
pub fn take_need_resched() -> bool { slot(|s| s.swap(false, Ordering::AcqRel)) }

/// Linux `__resched_curr(rq, TIF_NEED_RESCHED)` for a REMOTE rq: the flag
/// belongs to whatever task that CPU is running, so a request aimed at CPU `n`
/// must land on `rq(n)->curr` — not on a per-CPU word the next task to run
/// there would pick up. The caller pairs this with the reschedule IPI
/// (`live::resched_curr`). An out-of-range or not-yet-installed CPU falls back
/// to that CPU's anchor, which is where its pre-task state lives.
/// # C: O(1)
pub fn set_need_resched_on(cpu: usize) { set_need_resched_on_with(curr_of, cpu) }

/// `set_need_resched_on` with the `rq(cpu)->curr` lookup supplied — the same
/// seam `live::rq_locate` uses, so the ROUTING (which task a request aimed at a
/// CPU lands on) is host-testable against locally built runqueues instead of
/// the process-global `GLOBALS` array.
/// # C: O(1)
pub fn set_need_resched_on_with<'a>(curr_of: impl Fn(usize) -> Option<&'a Task>, cpu: usize) {
    if let Some(t) = curr_of(cpu) { set_tsk_need_resched(t); return; }
    if let Some(a) = ANCHOR.get(cpu) { a.0.store(true, Ordering::Release); }
}

/// Linux `test_tsk_need_resched(rq(cpu)->curr)` — the remote read the sysrq
/// per-CPU dump pairs with `preempt_count_on`. A wedged CPU has stopped
/// stamping heartbeats but its `rq->curr` is still readable.
/// # C: O(1)
pub fn need_resched_on(cpu: usize) -> bool { need_resched_on_with(curr_of, cpu) }

/// `need_resched_on` with the lookup supplied; pairs with
/// `set_need_resched_on_with`.
/// # C: O(1)
pub fn need_resched_on_with<'a>(curr_of: impl Fn(usize) -> Option<&'a Task>, cpu: usize) -> bool {
    if let Some(t) = curr_of(cpu) { return test_tsk_need_resched(t); }
    ANCHOR.get(cpu).is_some_and(|a| a.0.load(Ordering::Acquire))
}

// ---- runqueue lookups (the `live` module is compiled only for the kernel
// target and hosted/test builds; a bare host build has no runqueue, so every
// task lookup yields `None` and the anchors carry the state) ----

/// `rq(this_cpu)->curr` — Linux `current`.
/// # C: O(1)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn current_task() -> Option<&'static Task> { crate::live::current() }
/// # C: O(1)
#[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
fn current_task() -> Option<&'static Task> { None }

/// `rq(cpu)->curr`. `None` when `cpu` is out of range or its runqueue is not
/// installed yet.
/// # C: O(1)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn curr_of(cpu: usize) -> Option<&'static Task> {
    if cpu >= MAX_CPUS { return None; }
    // SAFETY: `global_for` is sound for any index and yields `None` for a CPU
    // that has not completed `install_global`; the borrow is a lock-free read
    // of a slot whose `Arc` the runqueue owns.
    let rq = unsafe { crate::live::runqueue::global_for(cpu as u32) }?;
    // SAFETY: same contract as `live::current` — the runqueue holds the strong
    // reference, and this read is short-lived.
    Some(unsafe { rq.current_ref() })
}
/// # C: O(1)
#[cfg(not(any(target_os = "oxide-kernel", test, feature = "hosted")))]
fn curr_of(_cpu: usize) -> Option<&'static Task> { None }

/// Reset one caller-owned anchor. Hosted-test hook only
/// (`preempt::_test_reset`).
/// # C: O(1)
#[cfg(any(test, feature = "hosted"))]
pub(super) fn _test_reset_anchor(cpu: usize) {
    #[cfg(all(not(target_os = "oxide-kernel"), any(test, feature = "hosted")))]
    {
        HOSTED_ANCHOR.with(|anchor| anchor.store(false, Ordering::Release));
        if let Some(anchor) = ANCHOR.get(cpu) { anchor.0.store(false, Ordering::Release); }
    }
    #[cfg(not(all(not(target_os = "oxide-kernel"), any(test, feature = "hosted"))))]
    {
        if let Some(anchor) = ANCHOR.get(cpu) { anchor.0.store(false, Ordering::Release); }
    }
}

#[cfg(test)]
#[path = "resched/tests.rs"] mod tests;
