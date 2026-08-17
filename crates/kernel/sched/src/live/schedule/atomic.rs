//! Atomic-schedule diagnosis and count recovery.

use crate::preempt::{self, PREEMPT_DISABLED};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Recovery {
    Clean,
    /// The count is BELOW the level `schedule()` just established, so the
    /// entry `preempt_disable` was paid into a count that had already gone
    /// negative. Nothing is held and nothing is atomic: the context is
    /// switchable and the count is simply wrong. Restore the level and
    /// schedule, which is what the reference does for every count mismatch.
    Repair,
    DeferAtomic,
}

/// A count below the scheduler's own entry level cannot be deferred.
///
/// `DeferAtomic` preserves the count and hands the request to whoever will
/// drop it — an IRQ tail, a bottom half, a lock release. An UNDER-count has no
/// such owner: the missing decrement already happened, so every later attempt
/// re-reads the same wrong value, refuses again, and the caller's wait loop
/// re-drives it. That is a livelock with no exit, and it is what a run of
/// identical `preempt_count=0` reports from one task at one stack pointer is.
/// The reference has no deferral at all here: it reports and stamps the count
/// back to the schedule-entry level, so the accounting is self-healing.
/// # C: O(1)
fn classify(count: u32, shared_stack: bool, in_interrupt: bool) -> Recovery {
    if shared_stack || in_interrupt { return Recovery::DeferAtomic; }
    if count == PREEMPT_DISABLED { return Recovery::Clean; }
    if count < PREEMPT_DISABLED { return Recovery::Repair; }
    Recovery::DeferAtomic
}

fn defer_schedule(task: Option<&crate::Task>) {
    match task {
        Some(task) => preempt::resched::set_tsk_need_resched(task),
        None => preempt::set_need_resched(),
    }
}

#[cfg(feature = "debug-preempt")]
fn current_sp() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: reads the architectural SP into a GPR without touching memory or flags.
        unsafe { core::arch::asm!("mov {v}, sp", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
        v
    }
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let v: u64;
        // SAFETY: reads RSP into a GPR without touching memory or flags.
        unsafe { core::arch::asm!("mov {v}, rsp", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
        v
    }
    #[cfg(not(all(any(target_arch = "aarch64", target_arch = "x86_64"), target_os = "oxide-kernel")))]
    { 0 }
}

/// The two shapes a count mismatch takes, so the line names which one it is.
/// A report whose every atomicity field reads zero is an UNDER-count, and
/// reading it as an atomic-context violation sends the diagnosis the wrong way.
fn reason(verdict: Recovery) -> &'static [u8] {
    match verdict {
        Recovery::Repair => b" reason=count-under-entry-level",
        _ => b" reason=atomic-context",
    }
}

#[track_caller]
fn report(count: u32, shared_stack: bool, verdict: Recovery) {
    klog::write_raw(b"[BUG] scheduling while atomic: preempt_count=");
    klog::write_hex_u64(count as u64);
    klog::write_raw(b" expected=");
    klog::write_hex_u64(PREEMPT_DISABLED as u64);
    klog::write_raw(reason(verdict));
    klog::write_raw(if preempt::in_interrupt() { b" in_interrupt=1" } else { b" in_interrupt=0" });
    #[cfg(feature = "debug-preempt")]
    {
        klog::write_raw(if shared_stack { b" irq_stack=1" } else { b" irq_stack=0" });
        klog::write_raw(b" sp=0x");
        klog::write_hex_u64(current_sp());
        // The innermost lock class the CPU still holds. The schedule site is
        // the victim — this names the lock the outgoing task is about to carry
        // off-CPU, which is the cause.
        klog::write_raw(b" held_lock_rank=");
        klog::write_dec_u64(sync::preempt_gate::held_rank() as u64);
        // ...and every frame under it, with the line each was taken on. A rank
        // names a class; the sleep is caused by a specific acquisition.
        sync::preempt_gate::write_held_stack();
        if let Some(task) = crate::live::current() {
            klog::write_raw(b" current_tid=");
            klog::write_dec_u64(task.tid as u64);
        }
        let caller = core::panic::Location::caller();
        klog::write_raw(b" caller=");
        klog::write_raw(caller.file().as_bytes());
        klog::write_raw(b":");
        klog::write_dec_u64(caller.line() as u64);
    }
    #[cfg(not(feature = "debug-preempt"))]
    { let _ = shared_stack; }
    klog::write_raw(b"\n");
}

/// Validate the scheduler-owned preempt-disable level.  An interrupt, bottom
/// half, lock, or shared-IRQ-stack count is not switchable state.  Preserve it
/// and defer the request to the owner that will drop that count, rather than
/// rewriting CPU-local accounting under the interrupted caller.  A count BELOW
/// the entry level has no such owner and is repaired here instead — see
/// [`classify`].
/// # C: O(1)
#[track_caller]
pub(super) fn recover() -> bool {
    let count = preempt::preempt_count();
    let shared_stack = preempt::on_irq_stack();
    let verdict = classify(count, shared_stack, preempt::in_interrupt());
    match verdict {
        Recovery::Clean => true,
        Recovery::Repair => {
            report(count, shared_stack, verdict);
            preempt::preempt_count_set(PREEMPT_DISABLED);
            true
        }
        Recovery::DeferAtomic => {
            report(count, shared_stack, verdict);
            defer_schedule(crate::live::current());
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_schedule_disable_is_clean() {
        assert_eq!(classify(PREEMPT_DISABLED, false, false), Recovery::Clean);
    }

    #[test]
    fn bottom_half_disabled_count_is_deferred() {
        assert_eq!(classify(preempt::SOFTIRQ_DISABLE_OFFSET + PREEMPT_DISABLED, false, true),
                   Recovery::DeferAtomic);
    }

    #[test]
    fn shared_irq_stack_schedule_is_deferred() {
        assert_eq!(classify(preempt::SOFTIRQ_OFFSET + PREEMPT_DISABLED, true, true),
                   Recovery::DeferAtomic);
        let task = crate::Task::new(1857, "atomic-defer",
            crate::SchedClass::Normal { weight: 1024 });
        task.set_state(crate::TaskState::Sleeping);
        defer_schedule(Some(&task));
        assert_eq!(task.state(), crate::TaskState::Sleeping,
            "defer must preserve the caller's intended sleep state");
        assert!(preempt::resched::test_tsk_need_resched(&task));
        assert!(preempt::resched::clear_tsk_need_resched(&task));
    }

    #[test]
    fn count_below_entry_level_is_repaired_not_deferred() {
        // The observed shape: the entry `preempt_disable` landed on a count
        // that had already gone one below zero, so `schedule()` reads zero
        // with nothing held, nothing on the IRQ stack and no interrupt.
        assert_eq!(classify(0, false, false), Recovery::Repair);
    }

    #[test]
    fn repair_restores_the_entry_level_and_lets_the_switch_run() {
        preempt::_test_reset();
        // No `preempt_disable` credit at all: the schedule-entry increment was
        // consumed by a prior missing decrement.
        assert!(recover(), "an under-count is switchable and must schedule");
        assert_eq!(preempt::preempt_count(), PREEMPT_DISABLED,
            "repair must leave exactly the level schedule() runs its body at");
        preempt::_test_reset();
    }

    // The property the 624-report boot violated: driving the real entry
    // sequence from an under-counted CPU must reach a schedule, not repeat one
    // refusal forever. Each round is what `schedule_once` does — the entry
    // increment, the check, and the give-back on refusal — so a verdict that
    // cannot heal the count shows up here as a loop that never returns true.
    #[test]
    fn undercounted_cpu_reaches_a_schedule_instead_of_looping_forever() {
        preempt::_test_reset();
        // One decrement more than was ever taken: the live wedge's state.
        preempt::preempt_count_set(0u32.wrapping_sub(1));
        let mut rounds = 0;
        let scheduled = loop {
            rounds += 1;
            preempt::preempt_disable();
            if recover() { break true; }
            // `schedule_once`'s give-back on refusal. Spelled as a set because
            // the paired helper's debug-only underflow assertion is compiled
            // out of the kernel build this state was observed in, and the
            // question here is the verdict, not the assertion.
            preempt::preempt_count_set(preempt::preempt_count().wrapping_sub(1));
            if rounds == 32 { break false; }
        };
        assert!(scheduled, "refusal never healed the count: {rounds} rounds, still refusing");
        assert_eq!(preempt::preempt_count(), PREEMPT_DISABLED);
        preempt::_test_reset();
    }

    #[test]
    fn recovery_preserves_softirq_count_and_defers() {
        preempt::_test_reset();
        preempt::preempt_count_add(preempt::SOFTIRQ_DISABLE_OFFSET + PREEMPT_DISABLED);
        assert!(!recover());
        assert_eq!(preempt::preempt_count(), preempt::SOFTIRQ_DISABLE_OFFSET + PREEMPT_DISABLED);
        preempt::_test_reset();
    }
}
