//! Atomic-schedule diagnosis and count recovery.

use crate::preempt::{self, PREEMPT_DISABLED};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Recovery {
    Clean,
    DeferAtomic,
}

fn classify(count: u32, shared_stack: bool, in_interrupt: bool) -> Recovery {
    if count == PREEMPT_DISABLED && !shared_stack && !in_interrupt { Recovery::Clean }
    else { Recovery::DeferAtomic }
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

#[track_caller]
fn report(count: u32, shared_stack: bool) {
    klog::write_raw(b"[BUG] scheduling while atomic: preempt_count=");
    klog::write_hex_u64(count as u64);
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
/// rewriting CPU-local accounting under the interrupted caller.
/// # C: O(1)
#[track_caller]
pub(super) fn recover() -> bool {
    let count = preempt::preempt_count();
    let shared_stack = preempt::on_irq_stack();
    match classify(count, shared_stack, preempt::in_interrupt()) {
        Recovery::Clean => true,
        Recovery::DeferAtomic => {
            report(count, shared_stack);
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
    fn recovery_preserves_softirq_count_and_defers() {
        preempt::_test_reset();
        preempt::preempt_count_add(preempt::SOFTIRQ_DISABLE_OFFSET + PREEMPT_DISABLED);
        assert!(!recover());
        assert_eq!(preempt::preempt_count(), preempt::SOFTIRQ_DISABLE_OFFSET + PREEMPT_DISABLED);
        preempt::_test_reset();
    }
}
