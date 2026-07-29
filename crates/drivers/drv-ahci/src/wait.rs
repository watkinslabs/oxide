//! Process-context AHCI waits with IRQ-enabled polling and lost-wakeup safety.

#![cfg(target_os = "oxide-kernel")]

use sched::live::wait_list::WaitList;

pub(crate) const IO_TIMEOUT_NS: u64 = 5_000_000_000;
pub(crate) const IO_SPIN_BUDGET: u64 = 200_000;

/// Monotonic wait clock. # C: O(1)
pub(crate) fn now_ns() -> u64 { crate::port::now_ns() }

#[inline]
fn irq_save_enable() -> u64 {
    use sync::IrqGate;
    // SAFETY: bounded block wait; irq_restore pairs on the same task/CPU.
    #[cfg(target_arch = "x86_64")]
    unsafe { hal_x86_64::X86IrqGate::save_enable() }
    #[cfg(target_arch = "aarch64")]
    unsafe { hal_aarch64::ArmIrqGate::save_enable() }
}

#[inline]
fn irq_restore(token: u64) {
    use sync::IrqGate;
    // SAFETY: token came from irq_save_enable on this task/CPU.
    #[cfg(target_arch = "x86_64")]
    unsafe { hal_x86_64::X86IrqGate::restore(token) }
    #[cfg(target_arch = "aarch64")]
    unsafe { hal_aarch64::ArmIrqGate::restore(token) }
}

fn can_sleep() -> bool {
    if sched::live::global().is_none() { return false; }
    #[cfg(target_arch = "aarch64")]
    if hal_aarch64::on_irq_stack() { return false; }
    #[cfg(target_arch = "x86_64")]
    if hal_x86_64::on_irq_stack() { return false; }
    match sched::live::current() {
        Some(task) => !matches!(task.sched_class(), sched::SchedClass::Idle),
        None => false,
    }
}

/// Poll a lock-free condition with IRQs enabled for one bounded budget.
/// # C: O(IO_SPIN_BUDGET)
pub(crate) fn poll_enabled(mut done: impl FnMut() -> bool, deadline: u64) -> bool {
    let irq = irq_save_enable();
    let mut spun = 0u64;
    let mut complete = false;
    while spun < IO_SPIN_BUDGET {
        if done() {
            complete = true;
            break;
        }
        if now_ns() >= deadline { break; }
        spun += 1;
        core::hint::spin_loop();
    }
    irq_restore(irq);
    complete
}

/// Register first, then recheck to close the cross-CPU wake-before-park gap.
/// # C: O(1)
pub(crate) fn park_checked(list: &WaitList, mut done: impl FnMut() -> bool) {
    if !can_sleep() {
        core::hint::spin_loop();
        return;
    }
    // SAFETY: process context, no driver spinlock held; immediate recheck
    // below cancels the registration when the condition already became true.
    unsafe { list.park(); }
    if done() {
        list.cancel_current_park();
        return;
    }
    // SAFETY: current is registered Sleeping on list and holds no plain lock.
    unsafe { sched::live::schedule::schedule(); }
}
