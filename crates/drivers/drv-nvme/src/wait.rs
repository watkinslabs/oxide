//! Process-context NVMe waits with IRQ-enabled polling and lost-wakeup safety.

#![cfg(target_os = "oxide-kernel")]

use sched::live::wait_list::WaitList;

pub(crate) const IO_TIMEOUT_NS: u64 = 5_000_000_000;
pub(crate) const IO_SPIN_BUDGET: u64 = 200_000;

/// Monotonic wait clock. # C: O(1)
pub(crate) fn now_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}

#[inline]
fn irq_save_enable() -> u64 {
    use sync::IrqGate;
    // SAFETY: poll_enabled holds no driver lock shared with the IRQ or
    // softirq paths, and every exit restores this exact mask token.
    #[cfg(target_arch = "x86_64")]
    unsafe { hal_x86_64::X86IrqGate::save_enable() }
    // SAFETY: poll_enabled holds no driver lock shared with the IRQ or
    // softirq paths, and every exit restores this exact mask token.
    #[cfg(target_arch = "aarch64")]
    unsafe { hal_aarch64::ArmIrqGate::save_enable() }
}

#[inline]
fn irq_restore(token: u64) {
    use sync::IrqGate;
    // SAFETY: token came from irq_save_enable in this call frame.
    #[cfg(target_arch = "x86_64")]
    unsafe { hal_x86_64::X86IrqGate::restore(token) }
    // SAFETY: token came from irq_save_enable in this call frame.
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
        if done() { complete = true; break; }
        if now_ns() >= deadline { break; }
        spun += 1;
        core::hint::spin_loop();
    }
    irq_restore(irq);
    complete
}

/// Use the scheduler's shared timed predicate wait to close wake-before-park.
/// # C: O(1)
pub(crate) fn park_checked(list: &WaitList, deadline: u64, done: impl FnMut() -> bool) {
    if !can_sleep() { core::hint::spin_loop(); return; }
    // SAFETY: process context, installed runqueue, no driver spinlock held;
    // the shared wait loop publishes before each predicate recheck.
    unsafe { let _ = sched::live::wait_event_uninterruptible_until(list, deadline, now_ns, done); }
}
