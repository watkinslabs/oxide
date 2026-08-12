//! Process-context NVMe waits with IRQ-enabled polling and lost-wakeup safety.

#![cfg(target_os = "oxide-kernel")]

use sched::live::wait_list::WaitList;

pub(crate) const IO_TIMEOUT_NS: u64 = 5_000_000_000;

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

/// Recheck the lock-free condition once with IRQs enabled before parking.
///
/// Linux's normal NVMe PCI path completes interrupt-driven queues in its IRQ
/// handler. It does not busy-poll an IRQ-driven request before sleeping; only
/// explicitly polled queues take that path. This one recheck admits an IRQ
/// that was masked on entry without turning every storage request into a CPU
/// spin window. The following shared wait loop publishes before rechecking,
/// which closes the wake-before-park race.
/// # C: O(1)
pub(crate) fn poll_enabled(mut done: impl FnMut() -> bool, _deadline: u64) -> bool {
    let irq = irq_save_enable();
    let complete = done();
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
