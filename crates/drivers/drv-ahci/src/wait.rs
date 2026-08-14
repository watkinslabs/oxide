//! Process-context AHCI waits with IRQ-enabled polling and lost-wakeup safety.

#![cfg(target_os = "oxide-kernel")]

use sched::live::wait_list::WaitList;

/// Monotonic wait clock. # C: O(1)
pub(crate) fn now_ns() -> u64 { crate::port::now_ns() }

#[inline]
fn irq_save_enable() -> u64 {
    use sync::IrqGate;
    // SAFETY: unmasking is sound because the only caller, `poll_enabled`, holds
    // no plain lock an IRQ or softirq path also takes, and its every exit —
    // completion, deadline, or budget — pairs this with `irq_restore(token)`.
    #[cfg(target_arch = "x86_64")]
    unsafe { hal_x86_64::X86IrqGate::save_enable() }
    // SAFETY: unmasking is sound because the only caller, `poll_enabled`, holds
    // no plain lock an IRQ or softirq path also takes, and its every exit —
    // completion, deadline, or budget — pairs this with `irq_restore(token)`.
    #[cfg(target_arch = "aarch64")]
    unsafe { hal_aarch64::ArmIrqGate::save_enable() }
}

#[inline]
fn irq_restore(token: u64) {
    use sync::IrqGate;
    // SAFETY: `token` is the opaque flags word the matching `irq_save_enable`
    // produced earlier in the same call frame on this CPU, so restoring it
    // returns the interrupt mask to exactly the caller's entry state.
    #[cfg(target_arch = "x86_64")]
    unsafe { hal_x86_64::X86IrqGate::restore(token) }
    // SAFETY: `token` is the opaque DAIF word the matching `irq_save_enable`
    // produced earlier in the same call frame on this CPU, so restoring it
    // returns the interrupt mask to exactly the caller's entry state.
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
/// Linux's normal AHCI path completes a command through the IRQ handler; it
/// does not spin before sleeping on every interrupt-driven request. This one
/// recheck admits an IRQ that was masked on entry, then the shared wait loop
/// publishes and rechecks before schedule to close the wake-before-park race.
/// # C: O(1)
pub(crate) fn poll_enabled(mut done: impl FnMut() -> bool, _deadline: u64) -> bool {
    let irq = irq_save_enable();
    let complete = done();
    irq_restore(irq);
    complete
}

/// Register first, then recheck to close the cross-CPU wake-before-park gap.
/// # C: O(1)
pub(crate) fn park_checked(list: &WaitList, deadline: u64, done: impl FnMut() -> bool) {
    if !can_sleep() {
        core::hint::spin_loop();
        return;
    }
    // SAFETY: process context, no driver spinlock held; the shared predicate
    // loop owns publication, recheck and schedule.
    // SAFETY: process context, installed runqueue, no driver spinlock held;
    // the shared timed predicate loop publishes before every recheck and
    // retires the deadline on either completion or timeout.
    unsafe {
        let _ = sched::live::wait_event_uninterruptible_until(
            list, deadline, now_ns, done,
        );
    }
}

/// Publish a command waiter before ringing the device doorbell.
///
/// Waiter publication precedes producer enable; the issuer then either
/// consumes the ready state or schedules. The caller must cancel the prepared
/// waiter if it consumes completion without yielding.
/// # C: O(N armed)
pub(crate) fn prepare_command_wait(list: &WaitList, deadline: u64) -> bool {
    if !can_sleep() { return false; }
    // SAFETY: caller is process context and owns the command turn.  No driver
    // lock is held across its subsequent schedule, and the AHCI IRQ only
    // mutates the lock-free completion predicate before waking this list.
    unsafe { list.prepare_to_wait_with_deadline(deadline); }
    true
}

/// Schedule after [`prepare_command_wait`] when the command is still pending.
/// # C: O(log N) plus a context switch
pub(crate) fn yield_prepared_command_wait() {
    // SAFETY: prepare_command_wait published current as Sleeping and the
    // caller rechecks the completion predicate after this handoff.
    unsafe { sched::live::park_yield(); }
}
