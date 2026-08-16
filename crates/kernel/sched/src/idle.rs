// The idle park's interrupt contract — Linux `default_idle_call` /
// `cpuidle_idle_call`.
//
// The idle loop is reached with interrupts MASKED: `schedule()` runs its pick
// behind a saved-and-disabled mask, and the idle task resumes with whatever
// mask its last switch-out saved. The park primitive is therefore the thing
// that enables them, and it must do so inseparably from the halt — Linux's
// `raw_safe_halt` is one instruction pair for exactly that reason.
//
// A park that halts with interrupts still masked is not slow, it is terminal:
// the core sits in `hlt` / spins out of `wfi` and takes no tick, no
// reschedule IPI and no device interrupt for the rest of the boot. Nothing
// reports it either, because the cross-CPU stall scan deliberately excuses a
// CPU that has entered the idle path (`diag::percpu::idle_enter`) — so the
// machine goes silent with no watchdog line at all, and the only surviving
// evidence is that the CPU's heartbeat stops and its saved flags show the mask
// closed. That was the every-boot gate's intermittent wedge.
//
// The decision lives here, off the target gate, because the loop it belongs to
// is `#[cfg(target_os = "oxide-kernel")]` and a test written beside it would
// compile away silently (`docs/53`).

/// The park primitives one CPU offers the idle loop, and the interrupt state
/// it can be asked about. Implemented once for real hardware and once for the
/// hosted model that pins the contract.
pub trait IdleOps {
    /// Are interrupts currently admitted on this CPU?
    /// # C: O(1)
    fn irqs_enabled(&self) -> bool;

    /// Park in a platform idle state, enabling interrupts as part of the park.
    /// `false` when no idle driver owns this CPU and nothing was parked.
    /// # C: O(1) plus the park
    fn cpuidle_park(&mut self) -> bool;

    /// Enable interrupts and halt, inseparably — Linux `raw_safe_halt`.
    /// # C: O(1) plus the park
    fn safe_halt(&mut self);

    /// Admit interrupts without parking — the repair for a park that returned
    /// with them still masked (Linux's `local_irq_enable` under its
    /// `WARN_ON_ONCE(irqs_disabled())`).
    /// # C: O(1)
    fn enable_irqs(&mut self);

    /// Report a park that returned with interrupts masked. Linux warns once;
    /// the repair happens either way, because leaving them masked hands the
    /// next park a core nothing can wake.
    /// # C: O(1)
    fn report_masked_return(&mut self);
}

/// One idle park: hand the CPU to its idle driver, or halt it directly, and
/// guarantee interrupts are admitted on return whichever arm ran.
///
/// The guarantee is the whole point. Every caller of this loop depends on the
/// next iteration being reachable, and the next iteration is only reachable if
/// something can interrupt the park.
/// # C: O(1) plus the park
pub fn idle_park<O: IdleOps>(ops: &mut O) {
    if !ops.cpuidle_park() { ops.safe_halt(); }
    if ops.irqs_enabled() { return; }
    ops.report_masked_return();
    ops.enable_irqs();
}

#[cfg(test)]
#[path = "idle/tests.rs"] mod tests;
