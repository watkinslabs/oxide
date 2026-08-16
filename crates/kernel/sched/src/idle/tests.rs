// The idle park's interrupt contract, against a CPU model that records the
// mask state it was actually halted in.
//
// The bug these pin: `halt_forever` parked through the bare architectural halt
// (`hlt` / `wfi`), which does not touch the mask. Reached with interrupts
// masked — the normal state on the idle path — that parks a core no interrupt
// can reach, and the stall scan excuses an idle-parked CPU, so nothing reports
// it. Measured on a wedged guest: CPU 1's heartbeat frozen 79 s, `[CPU-STALL]`
// silent, and both non-maskable-interrupt samples showing the mask closed.

use super::{idle_park, IdleOps};

/// A CPU with a mask, a park, and a memory of how it was parked.
#[derive(Default)]
struct Cpu {
    irqs_on: bool,
    /// Platform driver present, and whether its park admits interrupts.
    driver: Option<bool>,
    halts: u32,
    driver_parks: u32,
    /// Every park this CPU performed, and the mask state it entered with.
    parked_masked: u32,
    reports: u32,
    repairs: u32,
}

impl Cpu {
    /// A CPU with no idle driver, entering the loop with interrupts masked —
    /// the state the idle path is actually reached in.
    fn bare() -> Self { Self::default() }
    fn with_driver(admits: bool) -> Self { Self { driver: Some(admits), ..Self::default() } }
}

impl IdleOps for Cpu {
    fn irqs_enabled(&self) -> bool { self.irqs_on }
    fn cpuidle_park(&mut self) -> bool {
        let Some(admits) = self.driver else { return false };
        self.driver_parks += 1;
        // A park that admits interrupts does so as part of the park, so the
        // mask is open for the whole of it.
        if admits { self.irqs_on = true; } else { self.parked_masked += 1; }
        true
    }
    fn safe_halt(&mut self) {
        // Enable and park, inseparably: the mask is never closed while parked.
        self.irqs_on = true;
        self.halts += 1;
    }
    fn enable_irqs(&mut self) { self.repairs += 1; self.irqs_on = true; }
    fn report_masked_return(&mut self) { self.reports += 1; }
}

/// A CPU whose halt does NOT touch the mask — the pre-fix `hlt` / `wfi`. Kept
/// as a model rather than a comment so the failure it produces is visible in
/// the assertions below rather than only in a boot log.
struct MaskedHaltCpu(Cpu);

impl IdleOps for MaskedHaltCpu {
    fn irqs_enabled(&self) -> bool { self.0.irqs_enabled() }
    fn cpuidle_park(&mut self) -> bool { self.0.cpuidle_park() }
    fn safe_halt(&mut self) {
        self.0.halts += 1;
        if !self.0.irqs_on { self.0.parked_masked += 1; }
    }
    fn enable_irqs(&mut self) { self.0.enable_irqs() }
    fn report_masked_return(&mut self) { self.0.report_masked_return() }
}

/// The core invariant: the idle loop never halts a CPU whose interrupt mask is
/// closed. Nothing but a non-maskable interrupt can end such a park.
#[test]
fn the_idle_park_never_halts_with_interrupts_masked() {
    let mut cpu = Cpu::bare();
    assert!(!cpu.irqs_enabled(), "the idle path is entered with interrupts masked");
    idle_park(&mut cpu);
    assert_eq!(cpu.halts, 1, "a CPU with no idle driver halts directly");
    assert_eq!(cpu.parked_masked, 0, "parked with the interrupt mask closed");
}

/// And it holds over repeated iterations, which is the shape the real loop
/// runs: one masked park is enough to end the boot.
#[test]
fn no_iteration_of_the_loop_parks_masked() {
    let mut cpu = Cpu::bare();
    for _ in 0..8 {
        // Each wakeup returns to `schedule()`, which parks behind a masked
        // gate again before the next idle park.
        cpu.irqs_on = false;
        idle_park(&mut cpu);
    }
    assert_eq!(cpu.halts, 8);
    assert_eq!(cpu.parked_masked, 0);
}

/// Interrupts are admitted when the park returns — the condition the next loop
/// iteration, the tick, and every reschedule IPI depend on.
#[test]
fn the_park_returns_with_interrupts_admitted() {
    let mut cpu = Cpu::bare();
    idle_park(&mut cpu);
    assert!(cpu.irqs_enabled());
    assert_eq!(cpu.reports, 0, "a park that behaved needs no report");
    assert_eq!(cpu.repairs, 0);
}

/// A platform idle driver owns the park, and the direct halt is not also run —
/// parking twice would charge one idle period to two states.
#[test]
fn a_platform_idle_state_owns_the_park_instead_of_the_halt() {
    let mut cpu = Cpu::with_driver(true);
    idle_park(&mut cpu);
    assert_eq!(cpu.driver_parks, 1);
    assert_eq!(cpu.halts, 0, "the driver parked; the halt must not park again");
    assert!(cpu.irqs_enabled());
    assert_eq!(cpu.parked_masked, 0);
}

/// A driver whose park leaves the mask closed is repaired and reported rather
/// than trusted — Linux `if (WARN_ON_ONCE(irqs_disabled())) local_irq_enable()`.
/// Without this the next iteration parks masked and the CPU is gone.
#[test]
fn a_park_that_returns_masked_is_reported_and_repaired() {
    let mut cpu = Cpu::with_driver(false);
    idle_park(&mut cpu);
    assert_eq!(cpu.driver_parks, 1);
    assert_eq!(cpu.reports, 1, "a masked return must be reported");
    assert_eq!(cpu.repairs, 1, "and repaired, or the next park is unwakeable");
    assert!(cpu.irqs_enabled());
}

/// The pre-fix primitive, modelled: a halt that does not touch the mask parks
/// the CPU masked on the very first iteration. This is the defect the boot
/// wedge was, expressed where it costs milliseconds instead of a boot.
#[test]
fn a_halt_that_does_not_admit_interrupts_parks_the_cpu_masked() {
    let mut cpu = MaskedHaltCpu(Cpu::bare());
    idle_park(&mut cpu);
    assert_eq!(cpu.0.halts, 1);
    assert_eq!(cpu.0.parked_masked, 1, "the bare halt parks behind a closed mask");
    // The contract still catches it on the way out, which is the difference
    // between one lost wakeup and a CPU that never returns.
    assert_eq!(cpu.0.reports, 1);
    assert!(cpu.0.irqs_enabled());
}
