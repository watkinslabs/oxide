// The interrupt gate this crate's IRQ-shared locks close.
//
// `Policy::state` is read by the scheduler's utilisation hook, which runs in
// hard-interrupt context. A lock an interrupt handler takes must be taken with
// interrupts masked everywhere else, or the handler lands on a process-context
// holder and the CPU spins for ever (`06§3.1`). One cfg-selected alias at a
// module boundary keeps that choice out of the locking sites themselves.

#[cfg(target_arch = "x86_64")]
pub(crate) type CfIrq = hal_x86_64::X86IrqGate;
#[cfg(target_arch = "aarch64")]
pub(crate) type CfIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) type CfIrq = sync::NoopIrq;
