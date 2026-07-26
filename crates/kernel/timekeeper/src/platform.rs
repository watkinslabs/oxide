/// Arch IRQ gate for the timekeeper seqlock's writers. Readers acquire
/// nothing; writers must mask interrupts so an ISR reader can never spin on an
/// update it interrupted (`sync::seqlock` module note).
#[cfg(target_arch = "x86_64")]
pub type Irq = hal_x86_64::X86IrqGate;
#[cfg(target_arch = "aarch64")]
pub type Irq = hal_aarch64::ArmIrqGate;

/// Architecture monotonic clock in nanoseconds. # C: O(1)
#[inline]
pub fn monotonic_ns() -> u64 {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    { hal_x86_64::X86TimerOps::monotonic_ns().0 }
    #[cfg(target_arch = "aarch64")]
    { hal_aarch64::ArmTimerOps::monotonic_ns().0 }
}
