// Which CPU owns global timekeeping — Linux `tick_do_timer_cpu`
// (`skizm.md` Step 5, 3.2's duplicated-policy defect).
//
// The timer interrupt fires on EVERY CPU, and each dispatcher must split its
// work into the per-CPU half (arm this CPU's next one-shot, charge this CPU's
// time) and the global half (advance wall time, service the shared timer
// queue). The second half must run on exactly one CPU.
//
// Both dispatchers answered "am I that CPU?" themselves, and answered it
// DIFFERENTLY:
//
//   x86  : local_apic_id()            == cpu::smp::boot_cpu_id()
//   arm  : ArmCpuOps::current_cpu()   == cpu::smp::boot_cpu_id()
//
// `boot_cpu_id()` is the boot CPU's HARDWARE id (APIC id / MPIDR) — its own
// doc comment says so. x86 therefore compares hardware-to-hardware and is
// right; aarch64 compares a LOGICAL cpu index against a hardware id and is
// right only because its boot MPIDR happens to be 0. On a board whose boot
// core has a non-zero MPIDR, every aarch64 CPU would decide it is not the
// timekeeper and global time would stop advancing.
//
// One question, asked once, in ONE id space: logical CPU ids, which is what
// `CpuOps::current_cpu()` returns on both arches (`gs:0` / `TPIDR_EL1`).
//
// It is a variable, not a constant, because Linux's is: `tick_handover_do_timer`
// moves it when the owning CPU is offlined. Ours could not move, so offlining
// the boot CPU would have stopped global timekeeping (`skizm.md` 3.2).

use core::sync::atomic::{AtomicU32, Ordering};

/// Logical CPU that owns global timekeeping. Boot CPU is logical 0 on both
/// arches (`cpu::smp::set_boot_cpu_id` resolves the BSP to logical 0), so 0 is
/// the correct pre-handover value.
static TIMEKEEPER_CPU: AtomicU32 = AtomicU32::new(0);

/// This CPU's LOGICAL id — `gs:0` on x86_64, `TPIDR_EL1` on aarch64. Host
/// builds are UP.
#[inline]
fn current_logical_cpu() -> u32 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// The logical CPU currently owning global timekeeping.
/// # C: O(1)
pub fn timekeeper_cpu() -> u32 { TIMEKEEPER_CPU.load(Ordering::Acquire) }

/// Hand global timekeeping to `logical` (Linux `tick_handover_do_timer`).
/// Called when the current owner is going offline.
/// # SAFETY: caller asserts `logical` is an online CPU that takes timer
/// interrupts; passing an offline CPU stops global time from advancing.
/// # C: O(1)
pub unsafe fn set_timekeeper_cpu(logical: u32) {
    TIMEKEEPER_CPU.store(logical, Ordering::Release);
}

/// Does THIS CPU own the global half of the tick?
///
/// The single answer both dispatchers use, so the policy cannot drift between
/// them again.
/// # C: O(1)
/// # Ctx: timer IRQ
#[inline]
pub fn is_timekeeper() -> bool { current_logical_cpu() == timekeeper_cpu() }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_default_is_logical_zero() {
        // Host builds report logical CPU 0, and the pre-handover owner is 0, so
        // a UP/hosted kernel must consider itself the timekeeper — otherwise
        // global time never advances before any handover happens.
        assert_eq!(timekeeper_cpu(), 0);
        assert!(is_timekeeper());
    }

    #[test]
    fn handover_moves_ownership_away_and_back() {
        // SAFETY: test-only; no real CPU is going offline.
        unsafe { set_timekeeper_cpu(1); }
        assert_eq!(timekeeper_cpu(), 1);
        assert!(!is_timekeeper(), "logical CPU 0 must yield once ownership moves");
        // SAFETY: restore the default so sibling tests see a clean value.
        unsafe { set_timekeeper_cpu(0); }
        assert!(is_timekeeper());
    }
}
