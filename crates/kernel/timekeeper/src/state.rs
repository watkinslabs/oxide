// Canonical timekeeper state behind a seqlock (Linux `tk_core.seq`).
//
// This was a plain `Spinlock`, which made every clock read an acquisition of a
// lock that BOTH the timer ISR and syscalls take: `vvar::publish` runs in the
// tick and calls `realtime_ns`, while `clock_gettime`/`settimeofday` take the
// same lock in process context. A tick landing on a CPU whose syscall already
// held it deadlocks that CPU (`06§3.1`; lockdep reported the class as `Timer`,
// `skizm.md` 3.1 #3).
//
// Linux's answer is a seqcount, and it is the right one here: reads outnumber
// writes by orders of magnitude, the state is four `Copy` scalars, and readers
// must be callable from hard-IRQ context. `SeqLock::read` acquires nothing, so
// the ISR can never block on a writer. Writers mask interrupts (enforced by
// `SeqLock::write`'s `IrqGate` parameter) so an ISR reader can never spin on a
// half-finished update it interrupted.

use sync::{SeqLock, Timer as TimerLock};

pub use crate::model::{ClockSnapshot, TimeError, MAX_TAI_OFFSET};
use crate::model::ClockState;
use crate::platform::Irq;

static CLOCK: SeqLock<ClockState, TimerLock> = SeqLock::new(ClockState::ZERO);

/// Snapshot canonical timekeeper adjustment state. # C: O(1)
pub fn snapshot() -> ClockSnapshot { CLOCK.read().snapshot() }

/// Current CLOCK_REALTIME in Unix-epoch nanoseconds. # C: O(1)
/// # Ctx: any, including hard IRQ (lock-free seqlock read)
pub fn realtime_ns() -> u64 { CLOCK.read().realtime(crate::platform::monotonic_ns()) }

/// Current CLOCK_BOOTTIME including recorded suspend duration. # C: O(1)
pub fn boottime_ns() -> u64 { CLOCK.read().boottime(crate::platform::monotonic_ns()) }

/// Current CLOCK_TAI using the independently owned TAI-UTC offset. # C: O(1)
pub fn tai_ns() -> u64 { CLOCK.read().tai(crate::platform::monotonic_ns()) }

/// Step CLOCK_REALTIME without changing monotonic or boottime. # C: O(1)
pub fn set_realtime(target_ns: u64) {
    // Sampled before the write so the monotonic read is not taken with IRQs
    // masked and the writer section stays as short as Linux keeps it.
    let mono = crate::platform::monotonic_ns();
    CLOCK.write::<Irq>(|c| c.set_realtime(mono, target_ns));
}

/// Seed CLOCK_REALTIME from a persistent clock. # C: O(1)
pub fn seed_realtime(target_ns: u64) { set_realtime(target_ns); }

/// Set the kernel TAI-UTC offset in seconds. # C: O(1)
pub fn set_tai_offset(seconds: i32) -> Result<(), TimeError> {
    CLOCK.write_with::<Irq, _>(|c| c.set_tai_offset(seconds))
}

/// Add one completed suspend interval to CLOCK_BOOTTIME. # C: O(1)
pub fn account_suspend(elapsed_ns: u64) {
    CLOCK.write::<Irq>(|c| c.account_suspend(elapsed_ns));
}

/// Current TAI-UTC offset in seconds. # C: O(1)
pub fn tai_offset() -> i32 { CLOCK.read().tai_offset_sec }

/// Clock-step generation for realtime absolute deadline consumers. # C: O(1)
pub fn realtime_generation() -> u64 { CLOCK.read().realtime_generation }

/// Signed realtime-minus-monotonic offset, clamped to the legacy u64 ABI. # C: O(1)
pub fn realtime_offset_ns() -> u64 {
    CLOCK.read().wall_offset_ns.clamp(0, u64::MAX as i128) as u64
}

/// Unix epoch seconds corresponding to monotonic zero. # C: O(1)
pub fn boot_unix_seconds() -> u64 { realtime_offset_ns() / 1_000_000_000 }
