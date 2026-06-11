//! Per-CPU interrupt counters for `/proc/interrupts` (Linux `kstat_irqs` /
//! `show_interrupts`). The timer-IRQ dispatcher bumps the per-CPU bucket for
//! the line it handled: the local-APIC/CNTV timer (LOC), the resched IPI
//! (RES), and each per-vector MSI/SPI device line. `/proc/interrupts` reads
//! them; deltas are the reader's concern.

use core::sync::atomic::{AtomicU64, Ordering};

const NCPU: usize = cpu::MAX_CPUS;
/// Device interrupt lines tracked (x86 MSI pool / arm GICv2M SPI window).
pub const NLINES: usize = 224;

static TIMER:   [AtomicU64; NCPU] = [const { AtomicU64::new(0) }; NCPU];
static RESCHED: [AtomicU64; NCPU] = [const { AtomicU64::new(0) }; NCPU];
static LINES:   [[AtomicU64; NCPU]; NLINES] =
    [const { [const { AtomicU64::new(0) }; NCPU] }; NLINES];

#[inline]
fn cpu() -> usize {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_x86_64::X86CpuOps::current_cpu() as usize).min(NCPU - 1) }
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { use hal::CpuOps; (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(NCPU - 1) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { 0 }
}

/// Charge a local-timer (LOC) interrupt to this CPU. # C: O(1)
#[inline] pub fn hit_timer()   { TIMER[cpu()].fetch_add(1, Ordering::Relaxed); }
/// Charge a resched IPI (RES) to this CPU. # C: O(1)
#[inline] pub fn hit_resched() { RESCHED[cpu()].fetch_add(1, Ordering::Relaxed); }
/// Charge device line `idx` (MSI pool / SPI index) to this CPU. # C: O(1)
#[inline] pub fn hit_line(idx: usize) {
    if idx < NLINES { LINES[idx][cpu()].fetch_add(1, Ordering::Relaxed); }
}

/// Per-CPU LOC count. # C: O(1)
pub fn timer(c: usize) -> u64 { if c < NCPU { TIMER[c].load(Ordering::Relaxed) } else { 0 } }
/// Per-CPU RES count. # C: O(1)
pub fn resched(c: usize) -> u64 { if c < NCPU { RESCHED[c].load(Ordering::Relaxed) } else { 0 } }
/// Per-CPU count for device line `idx`. # C: O(1)
pub fn line(idx: usize, c: usize) -> u64 {
    if idx < NLINES && c < NCPU { LINES[idx][c].load(Ordering::Relaxed) } else { 0 }
}
/// Sum of line `idx` over all CPUs (skip-zero-row test). # C: O(NCPU)
pub fn line_total(idx: usize) -> u64 {
    (0..NCPU).map(|c| line(idx, c)).sum()
}
