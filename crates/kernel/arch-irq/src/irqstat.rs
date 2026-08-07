//! Per-CPU interrupt counters for `/proc/interrupts` (Linux `kstat_irqs` /
//! `show_interrupts`). The timer-IRQ dispatcher bumps the per-CPU bucket for
//! the line it handled: the local-APIC/CNTV timer (LOC), the resched IPI
//! (RES), and each per-vector MSI/SPI device line. `/proc/interrupts` reads
//! them; deltas are the reader's concern.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

const NCPU: usize = cpu::MAX_CPUS;
/// Device interrupt lines tracked (x86 MSI pool / arm GICv2M SPI and ITS LPI windows).
pub const NLINES: usize = 224;

static TIMER:   [AtomicU64; NCPU] = [const { AtomicU64::new(0) }; NCPU];
static RESCHED: [AtomicU64; NCPU] = [const { AtomicU64::new(0) }; NCPU];
static LINES:   [[AtomicU64; NCPU]; NLINES] =
    [const { [const { AtomicU64::new(0) }; NCPU] }; NLINES];
static LINE_IRQ: [AtomicU32; NLINES] = [const { AtomicU32::new(0) }; NLINES];
static LINE_ACTION: [AtomicU8; NLINES] = [const { AtomicU8::new(0) }; NLINES];

/// Action identity rendered for one device IRQ. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceAction { VirtioPci, Ahci }
impl DeviceAction {
    const fn code(self) -> u8 { match self { Self::VirtioPci => 1, Self::Ahci => 2 } }
    const fn from_code(code: u8) -> Option<Self> {
        match code { 1 => Some(Self::VirtioPci), 2 => Some(Self::Ahci), _ => None }
    }
    /// `/proc/interrupts` action name. # C: O(1)
    pub const fn name(self) -> &'static str { match self { Self::VirtioPci => "virtio-pci", Self::Ahci => "ahci" } }
}

/// One active device IRQ descriptor snapshot. # C: O(1)
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceLine { pub irq: u32, pub action: DeviceAction }

fn msi_index(irq: u32) -> Option<usize> {
    #[cfg(target_arch = "x86_64")]
    {
        let first = hal_x86_64::VEC_MSI_POOL_FIRST as u32;
        return irq.checked_sub(first).filter(|idx| (*idx as usize) < NLINES).map(|idx| idx as usize);
    }
    #[cfg(target_arch = "aarch64")]
    {
        let lpi_first = crate::gic::LPI_BASE + 1;
        if let Some(idx) = irq.checked_sub(lpi_first)
            .filter(|idx| (*idx as usize) < crate::ARM_MSI_SLOTS)
        {
            return Some(NLINES - crate::ARM_MSI_SLOTS + idx as usize);
        }
        let spi_first = crate::GICV2M_SPI_FIRST.load(Ordering::Acquire);
        return irq.checked_sub(spi_first)
            .filter(|idx| spi_first != 0 && (*idx as usize) < crate::ARM_MSI_SLOTS)
            .map(|idx| idx as usize);
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    { let _ = irq; None }
}

/// Publish the action identity for an installed PCI MSI descriptor. # C: O(1)
pub fn register_msi(irq: u32, action: DeviceAction) -> bool {
    let Some(idx) = msi_index(irq) else { return false; };
    for count in &LINES[idx] {
        count.store(0, Ordering::Relaxed);
    }
    LINE_ACTION[idx].store(action.code(), Ordering::Release);
    LINE_IRQ[idx].store(irq, Ordering::Release);
    true
}
/// Withdraw one PCI MSI descriptor before its vector becomes reusable. # C: O(1)
pub fn unregister_msi(irq: u32) {
    let Some(idx) = msi_index(irq) else { return; };
    LINE_IRQ[idx].store(0, Ordering::Release);
    LINE_ACTION[idx].store(0, Ordering::Release);
}
/// Snapshot one active PCI MSI descriptor. # C: O(1)
pub fn device_line(idx: usize) -> Option<DeviceLine> {
    let irq = LINE_IRQ.get(idx)?.load(Ordering::Acquire);
    let action = DeviceAction::from_code(LINE_ACTION.get(idx)?.load(Ordering::Acquire))?;
    (irq != 0).then_some(DeviceLine { irq, action })
}

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
/// Charge a registered PCI MSI descriptor to this CPU. # C: O(1)
#[inline] pub fn hit_msi(irq: u32) {
    if let Some(idx) = msi_index(irq) {
        if LINE_IRQ[idx].load(Ordering::Acquire) == irq { hit_line(idx); }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn msi_descriptor_owns_its_identity_and_counter_lifetime() {
        #[cfg(target_arch = "x86_64")]
        let irq = hal_x86_64::VEC_MSI_POOL_FIRST as u32 + 1;
        #[cfg(target_arch = "aarch64")]
        let irq = crate::gic::LPI_BASE + 2;
        let idx = msi_index(irq).unwrap();
        unregister_msi(irq);
        assert!(register_msi(irq, DeviceAction::VirtioPci));
        assert_eq!(device_line(idx), Some(DeviceLine { irq, action: DeviceAction::VirtioPci }));
        let before = line(idx, 0);
        assert_eq!(before, 0);
        hit_msi(irq);
        assert_eq!(line(idx, 0), before + 1);
        unregister_msi(irq);
        assert_eq!(device_line(idx), None);
        hit_msi(irq);
        assert_eq!(line(idx, 0), before + 1);
    }
}
