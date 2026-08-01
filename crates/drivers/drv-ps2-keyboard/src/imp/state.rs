// Driver-lifetime state: detection, IRQ ownership, and the boot platform data
// the IRQ setup needs. All published with release stores / acquire loads so the
// IRQ handler never observes a half-built driver.

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

pub(super) static PRESENT: AtomicBool = AtomicBool::new(false);
pub(super) static IRQ_ENABLED: AtomicBool = AtomicBool::new(false);
pub(super) static BSP_APIC_ID: AtomicU64 = AtomicU64::new(0);
pub(super) static DEVICE_WINDOW_BASE: AtomicU64 = AtomicU64::new(0);
pub(super) static IRQ_VEC: AtomicU64 = AtomicU64::new(0);
pub(super) static IRQ_PIN: AtomicU64 = AtomicU64::new(u64::MAX);

/// Sentinel meaning "no I/O APIC pin is owned by this driver".
pub(super) const NO_IRQ_PIN: u64 = u64::MAX;
/// Sentinel meaning "no x86 interrupt vector is owned by this driver".
pub(super) const NO_IRQ_VEC: u64 = 0;

/// True once the i8042 keyboard was detected by `Ps2KbdDriver::probe`. # C: O(1)
pub fn present() -> bool { PRESENT.load(Ordering::Acquire) }

/// True while IRQ1 delivery may drain scancodes into the input pipeline.
/// Shutdown/remove clear this before masking hardware so late vectors see a
/// quiesced driver.
/// # C: O(1)
pub fn irq_enabled() -> bool { IRQ_ENABLED.load(Ordering::Acquire) }

/// Boot-time platform data used by the driver's IRQ setup.
/// # C: O(1)
pub fn configure_probe(bsp_apic_id: u8, dev_window_base: u64) {
    BSP_APIC_ID.store(bsp_apic_id as u64, Ordering::Release);
    DEVICE_WINDOW_BASE.store(dev_window_base, Ordering::Release);
}
