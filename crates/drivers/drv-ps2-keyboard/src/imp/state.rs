// Driver-lifetime state: detection, IRQ ownership, and the boot platform data
// the IRQ setup needs. All published with release stores / acquire loads so the
// IRQ handler never observes a half-built driver.

use core::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};

use crate::ps2_mouse::PacketMode;

pub(super) static PRESENT: AtomicBool = AtomicBool::new(false);
pub(super) static IRQ_ENABLED: AtomicBool = AtomicBool::new(false);
pub(super) static AUX_PRESENT: AtomicBool = AtomicBool::new(false);
pub(super) static AUX_MODE: AtomicU8 = AtomicU8::new(AUX_MODE_BARE);
pub(super) static AUX_IRQ_ENABLED: AtomicBool = AtomicBool::new(false);
pub(super) static BSP_APIC_ID: AtomicU64 = AtomicU64::new(0);
pub(super) static DEVICE_WINDOW_BASE: AtomicU64 = AtomicU64::new(0);
pub(super) static IRQ_VEC: AtomicU64 = AtomicU64::new(0);
pub(super) static IRQ_PIN: AtomicU64 = AtomicU64::new(u64::MAX);
/// IRQ12 ownership is published independently from IRQ1 because both lines
/// route into the same controller but have distinct I/O-APIC redirections.
pub(super) static AUX_IRQ_VEC: AtomicU64 = AtomicU64::new(0);
pub(super) static AUX_IRQ_PIN: AtomicU64 = AtomicU64::new(u64::MAX);

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

const AUX_MODE_BARE: u8 = 0;
const AUX_MODE_WHEEL: u8 = 1;
const AUX_MODE_EXPLORER: u8 = 2;

/// Persist the hardware-negotiated PS/2 packet layout before AUX IRQ delivery. # C: O(1)
pub(super) fn set_aux_mode(mode: PacketMode) {
    let value = match mode {
        PacketMode::Bare => AUX_MODE_BARE,
        PacketMode::Wheel => AUX_MODE_WHEEL,
        PacketMode::Explorer => AUX_MODE_EXPLORER,
    };
    AUX_MODE.store(value, Ordering::Release);
}

/// Read the hardware-negotiated PS/2 packet layout. # C: O(1)
pub(super) fn aux_mode() -> PacketMode {
    match AUX_MODE.load(Ordering::Acquire) {
        AUX_MODE_WHEEL => PacketMode::Wheel,
        AUX_MODE_EXPLORER => PacketMode::Explorer,
        _ => PacketMode::Bare,
    }
}

/// Boot-time platform data used by the driver's IRQ setup.
/// # C: O(1)
pub fn configure_probe(bsp_apic_id: u8, dev_window_base: u64) {
    BSP_APIC_ID.store(bsp_apic_id as u64, Ordering::Release);
    DEVICE_WINDOW_BASE.store(dev_window_base, Ordering::Release);
}
