// Modern virtio-net runtime state (arch-neutral). The boot-time probe
// in `pci_boot::virtio_drv` brings up cap discovery, BAR mapping, queue
// program, DRIVER_OK, and MSI-X bind; once that finishes it hands the
// persistent kernel-side addresses here via `init_modern`. Later F59
// PRs consume the stashed state to drive RX-poll, TX, and ARP through
// `crate::net::stack`.
//
// Kept arch-neutral because every operation post-bring-up is MMIO
// (notify_cap window) + HHDM (ring frames). `pci_boot::virtio_drv`
// already speaks both arches, so the runtime side does too.

#![cfg(target_os = "oxide-kernel")]
#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

/// Persistent runtime state for one modern virtio-net device. Pointers
/// reference VAs/PAs already programmed into the device by the boot
/// probe; this module owns no allocation. `bus`/`device`/`function`
/// mirror the PCI BDF for log lines and later sysfs export.
#[derive(Copy, Clone, Default)]
pub struct ModernNetState {
    pub bus:      u8,
    pub device:   u8,
    pub function: u8,
    pub cfg_va:        u64,
    pub q0_notify_va:  u64,
    pub q1_notify_va:  u64,
    pub q0_desc_pa:    u64,
    pub q0_driver_pa:  u64,
    pub q0_device_pa:  u64,
    pub q1_desc_pa:    u64,
    pub q1_driver_pa:  u64,
    pub q1_device_pa:  u64,
    pub q0_size: u16,
    pub q1_size: u16,
}

static MODERN_DEV: Spinlock<Option<ModernNetState>, DriverLockClass> =
    Spinlock::new(None);
static MODERN_PRESENT: AtomicBool = AtomicBool::new(false);

/// Stash modern virtio-net runtime state for later RX/TX drivers.
/// Idempotent: subsequent calls are no-ops (boot probe runs once).
/// # C: O(1)
pub fn init_modern(state: ModernNetState) {
    if MODERN_PRESENT.load(Ordering::Acquire) { return; }
    *MODERN_DEV.lock() = Some(state);
    MODERN_PRESENT.store(true, Ordering::Release);
    debug_boot! {
        klog::write_raw(b"[INFO]  virtio-net-modern ");
        klog::write_dec_u64(state.bus as u64);
        klog::write_raw(b":");
        klog::write_dec_u64(state.device as u64);
        klog::write_raw(b".");
        klog::write_dec_u64(state.function as u64);
        klog::write_raw(b" cfg_va=");
        klog::write_hex_u64(state.cfg_va);
        klog::write_raw(b" q0_size=");
        klog::write_dec_u64(state.q0_size as u64);
        klog::write_raw(b" q1_size=");
        klog::write_dec_u64(state.q1_size as u64);
        klog::write_raw(b" q0_notify_va=");
        klog::write_hex_u64(state.q0_notify_va);
        klog::write_raw(b" q1_notify_va=");
        klog::write_hex_u64(state.q1_notify_va);
        klog::write_raw(b"\n");
    }
}

/// Snapshot of the registered modern device (None until init_modern).
/// # C: O(1) under MODERN_DEV.lock()
pub fn modern_state() -> Option<ModernNetState> { *MODERN_DEV.lock() }

/// True once `init_modern` has been called with a valid state.
/// # C: O(1)
pub fn is_modern_present() -> bool { MODERN_PRESENT.load(Ordering::Acquire) }
