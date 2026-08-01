// Driver-model registration: binding the i8042 keyboard as a platform-bus
// driver. Binding runs the hardware bring-up; failed detection leaves
// platform/i8042 unbound.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use super::bringup::{bringdown, bringup, shutdown_hw};
use super::irq::install_irq;
use super::state::{PRESENT, present};

struct Ps2KbdDriver;

impl drv::Driver for Ps2KbdDriver {
    fn bus(&self) -> &'static str { "platform" }
    fn name(&self) -> &'static str { "i8042-kbd" }
    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == "platform" && dev.addr == "i8042"
    }

    fn probe(&self, _dev: &Arc<drv::Device>) -> drv::KResult<()> {
        if present() {
            return Err(drv::Error::Busy);
        }
        // SAFETY: driver-core bind runs in the same boot window that
        // previously called init directly: single-CPU, IRQs masked, no
        // concurrent accessor for ports 0x60/0x64.
        if unsafe { bringup() } {
            PRESENT.store(true, Ordering::Release);
            // SAFETY: `bringup` returned true, so the controller answered and
            // scanning is enabled; `PRESENT` is published, which is what gates
            // the handler this call installs. Still the single-CPU bind window,
            // so nothing else can touch the I/O APIC or the i8042 meanwhile.
            if !unsafe { install_irq() } {
                // SAFETY: `install_irq` unwound its own vector/pin before
                // failing, so this driver still owns the bound i8042 exactly as
                // it did after `bringup`, and no IRQ can be in flight —
                // `IRQ_ENABLED` was never set on the failure path.
                unsafe { bringdown(); }
                return Err(drv::Error::ProbeFailed);
            }
            debug_boot! { klog::write_raw(b"[INFO]  i8042 keyboard detected\n"); }
            Ok(())
        } else {
            Err(drv::Error::ProbeFailed)
        }
    }

    fn remove(&self, _dev: &drv::Device) {
        if !present() {
            return;
        }
        // SAFETY: driver-core remove owns the bound platform/i8042 device.
        unsafe { bringdown(); }
    }

    fn shutdown(&self, _dev: &drv::Device) {
        if !present() {
            return;
        }
        // SAFETY: driver-core shutdown owns terminal platform-device quiesce.
        unsafe { shutdown_hw(); }
    }
}

static PS2_DRV: Ps2KbdDriver = Ps2KbdDriver;

/// Driver-model handle for kmain platform-device registration. # C: O(1)
pub fn driver() -> &'static dyn drv::Driver { &PS2_DRV }
