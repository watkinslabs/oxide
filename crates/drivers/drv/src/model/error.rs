// PCI error-recovery contract attached to the canonical bound `Driver`.

use super::{find_driver_on_bus, Device};

/// Connectivity state delivered with PCI error detection.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PciChannelState {
    Normal = 1,
    Frozen = 2,
    PermanentFailure = 3,
}

/// A driver's vote during PCI error recovery.
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PciErsResult {
    None = 1,
    CanRecover = 2,
    NeedReset = 3,
    Disconnect = 4,
    Recovered = 5,
    NoAerDriver = 6,
}

/// PCI driver's recovery callbacks. A service obtains this only through
/// [`bound_pci_error_handlers`], which resolves the device's live model binding.
#[derive(Copy, Clone)]
pub struct PciErrorHandlers {
    pub error_detected: Option<fn(&Device, PciChannelState) -> PciErsResult>,
    pub mmio_enabled: Option<fn(&Device) -> PciErsResult>,
    pub slot_reset: Option<fn(&Device) -> PciErsResult>,
    pub resume: Option<fn(&Device)>,
}

impl PciErrorHandlers {
    pub const NONE: Self = Self {
        error_detected: None,
        mmio_enabled: None,
        slot_reset: None,
        resume: None,
    };
}

/// Resolve the recovery callbacks of the PCI driver currently bound to `dev`.
/// Unbound, non-PCI, and handler-less drivers return `None`; callers must not
/// cache this result across teardown or invoke recovery after unbinding.
/// # C: O(N_drivers)
pub fn bound_pci_error_handlers(dev: &Device) -> Option<&'static PciErrorHandlers> {
    if dev.bus != "pci" { return None; }
    let name = dev.bound()?;
    find_driver_on_bus("pci", name)?.pci_error_handlers()
}
