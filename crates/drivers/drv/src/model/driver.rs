// The driver contract: what a bus asks of a driver across bind, teardown,
// error recovery and the sleep transitions of `32a§5`.

use alloc::sync::Arc;

use crate::KResult;
use crate::pm::DevPmOps;
use super::{Device, PciErrorHandlers};

/// The driver contract (drivers-plan: Driver/DriverInstance/Device +
/// probe/remove/shutdown symmetry). Object-safe (`&'static dyn Driver`).
/// `matches` decides whether this driver claims `dev`; `probe` performs
/// device bring-up and must leave no published partial state on failure;
/// `remove`/`shutdown` are the teardown symmetry.
pub trait Driver: Sync {
    /// Bus this driver registers on. PCI is the default because the current
    /// hardware model drivers mostly bind PCI functions; platform and future
    /// virtio child drivers override this.
    fn bus(&self) -> &'static str { "pci" }
    /// Driver name (appears at `/sys/bus/<bus>/drivers/<name>`).
    fn name(&self) -> &'static str;
    /// True iff this driver claims `dev`.
    fn matches(&self, dev: &Device) -> bool;
    /// Bind `dev`. Default Ok for passive/pseudo drivers. # C: driver-defined
    fn probe(&self, _dev: &Arc<Device>) -> KResult<()> { Ok(()) }
    /// PCI error-recovery callbacks for this bound PCI driver. Drivers without
    /// a complete recovery implementation return `None`. # C: O(1)
    fn pci_error_handlers(&self) -> Option<&'static PciErrorHandlers> { None }
    /// Sleep callbacks for this driver (`32a§5` steps 5-11). A driver whose
    /// state survives a sleep unchanged returns `None`, which is not the same
    /// as a table of empty callbacks: the phase walk skips it entirely.
    /// # C: O(1)
    fn pm(&self) -> Option<&'static DevPmOps> { None }
    /// Release `dev` (hot-unplug). Default no-op. # C: driver-defined
    fn remove(&self, _dev: &Device) {}
    /// Quiesce `dev` for reboot/poweroff. Default no-op. # C: driver-defined
    fn shutdown(&self, _dev: &Device) {}
}
