//! VT-d primary-fault MSI ownership.

use sync::{Devices, Spinlock};

static BINDING: Spinlock<Option<arch_irq::MsiMessage>, Devices> = Spinlock::new(None);

/// Allocate, publish, and retain the platform MSI used by every live DRHD. # C: O(1)
pub(super) fn install() -> bool {
    let mut binding = BINDING.lock();
    if let Some(message) = *binding {
        return iommu::enable_vtd_fault_interrupts(message.address, message.data);
    }
    let Some(message) = arch_irq::request_platform_msi(arch_irq::DeviceAction::Vtd,
        iommu::handle_vtd_fault_interrupt) else { return false; };
    if !iommu::enable_vtd_fault_interrupts(message.address, message.data) {
        arch_irq::free_platform_msi(message);
        return false;
    }
    *binding = Some(message);
    true
}
