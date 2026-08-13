//! AMD-Vi event-log PCI-MSI ownership.

use alloc::vec::Vec;
use pci::Bdf;
use sync::{Devices, Spinlock};

static BINDINGS: Spinlock<Vec<pci_irq::Binding>, Devices> = Spinlock::new(Vec::new());

fn source_bdf(unit: firmware::acpi::IommuUnit) -> Bdf {
    Bdf { segment: unit.segment, bus: (unit.source_id >> 8) as u8,
        device: ((unit.source_id >> 3) & 0x1f) as u8, function: (unit.source_id & 7) as u8 }
}

/// Program and retain one PCI MSI binding per AMD-Vi source function. # C: O(units * requesters)
pub(super) fn install(requesters: &[Bdf]) -> bool {
    let mut bindings = BINDINGS.lock();
    if !bindings.is_empty() { return iommu::enable_amd_vi_event_interrupts(); }
    let mut sources = Vec::new();
    for index in 0..firmware::acpi::iommu_unit_count() {
        let Some(unit) = firmware::acpi::iommu_unit(index) else { release(&mut bindings); return false; };
        if unit.kind != firmware::acpi::IommuKind::AmdVi { continue; }
        let bdf = source_bdf(unit);
        if !requesters.contains(&bdf) { release(&mut bindings); return false; }
        if !sources.contains(&bdf) { sources.push(bdf); }
    }
    for bdf in sources {
        let Some(binding) = pci_irq::request_msi_only(bdf, arch_irq::DeviceAction::AmdVi,
            iommu::handle_amd_vi_event_interrupt) else { release(&mut bindings); return false; };
        bindings.push(binding);
    }
    if iommu::enable_amd_vi_event_interrupts() { true } else { let _ = iommu::disable_amd_vi_event_interrupts(); release(&mut bindings); false }
}

fn release(bindings: &mut Vec<pci_irq::Binding>) {
    while let Some(binding) = bindings.pop() { binding.release(); }
}
