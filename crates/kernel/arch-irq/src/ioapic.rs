//! x86 IOAPIC routing through the architecture-owned interrupt-remapping path.

/// Program a live x86 IOAPIC source route.  VT-d owns source verification and
/// IRTE publication; the HAL owns the documented IOAPIC register layout.
/// Returns false when a selected remapping unit cannot allocate the route.
///
/// # SAFETY: caller holds the boot-time IOAPIC serialization required by the
/// HAL and has installed the handler for `vector` before this call. # C: O(IRTE scan + poll limit)
pub unsafe fn program_x86_ioapic(pin: u32, vector: u8, destination_apic_id: u8,
    level: bool, active_low: bool) -> bool {
    match iommu::allocate_vtd_ioapic(vector, u32::from(destination_apic_id)) {
        iommu::VtdIoapic::Remapped { index } => {
            // SAFETY: caller supplies the IOAPIC serialization and a live vector handler.
            unsafe { hal_x86_64::ioapic::program_remapped_redirect(pin, vector, index, level, active_low) }
        }
        iommu::VtdIoapic::Direct => {
            // SAFETY: caller supplies the IOAPIC serialization and a live vector handler.
            unsafe { hal_x86_64::ioapic::program_redirect(pin, vector, destination_apic_id, level, active_low); }
            true
        }
        iommu::VtdIoapic::Failed => false,
    }
}
