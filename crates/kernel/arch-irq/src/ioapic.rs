//! x86 IOAPIC routing through the architecture-owned interrupt-remapping path.

/// Program a live x86 IOAPIC source route.  VT-d owns source verification and
/// IRTE publication; the HAL owns the documented IOAPIC register layout.
/// Returns false when a selected remapping unit cannot allocate the route.
///
/// # SAFETY: caller holds the boot-time IOAPIC serialization required by the
/// HAL and has installed the handler for `vector` before this call. # C: O(IRTE scan + poll limit)
pub unsafe fn program_x86_ioapic(pin: u32, vector: u8, destination_apic_id: u32,
    level: bool, active_low: bool) -> bool {
    let Some(ioapic_id) = firmware::ioapic_id() else { return false; };
    // SAFETY: wrapper retains the first-controller route contract for legacy callers.
    unsafe { program_x86_ioapic_at(ioapic_id, hal_x86_64::ioapic::base_va(), pin, vector, destination_apic_id, level, active_low) }
}

/// # SAFETY: selected controller mapping is live and the vector handler is installed.
unsafe fn program_x86_ioapic_at(ioapic_id: u8, va: u64, pin: u32, vector: u8, destination_apic_id: u32,
    level: bool, active_low: bool) -> bool {
    match iommu::allocate_amd_vi_ioapic(ioapic_id, pin, vector, destination_apic_id) {
        iommu::AmdViIoapic::Remapped { index } => {
            // SAFETY: the AMD-Vi IRTE is live; this binds the wire index to the handler route.
            unsafe { hal_x86_64::ioapic::program_amd_remapped_redirect_at(va, pin, vector, index, level, active_low); }
            return true;
        }
        iommu::AmdViIoapic::Failed => return false,
        iommu::AmdViIoapic::Direct => {}
    }
    match iommu::allocate_vtd_ioapic(ioapic_id, vector, destination_apic_id) {
        iommu::VtdIoapic::Remapped { index } => {
            // SAFETY: caller supplies the IOAPIC serialization and a live vector handler.
            unsafe { hal_x86_64::ioapic::program_remapped_redirect_at(va, pin, vector, index, level, active_low) }
        }
        iommu::VtdIoapic::Direct => {
            let Ok(destination_apic_id) = u8::try_from(destination_apic_id) else { return false; };
            // SAFETY: caller supplies the IOAPIC serialization and a live vector handler.
            unsafe { hal_x86_64::ioapic::program_redirect_at(va, pin, vector, destination_apic_id, level, active_low); }
            true
        }
        iommu::VtdIoapic::Failed => false,
    }
}

/// Program a PCI INTx route named by its firmware GSI.  The currently
/// published x86 I/O APIC is responsible only for its own GSI range; callers
/// must therefore pass a route obtained from firmware, never the PCI
/// interrupt-line configuration byte.
///
/// # SAFETY: as [`program_x86_ioapic`]. # C: O(IRTE scan + poll limit)
pub unsafe fn program_x86_intx_gsi(gsi: u32, vector: u8, destination_apic_id: u32,
    level: bool, active_low: bool) -> bool {
    let Some((ioapic_id, va, pin)) = (unsafe { hal_x86_64::ioapic::gsi_pin(gsi) }) else { return false; };
    // SAFETY: `gsi_pin` selected a live mapped controller and the caller owns its serialization.
    unsafe { program_x86_ioapic_at(ioapic_id, va, pin, vector, destination_apic_id, level, active_low) }
}
