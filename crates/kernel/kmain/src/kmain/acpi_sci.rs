//! x86 FADT SCI interrupt bridge.

/// Route the FADT SCI through its MADT override and the owning I/O APIC.
/// # C: O(1)
pub fn install(interrupt: u16) -> bool {
    let Some(vector) = arch_irq::alloc_x86_vector() else { return false; };
    if arch_irq::register_irq_line_handler(u32::from(vector), irq).is_err() {
        let _ = arch_irq::free_x86_vector(vector);
        return false;
    }
    let (gsi, level, active_low) = match u8::try_from(interrupt) {
        Ok(source) if source < 16 => {
            let gsi = firmware::legacy_irq_gsi(source).unwrap_or(u32::from(source));
            let flags = firmware::legacy_irq_flags(source).unwrap_or(0);
            let (level, active_low) = firmware::acpi_sci_characteristics(flags);
            (gsi, level, active_low)
        }
        _ => (u32::from(interrupt), true, true),
    };
    // SAFETY: PCI boot mapped every MADT I/O APIC before this provider phase;
    // the line handler owns `vector` before the level source is unmasked.
    if unsafe { arch_irq::program_x86_intx_gsi(gsi, vector,
        arch_irq::lapic::local_apic_id(), level, active_low) } { return true; }
    let _ = arch_irq::free_irq_line_handler(u32::from(vector));
    let _ = arch_irq::free_x86_vector(vector);
    false
}

/// Dispatch one SCI delivery through the firmware event owner.
/// # C: O(GPE register bytes) # Ctx: hard IRQ
pub(crate) fn irq(_vector: u32) -> arch_irq::IrqReport {
    let ret = if firmware::acpi::events::handle_sci_irq() { arch_irq::IrqRet::Handled }
        else { arch_irq::IrqRet::NotMine };
    arch_irq::IrqReport::hard(ret)
}
