// Interrupt-driven COM1 serial RX (x86_64) — the Linux 8250 path.
// Program the I/O APIC redirection-table entry for COM1's IRQ4 → a
// vector whose handler drains the UART RX FIFO, then unmask the UART's
// RX-data-available interrupt. Replaces polling the UART from every
// timer tick (`tty::live::tick_poll_uart` stays only as a fallback).
// No-op when no I/O APIC was discovered in the MADT.

/// Wire interrupt-driven COM1 serial RX. See module docs. `bsp_apic` is
/// the boot CPU's LAPIC id (the redirection destination).
///
/// # SAFETY: post-ACPI (MADT I/O APIC captured) + post-LAPIC-enable +
/// MmuOps live; single-CPU, IRQs masked. Maps device MMIO, programs the
/// I/O APIC, and does privileged port I/O to the COM1 IER.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub(crate) unsafe fn setup_x86(bsp_apic: u8) {
    use hal::{MmuOps, Pa, PageFlags, PageSize, Va};
    let pa = firmware::ioapic_pa();
    if pa == 0 { return; } // no I/O APIC → keep the timer-poll fallback
    // Map the I/O APIC MMIO Device-attr at the kernel device window.
    let va = crate::smoke::device_map::KERNEL_DEVICE_BASE | (pa & 0xffff_ffff);
    let pflags = PageFlags::READ | PageFlags::WRITE
        | PageFlags::NO_CACHE | PageFlags::WRITE_THROUGH;
    // SAFETY: device-window VA disjoint from RAM mappings; pa is the MADT I/O APIC base; single-CPU pre-init.
    unsafe { <hal_x86_64::mmu_ops::X86Mmu as MmuOps>::map(Va(va), Pa(pa), pflags, PageSize::P4K); }
    hal_x86_64::ioapic::set_base_va(va);
    // Allocate a vector + register the RX-FIFO drain handler.
    let vec = match arch_irq::alloc_x86_vector() { Some(v) => v, None => return };
    let _ = arch_irq::register_msi_handler(vec, tty::live::serial_rx_isr);
    // IRQ4 routing from the MADT (source override, else ISA defaults:
    // edge-triggered, active-high). Flags bits[1:0]=polarity (3=low),
    // bits[3:2]=trigger (3=level).
    let ovr = firmware::irq4_flags();
    let pin = firmware::irq4_gsi().wrapping_sub(firmware::ioapic_gsi_base());
    let active_low = (ovr & 0x3) == 3;
    let level = ((ovr >> 2) & 0x3) == 3;
    // SAFETY: I/O APIC just mapped; vec has a handler installed; single-CPU pre-init.
    unsafe { hal_x86_64::ioapic::program_redirect(pin, vec, bsp_apic, level, active_low); }
    // Unmask the UART RX-data-available interrupt (IER bit 0, port 0x3F9).
    // SAFETY: privileged port I/O at CPL=0 to the COM1 IER register.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") 0x3F9u16, in("al") 0x01u8,
            options(nomem, nostack, preserves_flags));
    }
}
