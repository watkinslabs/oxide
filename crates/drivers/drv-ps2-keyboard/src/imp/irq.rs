// IRQ1 ownership: I/O APIC redirection programming and the IRQ-context drain
// that feeds scancodes into the ONE shared input pipeline.

use core::sync::atomic::Ordering;

use crate::scancode::decode_byte;

use super::bringup::{set_controller_irq, take_and_free_vector, take_and_mask_pin};
use super::ports::inb;
use super::regs::*;
use super::state::*;

/// Drain pending scancode bytes from IRQ context into the shared input
/// pipeline. Bounded so one IRQ cannot starve the CPU.
/// # SAFETY: IRQ context with the i8042 line owned by this driver.
/// # C: O(bytes pending), <= 64 per interrupt.
pub(super) unsafe fn drain_irq() {
    if !present() || !irq_enabled() {
        return;
    }
    let mut n = 0u32;
    loop {
        // SAFETY: reading the i8042 status register (0x64) at CPL=0 has no side effect.
        if unsafe { inb(CMD) } & STS_OUTPUT_FULL == 0 {
            break;
        }
        // SAFETY: output-buffer-full => a scancode byte is present at the data port (0x60).
        let byte = unsafe { inb(DATA) };
        if let Some((keycode, pressed)) = decode_byte(byte) {
            drv_virtio_input::drain::handle_key_event(keycode, pressed);
        }
        n += 1;
        if n >= DRAIN_MAX_BYTES {
            break;
        }
    }
}

fn irq1_handler() {
    // SAFETY: installed only after probe owns IRQ1 and maps the I/O APIC.
    unsafe { drain_irq(); }
}

/// Program IRQ1 through the I/O APIC and enable the controller IRQ bit.
/// # SAFETY: called from driver probe after i8042 bring-up, IRQs masked.
/// # C: O(1)
pub(super) unsafe fn install_irq() -> bool {
    let ioapic_pa = firmware::ioapic_pa();
    if ioapic_pa == 0 {
        return false;
    }
    let mut ioapic_va = hal_x86_64::ioapic::base_va();
    if ioapic_va == 0 {
        let dev_window_base = DEVICE_WINDOW_BASE.load(Ordering::Acquire);
        if dev_window_base == 0 {
            return false;
        }
        ioapic_va = dev_window_base | (ioapic_pa & DEVICE_WINDOW_PA_MASK);
        let pf = hal::PageFlags::READ
            | hal::PageFlags::WRITE
            | hal::PageFlags::NO_CACHE
            | hal::PageFlags::WRITE_THROUGH;
        // SAFETY: device-window VA disjoint from RAM; ioapic_pa is the MADT base; single-CPU probe.
        unsafe {
            <hal_x86_64::mmu_ops::X86Mmu as hal::MmuOps>::map(
                hal::Va(ioapic_va),
                hal::Pa(ioapic_pa),
                pf,
                hal::PageSize::P4K,
            );
        }
        hal_x86_64::ioapic::set_base_va(ioapic_va);
    }

    let vec = match arch_irq::alloc_x86_vector() {
        Some(v) => v,
        None => return false,
    };
    if arch_irq::register_msi_handler(vec, irq1_handler).is_err() {
        let _ = arch_irq::free_x86_vector(vec);
        return false;
    }
    let gsi = firmware::legacy_irq_gsi(KBD_ISA_IRQ).unwrap_or(KBD_ISA_IRQ_GSI);
    let base = firmware::ioapic_gsi_base();
    if gsi < base {
        let _ = arch_irq::free_x86_vector(vec);
        return false;
    }
    let pin = gsi - base;
    let flags = firmware::legacy_irq_flags(KBD_ISA_IRQ).unwrap_or(0);
    let active_low = (flags & MADT_FLAG_MASK) == MADT_POLARITY_ACTIVE_LOW;
    let level = ((flags >> MADT_TRIGGER_SHIFT) & MADT_FLAG_MASK) == MADT_TRIGGER_LEVEL;
    let bsp_apic = BSP_APIC_ID.load(Ordering::Acquire) as u8;
    // SAFETY: I/O APIC mapped; vector has a registered handler; probe owns IRQ1 setup.
    unsafe { hal_x86_64::ioapic::program_redirect(pin, vec, bsp_apic, level, active_low); }
    IRQ_VEC.store(vec as u64, Ordering::Release);
    IRQ_PIN.store(pin as u64, Ordering::Release);
    // SAFETY: the IRQ handler/vector/redirection entry are installed.
    if !unsafe { set_controller_irq(true) } {
        IRQ_ENABLED.store(false, Ordering::Release);
        take_and_mask_pin();
        take_and_free_vector();
        return false;
    }
    IRQ_ENABLED.store(true, Ordering::Release);
    // Drain any byte that arrived between scan enable and IRQ enable.
    // SAFETY: `IRQ_ENABLED` and `PRESENT` are now both published, the
    // redirection entry points at `irq1_handler`, and this driver is the sole
    // owner of 0x60/0x64 — the same state a real IRQ1 delivery would run under.
    unsafe { drain_irq(); }
    true
}
