// IRQ1 ownership: I/O APIC redirection programming and the IRQ-context drain
// that feeds scancodes into the ONE shared input pipeline.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::scancode::decode_byte;

use super::bringup::{
    set_controller_aux_irq, set_controller_irq, take_and_free_aux_vector,
    take_and_free_vector, take_and_mask_aux_pin, take_and_mask_pin,
};
use super::ports::inb;
use super::regs::*;
use super::state::*;

/// Drain pending scancode bytes from IRQ context into the shared input
/// pipeline. Bounded so one IRQ cannot starve the CPU.
/// # SAFETY: IRQ context with the i8042 line owned by this driver.
/// # C: O(bytes pending), <= 64 per interrupt.
pub(super) unsafe fn drain_irq() -> bool {
    if !present() || (!irq_enabled() && !AUX_IRQ_ENABLED.load(Ordering::Acquire)) {
        return false;
    }
    let mut n = 0u32;
    loop {
        // SAFETY: reading the i8042 status register (0x64) at CPL=0 has no side effect.
        let status = unsafe { inb(CMD) };
        if status & STS_OUTPUT_FULL == 0 {
            break;
        }
        // SAFETY: output-buffer-full => a scancode byte is present at the data port (0x60).
        let byte = unsafe { inb(DATA) };
        if status & STS_AUX_DATA == 0 {
            if irq_enabled() {
                if let Some((keycode, pressed)) = decode_byte(byte) {
                    super::keyboard::report_key(keycode, pressed);
                    drv_virtio_input::drain::handle_key_event(keycode, pressed);
                }
            }
        } else if AUX_IRQ_ENABLED.load(Ordering::Acquire) {
            super::mouse::handle_aux_byte(byte);
        }
        n += 1;
        if n >= DRAIN_MAX_BYTES {
            break;
        }
    }
    n != 0
}

type LineHandler = fn(u32) -> arch_irq::IrqReport;

/// Allocate, bind, and unmask one legacy i8042 I/O-APIC redirection. Both
/// controller ports use the same Linux-shaped line lifecycle; only their GSI,
/// handler, and published ownership slots differ.
/// # SAFETY: caller owns the i8042 probe window and the controller is quiesced.
/// # C: O(1)
unsafe fn install_line(
    isa_irq: u8,
    fallback_gsi: u32,
    handler: LineHandler,
    vector: &AtomicU64,
    pin_slot: &AtomicU64,
) -> bool {
    let ioapic_pa = firmware::ioapic_pa();
    if ioapic_pa == 0 { return false; }
    let mut ioapic_va = hal_x86_64::ioapic::base_va();
    if ioapic_va == 0 {
        let dev_window_base = DEVICE_WINDOW_BASE.load(Ordering::Acquire);
        if dev_window_base == 0 { return false; }
        ioapic_va = dev_window_base | (ioapic_pa & DEVICE_WINDOW_PA_MASK);
        let pf = hal::PageFlags::READ
            | hal::PageFlags::WRITE
            | hal::PageFlags::NO_CACHE
            | hal::PageFlags::WRITE_THROUGH;
        // SAFETY: device-window VA is disjoint from RAM; firmware supplied the
        // I/O-APIC PA and the single probe owner installs its first mapping.
        unsafe {
            <hal_x86_64::mmu_ops::X86Mmu as hal::MmuOps>::map(
                hal::Va(ioapic_va), hal::Pa(ioapic_pa), pf, hal::PageSize::P4K,
            );
        }
        hal_x86_64::ioapic::set_base_va(ioapic_va);
    }
    let Some(vec) = arch_irq::alloc_x86_vector() else { return false; };
    if arch_irq::register_irq_line_handler(vec as u32, handler).is_err() {
        let _ = arch_irq::free_x86_vector(vec);
        return false;
    }
    let gsi = firmware::legacy_irq_gsi(isa_irq).unwrap_or(fallback_gsi);
    let base = firmware::ioapic_gsi_base();
    if gsi < base {
        let _ = arch_irq::free_x86_vector(vec);
        return false;
    }
    let pin = gsi - base;
    let flags = firmware::legacy_irq_flags(isa_irq).unwrap_or(0);
    let active_low = (flags & MADT_FLAG_MASK) == MADT_POLARITY_ACTIVE_LOW;
    let level = ((flags >> MADT_TRIGGER_SHIFT) & MADT_FLAG_MASK) == MADT_TRIGGER_LEVEL;
    let bsp_apic = BSP_APIC_ID.load(Ordering::Acquire) as u8;
    // SAFETY: a handler owns `vec`, the I/O-APIC window is mapped, and this
    // probe owns the line until the matching published pin is taken.
    if !unsafe { arch_irq::program_x86_ioapic(pin, vec, u32::from(bsp_apic), level, active_low) } {
        let _ = arch_irq::free_x86_vector(vec);
        return false;
    }
    vector.store(vec as u64, Ordering::Release);
    pin_slot.store(pin as u64, Ordering::Release);
    true
}

fn irq1_handler(_irq: u32) -> arch_irq::IrqReport {
    // SAFETY: installed only after probe owns IRQ1 and maps the I/O APIC.
    arch_irq::IrqReport::hard(if unsafe { drain_irq() } {
        arch_irq::IrqRet::Handled
    } else {
        arch_irq::IrqRet::NotMine
    })
}

fn irq12_handler(_irq: u32) -> arch_irq::IrqReport {
    // Both legacy lines feed the same i8042 output buffer; AUX classification
    // remains the status-bit decision in `drain_irq`.
    // SAFETY: as `irq1_handler` — this handler is installed only by `install_irq`,
    // which runs after probe has taken the i8042 and routed both legacy pins.
    arch_irq::IrqReport::hard(if unsafe { drain_irq() } {
        arch_irq::IrqRet::Handled
    } else {
        arch_irq::IrqRet::NotMine
    })
}

/// Program IRQ1 through the I/O APIC and enable the controller IRQ bit.
/// # SAFETY: called from driver probe after i8042 bring-up, IRQs masked.
/// # C: O(1)
pub(super) unsafe fn install_irq() -> bool {
    // SAFETY: this probe owns the i8042 IRQ1 route and its vector storage.
    if !unsafe { install_line(KBD_ISA_IRQ, KBD_ISA_IRQ_GSI, irq1_handler, &IRQ_VEC, &IRQ_PIN) } {
        return false;
    }
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

/// Program IRQ12 only after the platform mouse has a live canonical input
/// sink. Failure leaves IRQ1 intact and the auxiliary controller bit masked.
/// # SAFETY: called from the i8042 probe window after `install_device` succeeds.
/// # C: O(1)
pub(super) unsafe fn install_aux_irq() -> bool {
    // SAFETY: this probe owns the i8042 IRQ12 route and its vector storage.
    if !unsafe { install_line(AUX_ISA_IRQ, AUX_ISA_IRQ_GSI, irq12_handler, &AUX_IRQ_VEC, &AUX_IRQ_PIN) } {
        return false;
    }
    // SAFETY: the IRQ12 handler, vector, redirection, and input sink are live.
    if !unsafe { set_controller_aux_irq(true) } {
        AUX_IRQ_ENABLED.store(false, Ordering::Release);
        take_and_mask_aux_pin();
        take_and_free_aux_vector();
        return false;
    }
    AUX_IRQ_ENABLED.store(true, Ordering::Release);
    // SAFETY: the auxiliary line can now deliver to `drain_irq` safely.
    unsafe { drain_irq(); }
    true
}
