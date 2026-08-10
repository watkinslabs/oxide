// I/O APIC redirection-table programming (x86_64) per Intel 82093AA.
// MMIO is an indirect window: write the register index to IOREGSEL
// (offset 0x00), then read/write the 32-bit value at IOWIN (0x10).
// Each redirection entry is 64 bits = two consecutive registers
// (0x10+2n low, 0x11+2n high). Used to route legacy device IRQs
// (e.g. COM1 = IRQ4/GSI4) to LAPIC vectors — the real interrupt path.

use core::sync::atomic::{AtomicU64, Ordering};

/// Kernel VA the I/O APIC MMIO is Device-attr mapped at (0 = unmapped).
/// Published by the kernel after mapping `firmware::ioapic_pa()`.
static IOAPIC_VA: AtomicU64 = AtomicU64::new(0);
static VECTOR_PINS: [AtomicU64; 256] =
    [const { AtomicU64::new(0) }; 256];

const IOREGSEL: u64 = 0x00;
const IOWIN: u64 = 0x10;
/// Version register; bits 23:16 hold the highest redirection-entry index.
const IOAPIC_VER: u32 = 0x01;
/// Directly-addressed EOI register. Present from version 0x20 onwards; a
/// write of a vector retires that vector's level assertion on this device.
const IOWIN_EOI: u64 = 0x40;
/// Lowest version that implements [`IOWIN_EOI`].
const VER_WITH_EOI: u32 = 0x20;

/// Redirection-entry low-word bits.
const RTE_MASK: u32 = 1 << 16;
const RTE_LEVEL: u32 = 1 << 15;
/// Remote IRR — set while a level assertion is in service, cleared by an EOI.
const RTE_REMOTE_IRR: u32 = 1 << 14;
/// Delivery-mode field, bits 10:8.
const RTE_DELIVERY_MASK: u32 = 0x700;
/// Delivery mode 010 — system management interrupt. Such an entry belongs to
/// firmware and must be left exactly as found.
const RTE_DELIVERY_SMI: u32 = 2 << 8;
/// Vector field of a redirection entry.
const RTE_VECTOR_MASK: u32 = 0xFF;

/// Publish the I/O APIC MMIO kernel VA. # C: O(1)
pub fn set_base_va(va: u64) { IOAPIC_VA.store(va, Ordering::Release); }
/// Read the published I/O APIC VA (0 = unmapped). # C: O(1)
pub fn base_va() -> u64 { IOAPIC_VA.load(Ordering::Acquire) }

/// Forget a vector-to-pin route when the vector is released. # C: O(1)
pub fn unroute_vector(vector: u8) { VECTOR_PINS[vector as usize].store(0, Ordering::Release); }

fn route_vector(vector: u8, pin: u32) {
    VECTOR_PINS[vector as usize].store(u64::from(pin) + 1, Ordering::Release);
}

fn pin_for_vector(vector: u8) -> Option<u32> {
    let encoded = VECTOR_PINS[vector as usize].load(Ordering::Acquire);
    (encoded != 0).then_some((encoded.saturating_sub(1)) as u32)
}

/// # SAFETY: `IOAPIC_VA` is a live Device-attr mapping; single-CPU /
/// IRQ-off so the IOREGSEL→IOWIN pair is atomic w.r.t. other accessors.
unsafe fn read_reg(idx: u32) -> u32 {
    let va = IOAPIC_VA.load(Ordering::Acquire);
    // SAFETY: caller asserts VA is mapped; the index select + window
    // read is the architected I/O APIC access sequence.
    unsafe {
        core::ptr::write_volatile((va + IOREGSEL) as *mut u32, idx);
        core::ptr::read_volatile((va + IOWIN) as *const u32)
    }
}

/// # SAFETY: as `read_reg`.
unsafe fn write_reg(idx: u32, val: u32) {
    let va = IOAPIC_VA.load(Ordering::Acquire);
    // SAFETY: caller asserts VA is mapped; architected select+write.
    unsafe {
        core::ptr::write_volatile((va + IOREGSEL) as *mut u32, idx);
        core::ptr::write_volatile((va + IOWIN) as *mut u32, val);
    }
}

/// Program redirection entry `pin` (GSI relative to this I/O APIC's
/// gsi_base) to deliver `vector` to physical LAPIC `dest_apic` as a
/// Fixed interrupt. `level` = level-triggered (else edge); `active_low`
/// = polarity. The entry is left **unmasked**. The high word is written
/// first, then the low word (which carries the unmask), per the usual
/// "destination before enable" discipline.
///
/// # SAFETY: I/O APIC mapped via `set_base_va`; `vector` is a valid IDT
/// slot with an installed handler; single-CPU, IRQ-off boot context.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn program_redirect(
    pin: u32,
    vector: u8,
    dest_apic: u8,
    level: bool,
    active_low: bool,
) {
    let lo_idx = 0x10 + 2 * pin;
    let hi_idx = 0x11 + 2 * pin;
    // low: vector[7:0]; delivery=Fixed(000)@10:8; dest=physical(0)@11;
    // polarity@13; trigger@15; mask@16 (left 0 = unmasked).
    let mut lo: u32 = vector as u32;
    if active_low { lo |= 1 << 13; }
    if level { lo |= 1 << 15; }
    // high: destination APIC id in bits 56:63 → high-word bits 24:31.
    let hi: u32 = (dest_apic as u32) << 24;
    route_vector(vector, pin);
    // SAFETY: per fn contract — mapped MMIO; write destination, then unmask the routed pin.
    unsafe {
        write_reg(hi_idx, hi);
        write_reg(lo_idx, lo);
    }
}

/// Mask redirection entry `pin` (set bit 16 of its low word).
/// # SAFETY: as `program_redirect`. # C: O(1)
pub unsafe fn mask(pin: u32) {
    let lo_idx = 0x10 + 2 * pin;
    // SAFETY: per fn contract — mapped MMIO read-modify-write.
    unsafe {
        let lo = read_reg(lo_idx) | (1 << 16);
        write_reg(lo_idx, lo);
    }
}

/// Mask every redirection entry this I/O APIC implements.
///
/// The count comes from the version register's maximum-redirection-entry
/// field rather than a constant, because a constant would be right for one
/// platform and silently leave lines asserting on another. A no-op when no
/// I/O APIC has been mapped.
/// # SAFETY: as `program_redirect`. # C: O(pins)
pub unsafe fn mask_all() {
    if IOAPIC_VA.load(Ordering::Acquire) == 0 { return; }
    // SAFETY: per fn contract — the window is mapped; register 0x01 is the
    // architected version register.
    let maxred = unsafe { (read_reg(IOAPIC_VER) >> 16) & 0xff };
    for pin in 0..=maxred {
        // SAFETY: `pin` is within the entry count the device just reported.
        unsafe { mask(pin) };
    }
}

/// Retire an in-service level assertion on `pin`.
///
/// Two ways to do it, because only the newer device has the direct register:
/// write the pin's vector to the EOI register, or — where that does not exist
/// — briefly present the entry as edge triggered, which is what makes the
/// device drop the assertion it is holding.
/// # SAFETY: as `program_redirect`, and the entry is already masked.
unsafe fn eoi_pin(pin: u32, lo: u32) {
    let lo_idx = 0x10 + 2 * pin;
    // SAFETY: per fn contract — the window is mapped and `pin` is an implemented entry.
    unsafe {
        let ver = read_reg(IOAPIC_VER) & RTE_VECTOR_MASK;
        if ver >= VER_WITH_EOI {
            let va = IOAPIC_VA.load(Ordering::Acquire);
            core::ptr::write_volatile((va + IOWIN_EOI) as *mut u32, lo & RTE_VECTOR_MASK);
            return;
        }
        write_reg(lo_idx, lo & !RTE_LEVEL);
        write_reg(lo_idx, lo);
    }
}

/// Put every redirection entry back to the state a device that has never been
/// programmed presents: masked, no vector, no trigger mode, no destination.
///
/// Masking alone is not enough. A level-triggered line whose assertion is
/// still in service keeps its remote-IRR bit set, and the next kernel to
/// program that entry finds a line it can never receive — the device is
/// waiting for an acknowledgement from a driver that no longer exists. So each
/// entry is masked, its in-service assertion retired, and only then flattened.
///
/// Entries delivering system-management interrupts are left untouched: they
/// are firmware's, not this kernel's.
/// # SAFETY: as `program_redirect`; irreversible for this boot.
/// # C: O(pins)
pub unsafe fn clear_all() {
    if IOAPIC_VA.load(Ordering::Acquire) == 0 { return; }
    // SAFETY: the window is mapped; register 0x01 is the version register.
    let maxred = unsafe { (read_reg(IOAPIC_VER) >> 16) & 0xff };
    for pin in 0..=maxred {
        let lo_idx = 0x10 + 2 * pin;
        let hi_idx = 0x11 + 2 * pin;
        // SAFETY: `pin` is within the entry count the device just reported.
        unsafe {
            let mut lo = read_reg(lo_idx);
            if lo & RTE_DELIVERY_MASK == RTE_DELIVERY_SMI { continue; }
            if lo & RTE_MASK == 0 {
                write_reg(lo_idx, lo | RTE_MASK);
                lo = read_reg(lo_idx);
            }
            if lo & RTE_REMOTE_IRR != 0 { eoi_pin(pin, lo | RTE_LEVEL); }
            write_reg(hi_idx, 0);
            write_reg(lo_idx, RTE_MASK);
        }
    }
}

/// Mask the I/O APIC pin currently routed to `vector`, if any.
/// # SAFETY: the published route implies a live I/O APIC mapping.
/// # C: O(1)
pub unsafe fn mask_vector(vector: u8) {
    let Some(pin) = pin_for_vector(vector) else { return; };
    // SAFETY: `program_redirect` publishes the route before it unmasks the low word.
    unsafe { mask(pin); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_route_round_trips_every_pin_bit() {
        let vector = 0x71;
        route_vector(vector, u32::MAX);
        assert_eq!(pin_for_vector(vector), Some(u32::MAX));
        unroute_vector(vector);
        assert_eq!(pin_for_vector(vector), None);
    }
}
