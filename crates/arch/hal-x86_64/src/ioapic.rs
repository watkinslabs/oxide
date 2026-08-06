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
