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
const MAX_IOAPICS: usize = 8;
static IOAPIC_VAS: [AtomicU64; MAX_IOAPICS] = [const { AtomicU64::new(0) }; MAX_IOAPICS];
static IOAPIC_GSI_BASES: [AtomicU64; MAX_IOAPICS] = [const { AtomicU64::new(0) }; MAX_IOAPICS];
static IOAPIC_IDS: [AtomicU64; MAX_IOAPICS] = [const { AtomicU64::new(u64::MAX) }; MAX_IOAPICS];
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
/// Remappable-format marker in redirection-entry bit 48.
const RTE_REMAP_FORMAT: u32 = 1 << 16;
/// Lower 15 bits of the interrupt-remapping table index occupy bits 49:63.
const RTE_REMAP_INDEX_SHIFT: u32 = 17;
/// The final interrupt-remapping table-index bit occupies RTE bit 11.
const RTE_REMAP_INDEX_HIGH: u32 = 1 << 11;

/// Publish the I/O APIC MMIO kernel VA. # C: O(1)
pub fn set_base_va(va: u64) {
    IOAPIC_VA.store(va, Ordering::Release);
    IOAPIC_VAS[0].store(va, Ordering::Release);
}
/// Read the published I/O APIC VA (0 = unmapped). # C: O(1)
pub fn base_va() -> u64 { IOAPIC_VA.load(Ordering::Acquire) }

/// Publish a mapped I/O APIC selected by the GSI base declared in MADT.
/// # C: O(N_IOAPIC)
pub fn set_gsi_base_va(id: u8, gsi_base: u32, va: u64) -> bool {
    if va == 0 { return false; }
    for index in 0..MAX_IOAPICS {
        let base = IOAPIC_GSI_BASES[index].load(Ordering::Acquire);
        if base == u64::from(gsi_base) {
            IOAPIC_IDS[index].store(u64::from(id), Ordering::Release);
            IOAPIC_VAS[index].store(va, Ordering::Release);
            if index == 0 { IOAPIC_VA.store(va, Ordering::Release); }
            return true;
        }
        if base == 0 && IOAPIC_GSI_BASES[index].compare_exchange(0, u64::from(gsi_base), Ordering::AcqRel, Ordering::Acquire).is_ok() {
            IOAPIC_IDS[index].store(u64::from(id), Ordering::Release);
            IOAPIC_VAS[index].store(va, Ordering::Release);
            if index == 0 { IOAPIC_VA.store(va, Ordering::Release); }
            return true;
        }
    }
    false
}

/// Forget a vector-to-pin route when the vector is released. # C: O(1)
pub fn unroute_vector(vector: u8) { VECTOR_PINS[vector as usize].store(0, Ordering::Release); }

fn route_vector(vector: u8, va: u64, pin: u32) {
    let Some(index) = (0..MAX_IOAPICS).find(|index| IOAPIC_VAS[*index].load(Ordering::Acquire) == va) else { return; };
    VECTOR_PINS[vector as usize].store(((index as u64 + 1) << 32) | (u64::from(pin) + 1), Ordering::Release);
}

fn pin_for_vector(vector: u8) -> Option<(u64, u32)> {
    let encoded = VECTOR_PINS[vector as usize].load(Ordering::Acquire);
    if encoded == 0 { return None; }
    let index = ((encoded >> 32).checked_sub(1)?) as usize;
    let pin = (encoded as u32).checked_sub(1)?;
    Some((IOAPIC_VAS.get(index)?.load(Ordering::Acquire), pin))
}

/// # SAFETY: `IOAPIC_VA` is a live Device-attr mapping; single-CPU /
/// IRQ-off so the IOREGSEL→IOWIN pair is atomic w.r.t. other accessors.
unsafe fn read_reg(idx: u32) -> u32 {
    let va = IOAPIC_VA.load(Ordering::Acquire);
    // SAFETY: the first published I/O APIC VA is live under this caller's serialization.
    unsafe { read_reg_at(va, idx) }
}

/// # SAFETY: `va` names one live Device-attr I/O APIC mapping and the caller
/// serializes the indirect selector/window pair. # C: O(1)
unsafe fn read_reg_at(va: u64, idx: u32) -> u32 {
    // SAFETY: caller asserts VA is mapped; the index select + window
    // read is the architected I/O APIC access sequence.
    unsafe {
        core::ptr::write_volatile((va + IOREGSEL) as *mut u32, idx);
        core::ptr::read_volatile((va + IOWIN) as *const u32)
    }
}

/// # SAFETY: as [`read_reg_at`]. # C: O(1)
unsafe fn write_reg_at(va: u64, idx: u32, val: u32) {
    // SAFETY: caller asserts VA is mapped; architected select+write.
    unsafe {
        core::ptr::write_volatile((va + IOREGSEL) as *mut u32, idx);
        core::ptr::write_volatile((va + IOWIN) as *mut u32, val);
    }
}

/// Return whether `pin` is implemented by the published I/O APIC.
///
/// # SAFETY: the caller provides the same I/O-APIC serialization as a
/// redirection-table programming operation. # C: O(1)
pub unsafe fn has_pin(pin: u32) -> bool {
    if IOAPIC_VA.load(Ordering::Acquire) == 0 { return false; }
    // SAFETY: the published MMIO window is live and the caller serializes the
    // indirect IOREGSEL/IOWIN pair.
    let highest = unsafe { (read_reg(IOAPIC_VER) >> 16) & 0xff };
    pin <= highest
}

/// Return the mapped I/O APIC and local pin that own `gsi`.
///
/// # SAFETY: caller serializes I/O-APIC indirect register accesses. # C: O(N_IOAPIC)
pub unsafe fn gsi_pin(gsi: u32) -> Option<(u8, u64, u32)> {
    for index in 0..MAX_IOAPICS {
        let va = IOAPIC_VAS[index].load(Ordering::Acquire);
        if va == 0 { continue; }
        let base = IOAPIC_GSI_BASES[index].load(Ordering::Acquire) as u32;
        let Some(pin) = gsi.checked_sub(base) else { continue; };
        // SAFETY: `va` is published only after a complete Device MMIO map.
        let highest = unsafe { (read_reg_at(va, IOAPIC_VER) >> 16) & 0xff };
        if pin <= highest {
            let id = u8::try_from(IOAPIC_IDS[index].load(Ordering::Acquire)).ok()?;
            return Some((id, va, pin));
        }
    }
    None
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
    let va = IOAPIC_VA.load(Ordering::Acquire);
    // SAFETY: this wrapper preserves the documented first-I/O-APIC contract.
    unsafe { program_redirect_at(va, pin, vector, dest_apic, level, active_low); }
}

/// Program one selected controller entry directly.
/// # SAFETY: `va` names the selected live I/O APIC and `pin` is implemented.
/// # C: O(1)
pub unsafe fn program_redirect_at(va: u64, pin: u32, vector: u8, dest_apic: u8,
    level: bool, active_low: bool) {
    let lo_idx = 0x10 + 2 * pin;
    let hi_idx = 0x11 + 2 * pin;
    // low: vector[7:0]; delivery=Fixed(000)@10:8; dest=physical(0)@11;
    // polarity@13; trigger@15; mask@16 (left 0 = unmasked).
    let mut lo: u32 = vector as u32;
    if active_low { lo |= 1 << 13; }
    if level { lo |= 1 << 15; }
    // high: destination APIC id in bits 56:63 → high-word bits 24:31.
    let hi: u32 = (dest_apic as u32) << 24;
    route_vector(vector, va, pin);
    // SAFETY: per fn contract — mapped MMIO; write destination, then unmask the routed pin.
    unsafe {
        write_reg_at(va, hi_idx, hi);
        write_reg_at(va, lo_idx, lo);
    }
}

/// Program an AMD-Vi-remapped source whose wire vector is its IRTE index.
/// # SAFETY: `va` names the selected live I/O APIC and the IRTE is already live.
/// # C: O(1)
pub unsafe fn program_amd_remapped_redirect_at(va: u64, pin: u32, handler_vector: u8,
    irte_index: u8, level: bool, active_low: bool) {
    let lo_idx = 0x10 + 2 * pin;
    let hi_idx = 0x11 + 2 * pin;
    let mut lo = u32::from(irte_index);
    if active_low { lo |= 1 << 13; }
    if level { lo |= RTE_LEVEL; }
    route_vector(handler_vector, va, pin);
    // SAFETY: the IOMMU invalidated the IRTE before this source-side unmask.
    unsafe {
        write_reg_at(va, hi_idx, 0);
        write_reg_at(va, lo_idx, lo);
    }
}

fn remapped_redirect_words(pin: u32, index: u16, level: bool, active_low: bool) -> Option<(u32, u32)> {
    let subhandle = u8::try_from(pin).ok()?;
    let mut lo = u32::from(subhandle);
    if active_low { lo |= 1 << 13; }
    if level { lo |= RTE_LEVEL; }
    if index & (1 << 15) != 0 { lo |= RTE_REMAP_INDEX_HIGH; }
    let hi = RTE_REMAP_FORMAT | (u32::from(index & 0x7fff) << RTE_REMAP_INDEX_SHIFT);
    Some((lo, hi))
}

/// Program one redirection entry in interrupt-remappable format.  The
/// caller has already published and invalidated `index` in the owning IOMMU;
/// this operation only changes the IOAPIC's source-side message encoding.
///
/// # SAFETY: I/O APIC mapped via `set_base_va`; `vector` has an installed
/// handler; `index` is a live IRTE owned by the IOAPIC source; single-CPU,
/// IRQ-off boot context.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn program_remapped_redirect(
    pin: u32,
    vector: u8,
    index: u16,
    level: bool,
    active_low: bool,
) -> bool {
    let va = IOAPIC_VA.load(Ordering::Acquire);
    // SAFETY: this wrapper preserves the documented first-I/O-APIC contract.
    unsafe { program_remapped_redirect_at(va, pin, vector, index, level, active_low) }
}

/// Program one selected controller entry in remappable format.
/// # SAFETY: `va` names the selected live I/O APIC and `index` names a live IRTE.
/// # C: O(1)
pub unsafe fn program_remapped_redirect_at(va: u64, pin: u32, vector: u8, index: u16,
    level: bool, active_low: bool) -> bool {
    let Some((lo, hi)) = remapped_redirect_words(pin, index, level, active_low) else { return false; };
    let lo_idx = 0x10 + 2 * pin;
    let hi_idx = 0x11 + 2 * pin;
    route_vector(vector, va, pin);
    // SAFETY: per fn contract — the live IRTE precedes this source-side unmask.
    unsafe {
        write_reg_at(va, hi_idx, hi);
        write_reg_at(va, lo_idx, lo);
    }
    true
}

/// Mask redirection entry `pin` (set bit 16 of its low word).
/// # SAFETY: as `program_redirect`. # C: O(1)
pub unsafe fn mask(pin: u32) {
    let va = IOAPIC_VA.load(Ordering::Acquire);
    // SAFETY: this wrapper preserves the documented first-I/O-APIC contract.
    unsafe { mask_at(va, pin); }
}

/// # SAFETY: `va` names the selected live I/O APIC and `pin` is implemented.
unsafe fn mask_at(va: u64, pin: u32) {
    let lo_idx = 0x10 + 2 * pin;
    // SAFETY: per fn contract — mapped MMIO read-modify-write.
    unsafe {
        let lo = read_reg_at(va, lo_idx) | (1 << 16);
        write_reg_at(va, lo_idx, lo);
    }
}

/// Retire an in-service level assertion on `pin`.
///
/// Two ways to do it, because only the newer device has the direct register:
/// write the pin's vector to the EOI register, or — where that does not exist
/// — briefly present the entry as edge triggered, which is what makes the
/// device drop the assertion it is holding.
/// # SAFETY: `va` names the selected live I/O APIC and `pin` is implemented.
unsafe fn eoi_pin_at(va: u64, pin: u32, lo: u32) {
    let lo_idx = 0x10 + 2 * pin;
    // SAFETY: per fn contract — the window is mapped and `pin` is an implemented entry.
    unsafe {
        let ver = read_reg_at(va, IOAPIC_VER) & RTE_VECTOR_MASK;
        if ver >= VER_WITH_EOI {
            core::ptr::write_volatile((va + IOWIN_EOI) as *mut u32, lo & RTE_VECTOR_MASK);
            return;
        }
        write_reg_at(va, lo_idx, lo & !RTE_LEVEL);
        write_reg_at(va, lo_idx, lo);
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
    for index in 0..MAX_IOAPICS {
        let va = IOAPIC_VAS[index].load(Ordering::Acquire);
        if va == 0 { continue; }
        // SAFETY: the published controller window is mapped and serialized by caller.
        unsafe { clear_at(va); }
    }
}

/// # SAFETY: `va` names a live I/O APIC mapping under caller serialization.
unsafe fn clear_at(va: u64) {
    let maxred = unsafe { (read_reg_at(va, IOAPIC_VER) >> 16) & 0xff };
    for pin in 0..=maxred {
        let lo_idx = 0x10 + 2 * pin;
        let hi_idx = 0x11 + 2 * pin;
        // SAFETY: `pin` is within the entry count the device just reported.
        unsafe {
            let mut lo = read_reg_at(va, lo_idx);
            if lo & RTE_DELIVERY_MASK == RTE_DELIVERY_SMI { continue; }
            if lo & RTE_MASK == 0 {
                write_reg_at(va, lo_idx, lo | RTE_MASK);
                lo = read_reg_at(va, lo_idx);
            }
            if lo & RTE_REMOTE_IRR != 0 { eoi_pin_at(va, pin, lo | RTE_LEVEL); }
            write_reg_at(va, hi_idx, 0);
            write_reg_at(va, lo_idx, RTE_MASK);
        }
    }
}

/// Mask the I/O APIC pin currently routed to `vector`, if any.
/// # SAFETY: the published route implies a live I/O APIC mapping.
/// # C: O(1)
pub unsafe fn mask_vector(vector: u8) {
    let Some((va, pin)) = pin_for_vector(vector) else { return; };
    // SAFETY: `program_redirect` publishes the route before it unmasks the low word.
    unsafe { mask_at(va, pin); }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_route_round_trips_every_pin_bit() {
        let vector = 0x71;
        let va = 0xfee0_0000;
        IOAPIC_VAS[0].store(va, Ordering::Release);
        route_vector(vector, va, u32::MAX);
        assert_eq!(pin_for_vector(vector), Some((va, u32::MAX)));
        unroute_vector(vector);
        assert_eq!(pin_for_vector(vector), None);
    }

    #[test]
    fn remapped_rte_uses_pin_subhandle_and_split_irte_index() {
        assert_eq!(remapped_redirect_words(0x34, 0x9234, true, true),
            Some((0x0000_a834, 0x2469_0000)));
        assert_eq!(remapped_redirect_words(256, 0, false, false), None);
    }
}
