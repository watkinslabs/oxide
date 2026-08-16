// I/O-APIC state across a sleep that loses controller context (`32a§7`).
//
// Two ordering rules, both load-bearing:
//
//   * A redirection entry is written HIGH half first. The mask bit lives in
//     the low half, so writing the low half last is what makes the entry go
//     live — with its destination already programmed. The other order puts a
//     live entry, briefly, on whatever destination survived the sleep.
//   * Masking an entry is the mirror: low half first, so the mask lands before
//     anything else about the entry changes.
//
// The identification register is rewritten only when the sleep changed it,
// because writing it is a bus-visible reconfiguration and firmware usually
// leaves it correct.

use alloc::vec::Vec;

use crate::apicdef::*;

/// An I/O-APIC's indirect register file.
pub trait IoapicRegs {
    /// Read the register at index `reg`. # C: O(1)
    fn read(&self, reg: u32) -> u32;
    /// Write `v` to the register at index `reg`. # C: O(1)
    fn write(&mut self, reg: u32, v: u32);
}

/// One redirection-table entry, as the two registers it occupies.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct RedirEntry { pub lo: u32, pub hi: u32 }

impl RedirEntry {
    /// Whether the entry is masked. # C: O(1)
    pub const fn masked(&self) -> bool { self.lo & IOAPIC_REDIR_MASKED != 0 }
}

/// Saved I/O-APIC state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IoapicState {
    /// The identification register's ID field, the value resume restores.
    pub id: u32,
    /// Every implemented redirection entry, by pin.
    pub entries: Vec<RedirEntry>,
}

/// Number of redirection entries this controller implements. # C: O(1)
pub fn pin_count<R: IoapicRegs>(r: &R) -> u32 { max_redir(r.read(IOAPIC_REG_VERSION)) + 1 }

/// Read every redirection entry and the identification register.
/// # C: O(N_pins)
/// # Ctx: IRQ-off, single-CPU
pub fn save<R: IoapicRegs>(r: &R) -> IoapicState {
    let n = pin_count(r);
    let mut entries = Vec::with_capacity(n as usize);
    for pin in 0..n {
        entries.push(RedirEntry { lo: r.read(redir_lo(pin)), hi: r.read(redir_hi(pin)) });
    }
    IoapicState { id: (r.read(IOAPIC_REG_ID) >> IOAPIC_ID_SHIFT) & IOAPIC_ID_MASK, entries }
}

/// Mask every entry that the saved snapshot shows unmasked, so no line is
/// delivered while the machine is on its way down. Works from the snapshot,
/// not from a fresh read, so it masks the configuration resume will restore.
/// # C: O(N_pins)
/// # Ctx: IRQ-off, single-CPU
pub fn mask_all<R: IoapicRegs>(r: &mut R, s: &IoapicState) {
    for (pin, e) in s.entries.iter().enumerate() {
        if e.masked() { continue; }
        let pin = pin as u32;
        r.write(redir_lo(pin), e.lo | IOAPIC_REDIR_MASKED);
        r.write(redir_hi(pin), e.hi);
    }
}

/// Rewrite the identification register if the sleep changed it. Returns
/// whether a write was needed.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
pub fn restore_id<R: IoapicRegs>(r: &mut R, s: &IoapicState) -> bool {
    let raw = r.read(IOAPIC_REG_ID);
    if (raw >> IOAPIC_ID_SHIFT) & IOAPIC_ID_MASK == s.id { return false; }
    let v = (raw & !(IOAPIC_ID_MASK << IOAPIC_ID_SHIFT)) | (s.id << IOAPIC_ID_SHIFT);
    r.write(IOAPIC_REG_ID, v);
    true
}

/// Put every saved redirection entry back, high half first.
/// # C: O(N_pins)
/// # Ctx: IRQ-off, single-CPU
pub fn restore_entries<R: IoapicRegs>(r: &mut R, s: &IoapicState) {
    for (pin, e) in s.entries.iter().enumerate() {
        let pin = pin as u32;
        r.write(redir_hi(pin), e.hi);
        r.write(redir_lo(pin), e.lo);
    }
}

/// The identification register first, then the routing. # C: O(N_pins)
/// # Ctx: IRQ-off, single-CPU
pub fn restore<R: IoapicRegs>(r: &mut R, s: &IoapicState) {
    restore_id(r, s);
    restore_entries(r, s);
}
