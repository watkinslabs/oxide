// I/O-APIC save/restore (`32a§7`). The round trip, plus the two ordering
// rules that decide whether an entry is ever briefly live on a stale
// destination: high half before low on restore, low half before high on mask.

use alloc::vec::Vec;

use crate::apicdef::*;
use crate::pm::ioapic_state::*;

const PINS: u32 = 24;

#[derive(Default)]
struct Fake { cells: Vec<(u32, u32)>, writes: Vec<(u32, u32)> }

impl Fake {
    fn populated() -> Self {
        let mut f = Fake::default();
        f.set(IOAPIC_REG_VERSION, ((PINS - 1) << 16) | 0x20);
        f.set(IOAPIC_REG_ID, 0x0200_0000);
        for pin in 0..PINS {
            // Alternate masked and live so both branches of `mask_all` run.
            let masked = if pin % 2 == 0 { IOAPIC_REDIR_MASKED } else { 0 };
            f.set(redir_lo(pin), 0x0000_0020 + pin | masked);
            f.set(redir_hi(pin), (pin + 1) << 24);
        }
        f
    }
    fn set(&mut self, reg: u32, v: u32) {
        match self.cells.iter_mut().find(|(r, _)| *r == reg) {
            Some(c) => c.1 = v,
            None => self.cells.push((reg, v)),
        }
    }
    fn get(&self, reg: u32) -> u32 {
        self.cells.iter().find(|(r, _)| *r == reg).map(|(_, v)| *v).unwrap_or(0)
    }
    fn table(&self) -> Vec<(u32, u32)> {
        (0..PINS).map(|p| (self.get(redir_lo(p)), self.get(redir_hi(p)))).collect()
    }
    fn clobber(&mut self) {
        for pin in 0..PINS { self.set(redir_lo(pin), 0xFFFF_FFFF); self.set(redir_hi(pin), 0); }
    }
}

impl IoapicRegs for Fake {
    fn read(&self, reg: u32) -> u32 { self.get(reg) }
    fn write(&mut self, reg: u32, v: u32) { self.writes.push((reg, v)); self.set(reg, v); }
}

#[test]
fn the_implemented_pin_count_comes_from_the_version_register() {
    let f = Fake::populated();
    assert_eq!(pin_count(&f), PINS);
    assert_eq!(max_redir(((PINS - 1) << 16) | 0x20), PINS - 1);
}

#[test]
fn a_save_restore_round_trip_reproduces_every_redirection_entry() {
    let mut f = Fake::populated();
    let before = f.table();
    let s = save(&f);
    assert_eq!(s.entries.len(), PINS as usize);
    f.clobber();
    assert_ne!(f.table(), before);
    restore(&mut f, &s);
    assert_eq!(f.table(), before);
}

#[test]
fn the_identification_register_is_saved_and_put_back_when_the_sleep_changed_it() {
    let mut f = Fake::populated();
    let s = save(&f);
    assert_eq!(s.id, 2);
    f.set(IOAPIC_REG_ID, 0x0700_0000);
    assert!(restore_id(&mut f, &s), "a changed identification must be rewritten");
    assert_eq!((f.get(IOAPIC_REG_ID) >> IOAPIC_ID_SHIFT) & IOAPIC_ID_MASK, 2);
}

#[test]
fn the_identification_register_is_left_alone_when_the_sleep_preserved_it() {
    let mut f = Fake::populated();
    let s = save(&f);
    f.writes.clear();
    assert!(!restore_id(&mut f, &s));
    assert!(f.writes.is_empty(), "an unchanged identification must not be rewritten");
}

#[test]
fn restoring_the_identification_preserves_the_registers_other_fields() {
    let mut f = Fake::populated();
    let s = save(&f);
    f.set(IOAPIC_REG_ID, 0x0700_0000 | 0x0000_00AA);
    restore_id(&mut f, &s);
    assert_eq!(f.get(IOAPIC_REG_ID) & 0x0000_00FF, 0xAA);
}

#[test]
fn an_entry_is_restored_high_half_first() {
    let mut f = Fake::populated();
    let s = save(&f);
    f.writes.clear();
    restore_entries(&mut f, &s);
    for pin in 0..PINS {
        let hi = f.writes.iter().position(|(r, _)| *r == redir_hi(pin)).unwrap();
        let lo = f.writes.iter().position(|(r, _)| *r == redir_lo(pin)).unwrap();
        assert!(hi < lo, "pin {pin}: the mask bit lives in the low half, so it is written last");
    }
}

#[test]
fn the_identification_register_precedes_the_routing_table() {
    let mut f = Fake::populated();
    let s = save(&f);
    f.set(IOAPIC_REG_ID, 0x0700_0000);
    f.writes.clear();
    restore(&mut f, &s);
    assert_eq!(f.writes[0].0, IOAPIC_REG_ID);
}

#[test]
fn masking_touches_only_the_entries_that_were_live_and_writes_the_mask_first() {
    let mut f = Fake::populated();
    let s = save(&f);
    f.writes.clear();
    mask_all(&mut f, &s);
    for pin in 0..PINS {
        let touched = f.writes.iter().any(|(r, _)| *r == redir_lo(pin));
        assert_eq!(touched, pin % 2 == 1, "pin {pin}: an already-masked entry needs no write");
        if !touched { continue; }
        let lo = f.writes.iter().position(|(r, _)| *r == redir_lo(pin)).unwrap();
        let hi = f.writes.iter().position(|(r, _)| *r == redir_hi(pin)).unwrap();
        assert!(lo < hi, "pin {pin}: the mask must land before anything else changes");
        assert_ne!(f.get(redir_lo(pin)) & IOAPIC_REDIR_MASKED, 0);
    }
}

#[test]
fn masking_does_not_disturb_what_the_resume_restores() {
    let mut f = Fake::populated();
    let before = f.table();
    let s = save(&f);
    mask_all(&mut f, &s);
    restore(&mut f, &s);
    assert_eq!(f.table(), before);
}

#[test]
fn a_controller_with_one_pin_still_round_trips() {
    let mut f = Fake::default();
    f.set(IOAPIC_REG_VERSION, 0x20);
    f.set(redir_lo(0), 0x1234);
    f.set(redir_hi(0), 0x5678);
    let s = save(&f);
    assert_eq!(s.entries.len(), 1);
    f.set(redir_lo(0), 0);
    f.set(redir_hi(0), 0);
    restore(&mut f, &s);
    assert_eq!((f.get(redir_lo(0)), f.get(redir_hi(0))), (0x1234, 0x5678));
}

#[test]
fn the_entry_register_indices_are_two_apart_starting_at_the_table_base() {
    assert_eq!(redir_lo(0), IOAPIC_REG_REDIR_BASE);
    assert_eq!(redir_hi(0), IOAPIC_REG_REDIR_BASE + 1);
    assert_eq!(redir_lo(23), IOAPIC_REG_REDIR_BASE + 46);
}
