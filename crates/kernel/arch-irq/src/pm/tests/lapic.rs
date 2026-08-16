// Local-APIC save/restore (`32a§7`). The round trip is the headline: fill the
// window with a synthetic register set, save it, clobber every register,
// restore, and require equality. The ordering assertions are separate, because
// a restore can be value-correct and order-wrong, and the order is what keeps
// the APIC from delivering through a half-programmed configuration.

use alloc::vec::Vec;

use crate::apicdef::*;
use crate::pm::lapic_state::*;

/// The registers a save reads and a restore writes, by offset.
const WINDOW: [usize; 15] = [
    REG_VERSION, REG_ID, REG_TASKPRI, REG_LDR, REG_DFR, REG_SVR, REG_LVT_TIMER,
    REG_LVT_PERF, REG_LVT_LINT0, REG_LVT_LINT1, REG_LVT_ERROR, REG_TIMER_INIT,
    REG_TIMER_DIV, REG_LVT_THERMAL, REG_LVT_CMCI,
];

#[derive(Default)]
struct Fake {
    cells: Vec<(usize, u32)>,
    writes: Vec<(usize, u32)>,
}

impl Fake {
    fn with_maxlvt(n: u32) -> Self {
        let mut f = Fake::default();
        f.set(REG_VERSION, n << VERSION_MAXLVT_SHIFT);
        // A distinguishable value per register, so a restore that writes the
        // right count of the wrong values still fails.
        for (i, off) in WINDOW.iter().enumerate() {
            if *off == REG_VERSION { continue; }
            f.set(*off, 0x1000_0000 + i as u32);
        }
        f
    }
    fn set(&mut self, off: usize, v: u32) {
        match self.cells.iter_mut().find(|(o, _)| *o == off) {
            Some(c) => c.1 = v,
            None => self.cells.push((off, v)),
        }
    }
    fn get(&self, off: usize) -> u32 {
        self.cells.iter().find(|(o, _)| *o == off).map(|(_, v)| *v).unwrap_or(0)
    }
    fn clobber(&mut self) {
        for (o, v) in self.cells.iter_mut() { if *o != REG_VERSION { *v = 0xDEAD_BEEF; } }
    }
    fn snapshot(&self) -> Vec<(usize, u32)> {
        let mut s: Vec<(usize, u32)> = WINDOW.iter().map(|o| (*o, self.get(*o))).collect();
        s.sort_unstable();
        s
    }
    fn write_order(&self) -> Vec<usize> { self.writes.iter().map(|(o, _)| *o).collect() }
}

impl ApicRegs for Fake {
    fn read(&self, off: usize) -> u32 { self.get(off) }
    fn write(&mut self, off: usize, v: u32) { self.writes.push((off, v)); self.set(off, v); }
}

#[test]
fn a_save_restore_round_trip_reproduces_every_register() {
    let mut f = Fake::with_maxlvt(MAXLVT_CMCI);
    let before = f.snapshot();
    let s = save(&f);
    f.clobber();
    assert_ne!(f.snapshot(), before, "the clobber must actually change the window");
    restore(&mut f, &s);
    assert_eq!(f.snapshot(), before);
}

#[test]
fn the_round_trip_holds_for_every_implemented_entry_count() {
    for maxlvt in 3..=MAXLVT_CMCI {
        let mut f = Fake::with_maxlvt(maxlvt);
        let s = save(&f);
        // Only the entries this APIC implements are part of the contract.
        let mut kept: Vec<usize> = alloc::vec![REG_ID, REG_TASKPRI, REG_LDR, REG_DFR, REG_SVR,
            REG_LVT_TIMER, REG_LVT_LINT0, REG_LVT_LINT1, REG_LVT_ERROR,
            REG_TIMER_INIT, REG_TIMER_DIV];
        if maxlvt >= MAXLVT_PERF { kept.push(REG_LVT_PERF); }
        if maxlvt >= MAXLVT_THERMAL { kept.push(REG_LVT_THERMAL); }
        if maxlvt >= MAXLVT_CMCI { kept.push(REG_LVT_CMCI); }
        let before: Vec<(usize, u32)> = kept.iter().map(|o| (*o, f.get(*o))).collect();
        f.clobber();
        restore(&mut f, &s);
        let after: Vec<(usize, u32)> = kept.iter().map(|o| (*o, f.get(*o))).collect();
        assert_eq!(after, before, "maxlvt {maxlvt}");
    }
}

#[test]
fn an_absent_entry_is_neither_saved_nor_restored() {
    let mut f = Fake::with_maxlvt(3);
    let s = save(&f);
    assert!(!s.has_perf() && !s.has_thermal() && !s.has_cmci());
    assert_eq!((s.lvt_perf, s.lvt_thermal, s.lvt_cmci), (0, 0, 0));
    restore(&mut f, &s);
    for off in [REG_LVT_PERF, REG_LVT_THERMAL, REG_LVT_CMCI] {
        assert!(!f.write_order().contains(&off), "wrote an entry this APIC has not got");
    }
}

#[test]
fn the_error_entry_is_masked_before_anything_else_and_unmasked_last() {
    let mut f = Fake::with_maxlvt(MAXLVT_CMCI);
    let s = save(&f);
    f.writes.clear();
    restore(&mut f, &s);
    let first = f.writes.first().copied().expect("a restore writes something");
    assert_eq!(first.0, REG_LVT_ERROR);
    assert_ne!(first.1 & LVT_MASKED, 0, "the first error-entry write must be masked");

    let unmasked = f.writes.iter().rposition(|(o, _)| *o == REG_LVT_ERROR)
        .expect("the real error entry is written");
    assert_eq!(f.writes[unmasked].1, s.lvt_error);
    // Everything after it is only the error-status clear pair.
    for (o, _) in &f.writes[unmasked + 1..] { assert_eq!(*o, REG_ESR); }
}

#[test]
fn the_software_enable_is_written_after_addressing_and_before_the_vectors() {
    let mut f = Fake::with_maxlvt(MAXLVT_CMCI);
    let s = save(&f);
    f.writes.clear();
    restore(&mut f, &s);
    let order = f.write_order();
    let pos = |o: usize| order.iter().position(|x| *x == o).unwrap();
    for before in [REG_ID, REG_DFR, REG_LDR, REG_TASKPRI] {
        assert!(pos(before) < pos(REG_SVR), "{before:#x} must precede the enable");
    }
    for after in [REG_LVT_LINT0, REG_LVT_LINT1, REG_LVT_TIMER, REG_TIMER_DIV, REG_TIMER_INIT] {
        assert!(pos(REG_SVR) < pos(after), "{after:#x} must follow the enable");
    }
}

#[test]
fn the_timer_count_is_written_after_its_divisor() {
    let mut f = Fake::with_maxlvt(MAXLVT_CMCI);
    let s = save(&f);
    f.writes.clear();
    restore(&mut f, &s);
    let order = f.write_order();
    let div = order.iter().position(|x| *x == REG_TIMER_DIV).unwrap();
    let init = order.iter().position(|x| *x == REG_TIMER_INIT).unwrap();
    assert!(div < init, "a count programmed before its divisor counts at the wrong rate");
}

#[test]
fn the_error_status_is_cleared_on_both_sides_of_the_error_entry_write() {
    let mut f = Fake::with_maxlvt(MAXLVT_CMCI);
    let s = save(&f);
    f.writes.clear();
    restore(&mut f, &s);
    let esr: Vec<usize> = f.write_order().iter().enumerate()
        .filter(|(_, o)| **o == REG_ESR).map(|(i, _)| i).collect();
    assert_eq!(esr.len(), 2);
    let real = f.write_order().iter().rposition(|x| *x == REG_LVT_ERROR).unwrap();
    assert!(esr[0] < real && real < esr[1]);
}

#[test]
fn quiescing_masks_every_implemented_entry_and_clears_the_enable() {
    let mut f = Fake::with_maxlvt(MAXLVT_CMCI);
    let s = save(&f);
    quiesce(&mut f, &s);
    for off in [REG_LVT_TIMER, REG_LVT_LINT0, REG_LVT_LINT1, REG_LVT_ERROR,
                REG_LVT_PERF, REG_LVT_THERMAL, REG_LVT_CMCI] {
        assert_ne!(f.get(off) & LVT_MASKED, 0, "{off:#x} left unmasked");
    }
    assert_eq!(f.get(REG_SVR) & SVR_ENABLE, 0);
}

#[test]
fn quiescing_does_not_disturb_the_saved_state() {
    let mut f = Fake::with_maxlvt(MAXLVT_CMCI);
    let before = f.snapshot();
    let s = save(&f);
    quiesce(&mut f, &s);
    restore(&mut f, &s);
    assert_eq!(f.snapshot(), before, "the mask must not survive the resume");
}

#[test]
fn the_implemented_entry_count_comes_from_the_version_register() {
    assert_eq!(maxlvt(6 << VERSION_MAXLVT_SHIFT), 6);
    assert_eq!(maxlvt(0x0005_0014), 5);
}
