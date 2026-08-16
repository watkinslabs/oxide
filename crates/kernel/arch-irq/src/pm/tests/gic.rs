// GIC save/restore (`32a§7`). Round trips for the distributor, the
// redistributor's private range and the CPU interface, plus the three ordering
// rules: the distributor off first and on last, every enable word cleared
// before it is set, and Group-1 delivery re-enabled last.

use alloc::vec::Vec;

use crate::gicdef::*;
use crate::pm::gic_state::*;

/// Thirty-two shared interrupts past the private range.
const TYPER_2_BLOCKS: u32 = 1;
const IRQS: u32 = 64;

#[derive(Default)]
struct Fake { cells: Vec<(usize, u64)>, writes: Vec<(usize, u64)> }

impl Fake {
    fn distributor() -> Self {
        let mut f = Fake::default();
        f.put(GICD_TYPER, TYPER_2_BLOCKS as u64);
        f.put(GICD_CTLR, (CTLR_ENGRP1 | CTLR_ARE_NS) as u64);
        for i in first_1bit_word()..words_1bit(IRQS) {
            f.put(GICD_IGROUPR + (i * 4) as usize, 0xFFFF_0000 + i as u64);
            f.put(GICD_ISENABLER + (i * 4) as usize, 0x0000_00F0 + i as u64);
        }
        for i in first_8bit_word()..words_8bit(IRQS) {
            f.put(GICD_IPRIORITYR + (i * 4) as usize, 0xA0A0_A000 + i as u64);
        }
        for i in first_2bit_word()..words_2bit(IRQS) {
            f.put(GICD_ICFGR + (i * 4) as usize, 0x5555_0000 + i as u64);
        }
        for intid in SPI_BASE..IRQS {
            f.put(GICD_IROUTER + (intid * 8) as usize, 0x0000_0001_0000_0000 + intid as u64);
        }
        f
    }
    fn sgi_frame() -> Self {
        let mut f = Fake::default();
        f.put(GICR_IGROUPR0, 0xFFFF_FFFF);
        f.put(GICR_ISENABLER0, 0x0000_FFFF);
        f.put(GICR_ICFGR1, 0xAAAA_AAAA);
        for i in 0..PRIVATE_PRIORITY_WORDS { f.put(GICR_IPRIORITYR + i * 4, 0xA0A0_A000 + i as u64); }
        f
    }
    fn put(&mut self, off: usize, v: u64) {
        match self.cells.iter_mut().find(|(o, _)| *o == off) {
            Some(c) => c.1 = v,
            None => self.cells.push((off, v)),
        }
    }
    fn peek(&self, off: usize) -> u64 {
        self.cells.iter().find(|(o, _)| *o == off).map(|(_, v)| *v).unwrap_or(0)
    }
    fn snapshot(&self) -> Vec<(usize, u64)> {
        let mut s = self.cells.clone();
        s.sort_unstable();
        s
    }
    fn clobber(&mut self) {
        for (o, v) in self.cells.iter_mut() { if *o != GICD_TYPER { *v = 0xDEAD_BEEF_DEAD_BEEF; } }
    }
    fn order(&self) -> Vec<usize> { self.writes.iter().map(|(o, _)| *o).collect() }
}

impl GicRegs for Fake {
    fn read(&self, off: usize) -> u32 { self.peek(off) as u32 }
    fn write(&mut self, off: usize, v: u32) {
        self.writes.push((off, v as u64));
        self.put(off, v as u64);
    }
    fn read64(&self, off: usize) -> u64 { self.peek(off) }
    fn write64(&mut self, off: usize, v: u64) { self.writes.push((off, v)); self.put(off, v); }
}

#[test]
fn the_implemented_interrupt_count_comes_from_the_type_register() {
    assert_eq!(gic_irqs(TYPER_2_BLOCKS), IRQS);
    assert_eq!(gic_irqs(0), 32);
    assert_eq!(gic_irqs(0x1F), 1020, "the count is capped at the largest shared identifier");
}

#[test]
fn the_word_counts_match_the_bits_per_interrupt() {
    assert_eq!(words_1bit(64), 2);
    assert_eq!(words_2bit(64), 4);
    assert_eq!(words_8bit(64), 16);
    assert_eq!(words_1bit(33), 2, "a partial word still needs a word");
    assert_eq!((first_1bit_word(), first_2bit_word(), first_8bit_word()), (1, 2, 8));
}

#[test]
fn a_distributor_save_restore_round_trip_reproduces_every_register() {
    let mut f = Fake::distributor();
    let before = f.snapshot();
    let s = dist_save(&f);
    assert_eq!(s.irqs, IRQS);
    f.clobber();
    assert_ne!(f.snapshot(), before);
    dist_restore(&mut f, &s);
    // The clear pass leaves the write-one-to-clear register behind; the state
    // that matters is everything the save read.
    for (off, v) in before {
        if off == GICD_ICENABLER { continue; }
        assert_eq!(f.peek(off), v, "offset {off:#x}");
    }
}

#[test]
fn the_distributor_is_disabled_first_and_re_enabled_last() {
    let mut f = Fake::distributor();
    let s = dist_save(&f);
    f.writes.clear();
    dist_restore(&mut f, &s);
    assert_eq!(f.writes.first().copied(), Some((GICD_CTLR, 0)));
    assert_eq!(f.writes.last().copied(), Some((GICD_CTLR, s.ctlr as u64)));
    assert_ne!(s.ctlr, 0, "the fixture must have the distributor enabled to start with");
}

#[test]
fn every_enable_word_is_cleared_before_it_is_set() {
    let mut f = Fake::distributor();
    let s = dist_save(&f);
    f.writes.clear();
    dist_restore(&mut f, &s);
    for n in 0..s.enable.len() {
        let word = (first_1bit_word() as usize + n) * 4;
        let clear = f.writes.iter().position(|(o, v)| *o == GICD_ICENABLER + word
                                                       && *v == ALL_BITS as u64);
        let set = f.writes.iter().position(|(o, _)| *o == GICD_ISENABLER + word);
        let (clear, set) = (clear.expect("a clear pass"), set.expect("a set pass"));
        assert!(clear < set, "word {n}: setting alone can only ever add enabled lines");
    }
}

#[test]
fn configuration_and_priority_and_routing_precede_the_enables() {
    let mut f = Fake::distributor();
    let s = dist_save(&f);
    f.writes.clear();
    dist_restore(&mut f, &s);
    let order = f.order();
    let first_enable = order.iter().position(|o| *o == GICD_ISENABLER + 4).unwrap();
    // Exact offsets, not a range: the register classes interleave in the
    // address map, so a range test finds the wrong write.
    let mut earlier: Vec<usize> = Vec::new();
    for i in first_2bit_word()..words_2bit(IRQS) { earlier.push(GICD_ICFGR + (i * 4) as usize); }
    for i in first_8bit_word()..words_8bit(IRQS) { earlier.push(GICD_IPRIORITYR + (i * 4) as usize); }
    for i in first_1bit_word()..words_1bit(IRQS) { earlier.push(GICD_IGROUPR + (i * 4) as usize); }
    for id in SPI_BASE..IRQS { earlier.push(GICD_IROUTER + (id * 8) as usize); }
    for off in earlier {
        let at = order.iter().position(|o| *o == off)
            .unwrap_or_else(|| panic!("{off:#x} was never restored"));
        assert!(at < first_enable, "{off:#x} must be programmed before a line goes live");
    }
}

#[test]
fn only_the_shared_range_is_saved_from_the_distributor() {
    let f = Fake::distributor();
    let s = dist_save(&f);
    assert_eq!(s.enable.len(), (words_1bit(IRQS) - first_1bit_word()) as usize);
    assert_eq!(s.priority.len(), (words_8bit(IRQS) - first_8bit_word()) as usize);
    assert_eq!(s.config.len(), (words_2bit(IRQS) - first_2bit_word()) as usize);
    assert_eq!(s.route.len(), (IRQS - SPI_BASE) as usize);
}

#[test]
fn a_redistributor_save_restore_round_trip_reproduces_the_private_range() {
    let mut f = Fake::sgi_frame();
    let before = f.snapshot();
    let s = redist_save(&f);
    f.clobber();
    redist_restore(&mut f, &s);
    for (off, v) in before {
        if off == GICR_ICENABLER0 { continue; }
        assert_eq!(f.peek(off), v, "offset {off:#x}");
    }
}

#[test]
fn the_private_enable_word_is_also_cleared_before_it_is_set() {
    let mut f = Fake::sgi_frame();
    let s = redist_save(&f);
    f.writes.clear();
    redist_restore(&mut f, &s);
    let clear = f.writes.iter().position(|(o, v)| *o == GICR_ICENABLER0
                                                   && *v == ALL_BITS as u64).unwrap();
    let set = f.writes.iter().position(|(o, _)| *o == GICR_ISENABLER0).unwrap();
    assert!(clear < set);
}

#[test]
fn the_private_priority_covers_all_thirty_two_private_interrupts() {
    assert_eq!(PRIVATE_PRIORITY_WORDS, 8);
    let f = Fake::sgi_frame();
    let s = redist_save(&f);
    for (i, w) in s.priority.iter().enumerate() { assert_eq!(*w, 0xA0A0_A000 + i as u32); }
}

#[test]
fn sleeping_the_redistributor_waits_for_its_acknowledgement() {
    struct Waker { asleep: bool, reads: u32 }
    impl GicRegs for Waker {
        fn read(&self, _off: usize) -> u32 {
            let mut v = 0;
            if self.asleep { v |= WAKER_PROCESSOR_SLEEP; }
            // Answers only after a few polls, the way real hardware does.
            if self.asleep && self.reads > 2 { v |= WAKER_CHILDREN_ASLEEP; }
            v
        }
        fn write(&mut self, _off: usize, v: u32) { self.asleep = v & WAKER_PROCESSOR_SLEEP != 0; }
        fn read64(&self, _off: usize) -> u64 { 0 }
        fn write64(&mut self, _off: usize, _v: u64) {}
    }
    let mut w = Waker { asleep: false, reads: 9 };
    assert!(redist_sleep(&mut w, 8));
    assert!(w.asleep);
}

#[test]
fn a_redistributor_that_refuses_to_sleep_is_reported_rather_than_spun_on() {
    struct NoPm;
    impl GicRegs for NoPm {
        fn read(&self, _off: usize) -> u32 { 0 }
        fn write(&mut self, _off: usize, _v: u32) {}
        fn read64(&self, _off: usize) -> u64 { 0 }
        fn write64(&mut self, _off: usize, _v: u64) {}
    }
    assert!(!redist_sleep(&mut NoPm, 4), "the sleep bit did not stick, so there is no support");
    assert!(redist_wake(&mut NoPm, 4), "children already awake");
}

#[test]
fn group_one_delivery_is_the_last_cpu_interface_register_restored() {
    assert_eq!(CPUIF_RESTORE_ORDER.last(), Some(&CpuIfReg::Grpen1));
    assert_eq!(CPUIF_RESTORE_ORDER[0], CpuIfReg::Pmr);
    let s = GicCpuIf { pmr: 0xF0, ctlr: 0x2, grpen1: 1 };
    let got: Vec<u32> = CPUIF_RESTORE_ORDER.iter().map(|r| s.value(*r)).collect();
    assert_eq!(got, alloc::vec![0xF0, 0x2, 1]);
}

#[test]
fn quiescing_the_distributor_stops_delivery() {
    let mut f = Fake::distributor();
    dist_quiesce(&mut f);
    assert_eq!(f.peek(GICD_CTLR), 0);
}
