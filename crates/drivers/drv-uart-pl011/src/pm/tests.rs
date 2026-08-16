// PL011 save/restore (`32a§5`). The round trip, and the two orderings that
// decide whether the port comes back at the right baud rate: both divisor
// halves before the line control that latches them, and the control register
// before the interrupt mask.

use alloc::vec::Vec;

use super::*;

#[derive(Default)]
struct Fake { cells: Vec<(usize, u32)>, writes: Vec<(usize, u32)> }

impl Fake {
    fn programmed() -> Self {
        let mut f = Fake::default();
        f.put(REG_CR, CR_UARTEN | CR_TXE | CR_RXE | CR_HANDSHAKE);
        f.put(REG_LCRH, 0x60 | LCRH_FEN);
        f.put(REG_IBRD, 13);
        f.put(REG_FBRD, 1);
        f.put(REG_IMSC, 0x50);
        f
    }
    fn put(&mut self, off: usize, v: u32) {
        match self.cells.iter_mut().find(|(o, _)| *o == off) {
            Some(c) => c.1 = v,
            None => self.cells.push((off, v)),
        }
    }
    fn peek(&self, off: usize) -> u32 {
        self.cells.iter().find(|(o, _)| *o == off).map(|(_, v)| *v).unwrap_or(0)
    }
    fn programming(&self) -> (u32, u32, u32, u32, u32) {
        (self.peek(REG_CR), self.peek(REG_LCRH), self.peek(REG_IBRD),
         self.peek(REG_FBRD), self.peek(REG_IMSC))
    }
    fn clobber(&mut self) { for (_, v) in self.cells.iter_mut() { *v = 0; } }
    fn order(&self) -> Vec<usize> { self.writes.iter().map(|(o, _)| *o).collect() }
}

impl Pl011Regs for Fake {
    fn read(&self, off: usize) -> u32 { self.peek(off) }
    fn write(&mut self, off: usize, v: u32) { self.writes.push((off, v)); self.put(off, v); }
}

#[test]
fn a_save_reads_the_control_frame_divisor_and_mask() {
    let f = Fake::programmed();
    let s = save(&f);
    assert_eq!(s.cr, CR_UARTEN | CR_TXE | CR_RXE | CR_HANDSHAKE);
    assert_eq!(s.lcrh, 0x60 | LCRH_FEN);
    assert_eq!((s.ibrd, s.fbrd, s.imsc), (13, 1, 0x50));
}

#[test]
fn a_save_restore_round_trip_reproduces_the_programming() {
    let mut f = Fake::programmed();
    let before = f.programming();
    let s = save(&f);
    f.clobber();
    assert_ne!(f.programming(), before);
    restore(&mut f, &s);
    assert_eq!(f.programming(), before);
}

#[test]
fn a_quiesced_port_still_round_trips() {
    let mut f = Fake::programmed();
    let before = f.programming();
    let s = save(&f);
    quiesce(&mut f, &s);
    assert_eq!(f.peek(REG_IMSC), IMSC_NONE);
    f.clobber();
    restore(&mut f, &s);
    assert_eq!(f.programming(), before);
}

#[test]
fn both_divisor_halves_are_written_before_the_line_control_latches_them() {
    let mut f = Fake::programmed();
    let s = save(&f);
    f.writes.clear();
    restore(&mut f, &s);
    let order = f.order();
    let pos = |o: usize| order.iter().position(|x| *x == o).unwrap();
    assert!(pos(REG_FBRD) < pos(REG_LCRH));
    assert!(pos(REG_IBRD) < pos(REG_LCRH));
    assert!(pos(REG_FBRD) < pos(REG_IBRD), "the fractional half goes first");
}

#[test]
fn the_control_register_is_written_after_the_frame_and_before_the_mask() {
    let mut f = Fake::programmed();
    let s = save(&f);
    f.writes.clear();
    restore(&mut f, &s);
    let order = f.order();
    let cr = order.iter().rposition(|x| *x == REG_CR).unwrap();
    let lcrh = order.iter().position(|x| *x == REG_LCRH).unwrap();
    let imsc = order.iter().rposition(|x| *x == REG_IMSC).unwrap();
    assert!(lcrh < cr, "enabling the port before its frame format delivers noise");
    assert!(cr < imsc, "the mask lifts last");
    assert_eq!(f.writes[imsc], (REG_IMSC, s.imsc));
}

#[test]
fn a_restore_masks_and_clears_before_it_reprograms_anything() {
    let mut f = Fake::programmed();
    let s = save(&f);
    f.writes.clear();
    restore(&mut f, &s);
    assert_eq!(f.writes[0], (REG_IMSC, IMSC_NONE));
    assert_eq!(f.writes[1], (REG_ICR, ICR_ALL));
}

#[test]
fn the_full_restore_sequence_is_pinned() {
    let mut f = Fake::programmed();
    let s = save(&f);
    f.writes.clear();
    restore(&mut f, &s);
    assert_eq!(f.writes, alloc::vec![
        (REG_IMSC, IMSC_NONE),
        (REG_ICR, ICR_ALL),
        (REG_FBRD, s.fbrd),
        (REG_IBRD, s.ibrd),
        (REG_LCRH, s.lcrh),
        (REG_CR, s.cr),
        (REG_IMSC, s.imsc),
    ]);
}

#[test]
fn quiescing_masks_clears_drops_the_receiver_and_keeps_the_transmitter() {
    let mut f = Fake::programmed();
    let s = save(&f);
    f.writes.clear();
    quiesce(&mut f, &s);
    assert_eq!(f.writes[0], (REG_IMSC, IMSC_NONE));
    assert_eq!(f.writes[1], (REG_ICR, ICR_ALL));
    let cr = f.peek(REG_CR);
    assert_eq!(cr & CR_RXE, 0, "the receiver must be off on the way down");
    assert_ne!(cr & CR_TXE, 0, "a late console write must still land");
    assert_ne!(cr & CR_UARTEN, 0);
    assert_eq!(cr & CR_HANDSHAKE, CR_HANDSHAKE, "the peer must not see the line drop");
}

#[test]
fn quiescing_drops_the_fifos_and_any_break() {
    let mut f = Fake::programmed();
    f.put(REG_LCRH, 0x60 | LCRH_FEN | LCRH_BRK);
    let s = save(&f);
    quiesce(&mut f, &s);
    assert_eq!(f.peek(REG_LCRH) & (LCRH_FEN | LCRH_BRK), 0);
}

#[test]
fn the_saved_divisor_survives_a_port_firmware_reprogrammed() {
    let mut f = Fake::programmed();
    let s = save(&f);
    f.put(REG_IBRD, 26);
    f.put(REG_FBRD, 3);
    f.put(REG_LCRH, 0x20);
    restore(&mut f, &s);
    assert_eq!((f.peek(REG_IBRD), f.peek(REG_FBRD)), (13, 1));
    assert_eq!(f.peek(REG_LCRH), 0x60 | LCRH_FEN);
}

#[test]
fn the_callback_table_covers_all_three_transitions_and_no_others() {
    assert!(PM_OPS.suspend.is_some() && PM_OPS.resume.is_some());
    assert!(PM_OPS.freeze.is_some() && PM_OPS.thaw.is_some());
    assert!(PM_OPS.poweroff.is_some() && PM_OPS.restore.is_some());
    assert!(PM_OPS.prepare.is_none() && PM_OPS.complete.is_none());
    assert!(PM_OPS.suspend_late.is_none() && PM_OPS.suspend_noirq.is_none());
}

#[test]
fn the_register_offsets_are_the_architectural_ones() {
    assert_eq!((REG_DR, REG_FR, REG_IBRD, REG_FBRD), (0x00, 0x18, 0x24, 0x28));
    assert_eq!((REG_LCRH, REG_CR, REG_IFLS, REG_IMSC), (0x2C, 0x30, 0x34, 0x38));
    assert_eq!((REG_ICR, REG_DMACR), (0x44, 0x48));
}
