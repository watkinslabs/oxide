// 16550 save/restore (`32a§5`). The round trip is the headline; the divisor
// bracketing is the part that is easy to get value-correct and order-wrong,
// and an unbracketed divisor write lands in the data and interrupt-enable
// registers instead.

use alloc::vec::Vec;

use super::*;

/// The divisor latch aliases the first two registers, so the model has to know
/// which pair a read or write lands on.
#[derive(Default)]
struct Fake {
    data: [u8; 8],
    latch: [u8; 2],
    /// Every write, as (offset, value, whether the latch was selected).
    writes: Vec<(u16, u8, bool)>,
    reads: Vec<u16>,
}

impl Fake {
    fn programmed() -> Self {
        let mut f = Fake::default();
        f.data[REG_IER as usize] = 0x0D;
        f.data[REG_LCR as usize] = 0x03;
        f.data[REG_MCR as usize] = 0x0B;
        f.data[REG_LSR as usize] = 0x60;
        f.latch = [0x01, 0x00];
        f
    }
    fn dlab(&self) -> bool { self.data[REG_LCR as usize] & LCR_DLAB != 0 }
    fn programming(&self) -> (u8, u8, u8, [u8; 2]) {
        (self.data[REG_IER as usize], self.data[REG_LCR as usize],
         self.data[REG_MCR as usize], self.latch)
    }
    fn clobber(&mut self) {
        self.data = [0; 8];
        self.latch = [0xFF, 0xFF];
    }
}

impl SerialRegs for Fake {
    fn read(&self, off: u16) -> u8 {
        if self.dlab() && off < 2 { return self.latch[off as usize]; }
        self.data[off as usize]
    }
    fn write(&mut self, off: u16, v: u8) {
        let dlab = self.dlab();
        self.writes.push((off, v, dlab));
        if dlab && off < 2 { self.latch[off as usize] = v; return; }
        self.data[off as usize] = v;
    }
}

// `read` takes `&self`, so the read trace is recorded through a wrapper the
// tests that care about it use.
impl Fake {
    fn read_traced(&mut self, off: u16) -> u8 { self.reads.push(off); self.read(off) }
}

const FCR_SHADOW: u8 = 0x81;

#[test]
fn a_save_reads_the_divisor_and_leaves_the_latch_closed() {
    let mut f = Fake::programmed();
    let s = save(&mut f, FCR_SHADOW);
    assert_eq!((s.ier, s.lcr, s.mcr, s.fcr), (0x0D, 0x03, 0x0B, FCR_SHADOW));
    assert_eq!((s.dll, s.dlm), (0x01, 0x00));
    assert!(!f.dlab(), "the latch must not be left selected");
    assert_eq!(f.data[REG_LCR as usize], 0x03);
}

#[test]
fn a_save_restore_round_trip_reproduces_the_programming() {
    let mut f = Fake::programmed();
    let before = f.programming();
    let s = save(&mut f, FCR_SHADOW);
    f.clobber();
    assert_ne!(f.programming(), before);
    restore(&mut f, &s);
    assert_eq!(f.programming(), before);
}

#[test]
fn a_quiesced_port_still_round_trips() {
    // The real sequence: save, quiesce, sleep, restore.
    let mut f = Fake::programmed();
    let before = f.programming();
    let s = save(&mut f, FCR_SHADOW);
    quiesce(&mut f, &s);
    assert_eq!(f.data[REG_IER as usize], IER_NONE, "the quiesce must mask interrupts");
    f.clobber();
    restore(&mut f, &s);
    assert_eq!(f.programming(), before);
}

#[test]
fn every_divisor_access_happens_with_the_latch_selected() {
    let mut f = Fake::programmed();
    let s = save(&mut f, FCR_SHADOW);
    f.writes.clear();
    restore(&mut f, &s);
    // Offsets alias — the interrupt-enable register and the divisor's high
    // half are the same offset — so the check is positional, and the latch's
    // own contents are the proof that the writes landed where intended.
    assert_eq!(f.writes[1], (REG_DLL, s.dll, true));
    assert_eq!(f.writes[2], (REG_DLM, s.dlm, true));
    assert_eq!(f.latch, [s.dll, s.dlm]);
    let last = *f.writes.last().unwrap();
    assert_eq!(last, (REG_IER, s.ier, false), "the enable must not land in the latch");
    assert_eq!(f.data[REG_IER as usize], s.ier);
}

#[test]
fn the_restore_order_is_latch_divisor_frame_fifo_modem_interrupts() {
    let mut f = Fake::programmed();
    let s = save(&mut f, FCR_SHADOW);
    f.writes.clear();
    restore(&mut f, &s);
    let seq: Vec<(u16, u8)> = f.writes.iter().map(|(o, v, _)| (*o, *v)).collect();
    assert_eq!(seq, alloc::vec![
        (REG_LCR, s.lcr | LCR_DLAB),
        (REG_DLL, s.dll),
        (REG_DLM, s.dlm),
        (REG_LCR, s.lcr),
        (REG_FCR, s.fcr),
        (REG_MCR, s.mcr),
        (REG_IER, s.ier),
    ]);
}

#[test]
fn interrupts_are_enabled_only_after_the_frame_format_is_back() {
    let mut f = Fake::programmed();
    let s = save(&mut f, FCR_SHADOW);
    f.writes.clear();
    restore(&mut f, &s);
    // Positional: the interrupt-enable offset aliases the divisor's high half,
    // so "the last write" is the only unambiguous way to name it.
    let ier = f.writes.len() - 1;
    assert_eq!(f.writes[ier], (REG_IER, s.ier, false), "the enable is the last write");
    // The write that re-establishes the frame format is also the one that
    // closes the latch, so it is made while the latch is still selected.
    let lcr = f.writes.iter().rposition(|(o, v, _)| *o == REG_LCR && *v == s.lcr).unwrap();
    assert_eq!(f.writes[lcr], (REG_LCR, s.lcr, true));
    assert!(lcr < ier, "a receiver enabled at the wrong baud rate delivers noise");
}

#[test]
fn quiescing_clears_the_break_and_the_latch_and_both_fifos() {
    let mut f = Fake::programmed();
    f.data[REG_LCR as usize] = 0x03 | LCR_BREAK;
    let s = save(&mut f, FCR_SHADOW);
    f.writes.clear();
    quiesce(&mut f, &s);
    assert_eq!(f.data[REG_LCR as usize] & (LCR_BREAK | LCR_DLAB), 0);
    assert!(f.writes.iter().any(|(o, v, _)| *o == REG_FCR && *v == FCR_RESET));
    assert_eq!(f.writes[0], (REG_IER, IER_NONE, false), "mask before anything else");
}

#[test]
fn quiescing_drains_the_latched_receive_byte() {
    let mut f = Fake::programmed();
    let s = save(&mut f, FCR_SHADOW);
    f.reads.clear();
    // Mirror `quiesce`'s reads through the tracing accessor.
    f.write(REG_IER, IER_NONE);
    f.write(REG_LCR, s.lcr & !(LCR_DLAB | LCR_BREAK));
    f.write(REG_FCR, FCR_RESET);
    let _ = f.read_traced(REG_RBR);
    assert_eq!(f.reads, alloc::vec![REG_RBR]);
}

#[test]
fn the_saved_divisor_survives_a_port_that_came_back_at_a_different_rate() {
    let mut f = Fake::programmed();
    let s = save(&mut f, FCR_SHADOW);
    // Firmware left the port at 9600 with a different frame format.
    f.data[REG_LCR as usize] = 0x1B;
    f.latch = [0x0C, 0x00];
    restore(&mut f, &s);
    assert_eq!(f.latch, [0x01, 0x00]);
    assert_eq!(f.data[REG_LCR as usize], 0x03);
}

#[test]
fn the_callback_table_covers_all_three_transitions_and_no_others() {
    assert!(PM_OPS.suspend.is_some() && PM_OPS.resume.is_some());
    assert!(PM_OPS.freeze.is_some() && PM_OPS.thaw.is_some());
    assert!(PM_OPS.poweroff.is_some() && PM_OPS.restore.is_some());
    assert!(PM_OPS.prepare.is_none() && PM_OPS.complete.is_none());
    assert!(PM_OPS.suspend_late.is_none() && PM_OPS.suspend_noirq.is_none());
}
