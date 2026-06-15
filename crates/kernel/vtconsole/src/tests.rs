// T5 end-to-end tests: drive the FULL VT stack assembled as a real
// `TtyStruct<VtConsoleDriver<RecordingConsw, RecordingSignal>, HostWait>`
// and assert BOTH what the program/read sees AND what the screen (`Vc`
// cells) holds AND what the renderer (consw) was asked to paint.

use super::*;
use std::cell::RefCell;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

use tty::pty::{default_termios, lflag, TERMIOS_OFF_LFLAG};
use tty::wait::host::HostWait;
use vtdata::{Consw, ScrollDir, Vc};

// --- recording renderer -------------------------------------------------

#[derive(Default, Clone)]
struct ConswLog {
    init: Vec<(u32, u32)>,
    putcs: Vec<(u32, u32, u32)>, // (row, col, n)
    cursor: Vec<bool>,
    switch: u32,
    scroll: u32,
}

/// `Consw` that records every op (and the rendered glyph rows) so tests
/// assert the emulator drove the renderer correctly.
#[derive(Default, Clone)]
struct RecordingConsw {
    log: Rc<RefCell<ConswLog>>,
}

impl RecordingConsw {
    fn log(&self) -> std::cell::Ref<'_, ConswLog> {
        self.log.borrow()
    }
}

impl Consw for RecordingConsw {
    fn con_init(&mut self, cols: u32, rows: u32) {
        self.log.borrow_mut().init.push((cols, rows));
    }
    fn con_clear(&mut self, _vc: &Vc, _x: u32, _y: u32, _w: u32, _h: u32) {}
    fn con_putcs(&mut self, _vc: &Vc, row: u32, col: u32, n: u32) {
        self.log.borrow_mut().putcs.push((row, col, n));
    }
    fn con_cursor(&mut self, _vc: &Vc, visible: bool) {
        self.log.borrow_mut().cursor.push(visible);
    }
    fn con_scroll(&mut self, vc: &Vc, _t: u32, _b: u32, _d: ScrollDir, _n: u32) {
        self.log.borrow_mut().scroll += 1;
        self.con_switch(vc);
    }
    fn con_switch(&mut self, vc: &Vc) {
        self.log.borrow_mut().switch += 1;
        let rows = vc.rows as u32;
        let cols = vc.cols as u32;
        for r in 0..rows {
            self.con_putcs(vc, r, 0, cols);
        }
        self.con_cursor(vc, true);
    }
}

// --- recording signal sink ---------------------------------------------

#[derive(Default, Clone)]
struct RecordingSignal {
    log: Rc<RefCell<Vec<(u32, Sig)>>>,
}

impl FgSignal for RecordingSignal {
    fn raise(&mut self, pgrp: u32, sig: Sig) {
        self.log.borrow_mut().push((pgrp, sig));
    }
}

// --- assembly helper ----------------------------------------------------

type Vtc = VtConsoleDriver<RecordingConsw, RecordingSignal>;

fn build(
    cols: u16,
    rows: u16,
) -> (
    TtyStruct<Vtc, HostWait>,
    RecordingConsw,
    RecordingSignal,
) {
    let consw = RecordingConsw::default();
    let sig = RecordingSignal::default();
    let tty = assemble(consw.clone(), sig.clone(), HostWait::new(), cols, rows);
    (tty, consw, sig)
}

/// Read the active VT's row `r` as a String via `with_driver` (decode
/// each cell glyph; `row_string` is vtdata-test-only so reconstruct here).
fn row(tty: &TtyStruct<Vtc, HostWait>, r: u16) -> String {
    tty.with_driver(|d| {
        let v = d.active();
        let mut s = String::new();
        for c in 0..v.cols {
            let g = v.glyph_at(c, r);
            s.push(char::from_u32(g).unwrap_or('\u{fffd}'));
        }
        s
    })
}

fn cursor(tty: &TtyStruct<Vtc, HostWait>) -> (u16, u16) {
    tty.with_driver(|d| (d.active().x, d.active().y))
}

// --- T5 end-to-end tests ------------------------------------------------

#[test]
fn program_write_lands_on_screen_and_advances_cursor() {
    let (tty, consw, _sig) = build(20, 5);
    // OPOST ONLCR on by default: "hi\n" → emulator sees "hi\r\n".
    let n = tty.write(b"hi\n");
    assert_eq!(n, 3);
    assert!(row(&tty, 0).starts_with("hi"), "row0 = {:?}", row(&tty, 0));
    // \r homes col, \n moves to row 1.
    assert_eq!(cursor(&tty), (0, 1));
    // consw received putcs for the dirtied row(s).
    assert!(
        !consw.log().putcs.is_empty(),
        "renderer got no putcs for the write"
    );
}

#[test]
fn input_echoes_to_screen_and_read_returns_line() {
    let (tty, _consw, _sig) = build(20, 5);
    // RX a full canonical line: cooked + echoed.
    tty.receive_from_driver(b"ls -l\n");
    // Program read returns the cooked line (with trailing \n).
    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf).bytes_or_zero();
    assert_eq!(&buf[..got], b"ls -l\n");
    // Echo went out driver_write → emulator → Vc: screen shows "ls -l".
    assert!(row(&tty, 0).starts_with("ls -l"), "row0 = {:?}", row(&tty, 0));
}

#[test]
fn password_mode_echo_off_reads_line_but_screen_blank() {
    // ECHO cleared in lflag.
    let mut t = default_termios();
    let mut lf = [t[TERMIOS_OFF_LFLAG], t[TERMIOS_OFF_LFLAG + 1], t[TERMIOS_OFF_LFLAG + 2], t[TERMIOS_OFF_LFLAG + 3]];
    let mut val = u32::from_le_bytes(lf);
    val &= !lflag::ECHO;
    lf = val.to_le_bytes();
    t[TERMIOS_OFF_LFLAG] = lf[0];
    t[TERMIOS_OFF_LFLAG + 1] = lf[1];
    t[TERMIOS_OFF_LFLAG + 2] = lf[2];
    t[TERMIOS_OFF_LFLAG + 3] = lf[3];

    let consw = RecordingConsw::default();
    let sig = RecordingSignal::default();
    let drv = VtConsoleDriver::with_geometry(consw, sig, 20, 3);
    let tty = TtyStruct::with_termios(drv, HostWait::new(), t);

    tty.receive_from_driver(b"secret\n");
    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf).bytes_or_zero();
    assert_eq!(&buf[..got], b"secret\n");
    // Nothing echoed → screen row 0 is all blanks.
    assert_eq!(row(&tty, 0).trim_end(), "");
}

#[test]
fn ctrl_c_raises_sigint_on_fg_pgrp() {
    let (tty, _consw, sig) = build(20, 3);
    set_fg_pgrp(&tty, 4242);
    tty.receive_from_driver(b"\x03");
    let log = sig.log.borrow();
    assert_eq!(log.len(), 1, "expected exactly one signal");
    assert_eq!(log[0], (4242, Sig::Int));
}

#[test]
fn csi_sgr_red_carries_attr_through_full_stack() {
    let (tty, _consw, _sig) = build(20, 3);
    // ESC[31m red fg, "ERR", ESC[0m reset.
    tty.write(b"\x1b[31mERR\x1b[0m");
    // Cells E,R,R carry red fg (resolved to VGA-red RGB).
    let red = vtdata::xterm_256_rgb(1);
    let a0 = tty.with_driver(|d| d.active().attr_at(0, 0)).unwrap();
    let a2 = tty.with_driver(|d| d.active().attr_at(2, 0)).unwrap();
    assert_eq!(a0.fg, red, "ERR first cell fg should be red: {:?}", a0);
    assert_eq!(a2.fg, red);
    assert_eq!(row(&tty, 0).trim_end(), "ERR");
}

#[test]
fn backspace_editing_visible_on_screen() {
    let (tty, _consw, _sig) = build(20, 3);
    // Type "abX", erase the X (VERASE=^?=0x7f), type "c", newline.
    // ECHOE echoes "\b \b": emulator BS then space then BS erases the cell.
    tty.receive_from_driver(b"abX\x7fc\n");
    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf).bytes_or_zero();
    assert_eq!(&buf[..got], b"abc\n", "cooked line should be abc");
    // Screen shows "abc" — the X was erased by the echoed \b \b.
    assert_eq!(row(&tty, 0).trim_end(), "abc", "row0 = {:?}", row(&tty, 0));
}

#[test]
fn write_then_input_share_the_active_vc() {
    // Program prompt write, then user types a line: both on the same VT.
    let (tty, _consw, _sig) = build(20, 4);
    tty.write(b"$ ");
    tty.receive_from_driver(b"echo hi\n");
    let mut buf = [0u8; 32];
    let got = tty.read(&mut buf).bytes_or_zero();
    assert_eq!(&buf[..got], b"echo hi\n");
    // Row 0: prompt then echoed command.
    assert!(row(&tty, 0).starts_with("$ echo hi"), "row0 = {:?}", row(&tty, 0));
}

// --- proptest: random interleave never panics / stays in bounds ---------

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]
    #[test]
    fn random_interleave_never_panics_and_stays_in_bounds(
        ops in proptest::collection::vec(
            prop_oneof![
                proptest::collection::vec(any::<u8>(), 0..16).prop_map(Op::Write),
                proptest::collection::vec(any::<u8>(), 0..16).prop_map(Op::Recv),
                Just(Op::Read),
            ],
            0..64,
        )
    ) {
        let (tty, _consw, _sig) = build(16, 4);
        for op in ops {
            match op {
                Op::Write(b) => { tty.write(&b); }
                Op::Recv(b) => { tty.receive_from_driver(&b); }
                Op::Read => {
                    let mut buf = [0u8; 64];
                    // read_nonblock so the proptest never parks forever.
                    let n = tty.read_nonblock(&mut buf);
                    prop_assert!(n <= buf.len());
                }
            }
            // Cursor always in bounds of the active VT.
            let (cx, cy, cols, rows) = tty.with_driver(|d| {
                let v = d.active();
                (v.x, v.y, v.cols, v.rows)
            });
            prop_assert!(cx < cols);
            prop_assert!(cy < rows);
        }
    }
}

#[derive(Debug, Clone)]
enum Op {
    Write(Vec<u8>),
    Recv(Vec<u8>),
    Read,
}
