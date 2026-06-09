// Shared test harness: recording renderer (consw), recording UART sink,
// a recording signal sink that satisfies BOTH crates' `FgSignal` traits,
// and termios mutation helpers. Mirrors the per-crate harnesses in
// `vtconsole/src/tests.rs` and `serialtty/src/tests.rs` so the
// integration net drives the identical assembled stacks.

use std::cell::RefCell;
use std::rc::Rc;
use std::string::String;
use std::vec::Vec;

use tty::ldisc::Sig;
use tty::pty::{default_termios, lflag, oflag, TERMIOS_BYTES, TERMIOS_OFF_LFLAG, TERMIOS_OFF_OFLAG};
use tty::wait::host::HostWait;
use tty::TtyStruct;

use vtconsole::{assemble as vt_assemble, set_fg_pgrp as vt_set_fg_pgrp, VtConsoleDriver};
use serialtty::{assemble as ser_assemble, set_fg_pgrp as ser_set_fg_pgrp, SerialTtyDriver};

use vtdata::{Consw, ScrollDir, Vc};

// --- recording renderer (consw) -----------------------------------------

#[derive(Default, Clone)]
pub struct ConswLog {
    pub init: Vec<(u32, u32)>,
    pub putcs: Vec<(u32, u32, u32)>, // (row, col, n)
    pub cursor: Vec<bool>,
    pub switch: u32,
    pub scroll: u32,
}

/// `Consw` that records every op so tests assert the emulator drove the
/// renderer (fbcon) correctly without a real framebuffer.
#[derive(Default, Clone)]
pub struct RecordingConsw {
    pub log: Rc<RefCell<ConswLog>>,
}

impl RecordingConsw {
    pub fn log(&self) -> std::cell::Ref<'_, ConswLog> {
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

// --- recording UART sink ------------------------------------------------

/// `serialtty::SerialOut` that records every post-cook TX byte so tests
/// assert what the wire sees without a real UART.
#[derive(Default, Clone)]
pub struct RecordingOut {
    pub bytes: Rc<RefCell<Vec<u8>>>,
}

impl RecordingOut {
    pub fn tx(&self) -> Vec<u8> {
        self.bytes.borrow().clone()
    }
}

impl serialtty::SerialOut for RecordingOut {
    fn emit(&mut self, bytes: &[u8]) {
        self.bytes.borrow_mut().extend_from_slice(bytes);
    }
}

// --- recording signal sink (satisfies BOTH FgSignal traits) -------------

/// Records `(pgrp, sig)` raised by ISIG. `vtconsole::FgSignal` and
/// `serialtty::FgSignal` are distinct traits over the same `Sig`; one
/// recorder impls both so the same harness type drives both stacks.
#[derive(Default, Clone)]
pub struct RecordingSignal {
    pub log: Rc<RefCell<Vec<(u32, Sig)>>>,
}

impl RecordingSignal {
    pub fn sigs(&self) -> Vec<(u32, Sig)> {
        self.log.borrow().clone()
    }
}

impl vtconsole::FgSignal for RecordingSignal {
    fn raise(&mut self, pgrp: u32, sig: Sig) {
        self.log.borrow_mut().push((pgrp, sig));
    }
}

impl serialtty::FgSignal for RecordingSignal {
    fn raise(&mut self, pgrp: u32, sig: Sig) {
        self.log.borrow_mut().push((pgrp, sig));
    }
}

// --- termios helpers ----------------------------------------------------

/// Mutate a termios u32 field (oflag/lflag) in place.
fn set_field(t: &mut [u8; TERMIOS_BYTES], off: usize, f: impl FnOnce(u32) -> u32) {
    let cur = u32::from_le_bytes([t[off], t[off + 1], t[off + 2], t[off + 3]]);
    let b = f(cur).to_le_bytes();
    t[off..off + 4].copy_from_slice(&b);
}

/// Cooked termios with ECHO cleared (password prompt).
pub fn echo_off_termios() -> [u8; TERMIOS_BYTES] {
    let mut t = default_termios();
    set_field(&mut t, TERMIOS_OFF_LFLAG, |l| l & !lflag::ECHO);
    t
}

/// Cooked termios with OPOST cleared (raw output, no ONLCR).
pub fn opost_off_termios() -> [u8; TERMIOS_BYTES] {
    let mut t = default_termios();
    set_field(&mut t, TERMIOS_OFF_OFLAG, |o| o & !oflag::OPOST);
    t
}

// --- VT stack assembly --------------------------------------------------

pub type Vtc = VtConsoleDriver<RecordingConsw, RecordingSignal>;
pub type VtTty = TtyStruct<Vtc, HostWait>;

/// Assemble a full VT stack (cooked termios) + return the renderer +
/// signal recorders.
pub fn build_vt(cols: u16, rows: u16) -> (VtTty, RecordingConsw, RecordingSignal) {
    let consw = RecordingConsw::default();
    let sig = RecordingSignal::default();
    let tty = vt_assemble(consw.clone(), sig.clone(), HostWait::new(), cols, rows);
    (tty, consw, sig)
}

/// Assemble a full VT stack with an explicit termios.
pub fn build_vt_termios(
    cols: u16,
    rows: u16,
    t: [u8; TERMIOS_BYTES],
) -> (VtTty, RecordingConsw, RecordingSignal) {
    let consw = RecordingConsw::default();
    let sig = RecordingSignal::default();
    let drv = VtConsoleDriver::with_geometry(consw.clone(), sig.clone(), cols, rows);
    let tty = TtyStruct::with_termios(drv, HostWait::new(), t);
    (tty, consw, sig)
}

/// Read the active VT's row `r` as a String (decode each cell glyph).
pub fn vt_row(tty: &VtTty, r: u16) -> String {
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

/// Set the fg pgrp on the VT stack (core + driver shadow).
pub fn vt_set_pgrp(tty: &VtTty, pgrp: u32) {
    vt_set_fg_pgrp(tty, pgrp);
}

// --- serial stack assembly ----------------------------------------------

pub type Stty = SerialTtyDriver<RecordingOut, RecordingSignal>;
pub type SerTty = TtyStruct<Stty, HostWait>;

/// Assemble a full serial stack (cooked termios) + return the UART +
/// signal recorders.
pub fn build_serial() -> (SerTty, RecordingOut, RecordingSignal) {
    let out = RecordingOut::default();
    let sig = RecordingSignal::default();
    let tty = ser_assemble(out.clone(), sig.clone(), HostWait::new());
    (tty, out, sig)
}

/// Assemble a full serial stack with an explicit termios.
pub fn build_serial_termios(t: [u8; TERMIOS_BYTES]) -> (SerTty, RecordingOut, RecordingSignal) {
    let out = RecordingOut::default();
    let sig = RecordingSignal::default();
    let drv = SerialTtyDriver::with_signal(out.clone(), sig.clone());
    let tty = TtyStruct::with_termios(drv, HostWait::new(), t);
    (tty, out, sig)
}

/// Set the fg pgrp on the serial stack (core + driver shadow).
pub fn ser_set_pgrp(tty: &SerTty, pgrp: u32) {
    ser_set_fg_pgrp(tty, pgrp);
}
