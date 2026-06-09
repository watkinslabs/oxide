// N_TTY line discipline (`drivers/tty/n_tty.c`). Pure logic; no lock,
// no block. See `ldisc/mod.rs` for the layer contract.

extern crate alloc;
use alloc::collections::VecDeque;

use super::{pollmask, LdiscOps, Sig, TtyDriverHooks};
use crate::pty::{
    cc, default_termios, iflag, lflag, oflag, read_iflag, read_lflag, read_oflag,
    TERMIOS_BYTES, TERMIOS_OFF_CC,
};

/// Canonical line buffer cap. Linux N_TTY_BUF_SIZE is 4096; a cooked
/// line that overruns simply stops accepting non-terminator bytes
/// (the terminator still completes the line) — matches Linux's
/// behaviour of dropping past the limit while keeping the line usable.
const CANON_CAP: usize = 4096;

/// Tab stop width for OPOST tab expansion (Linux `XTABS`/`TAB3` expands
/// to the next multiple of 8 columns).
const TAB_WIDTH: u16 = 8;

/// N_TTY line discipline state.
///
/// `termios` is the live image (reused `crate::pty` layout). `canon`
/// accumulates the current unfinished line under ICANON. `readq` holds
/// bytes ready for `read` (completed cooked lines, or raw bytes).
/// `out_col` tracks the output column for OPOST tab/CR. `eof_pending`
/// is set by VEOF and makes a `read` of an empty queue return 0 (EOF).
pub struct NTty {
    termios: [u8; TERMIOS_BYTES],
    canon: VecDeque<u8>,
    readq: VecDeque<u8>,
    out_col: u16,
    eof_pending: bool,
}

impl Default for NTty {
    fn default() -> Self {
        Self::new()
    }
}

impl NTty {
    /// Fresh N_TTY with cooked-sane defaults (`default_termios`:
    /// ICANON|ECHO|ISIG, ICRNL, OPOST|ONLCR).
    /// # C: O(1)
    pub fn new() -> Self {
        Self {
            termios: default_termios(),
            canon: VecDeque::new(),
            readq: VecDeque::new(),
            out_col: 0,
            eof_pending: false,
        }
    }

    /// Build with a caller-supplied termios image (raw-mode ptys etc.).
    /// # C: O(1)
    pub fn with_termios(t: [u8; TERMIOS_BYTES]) -> Self {
        let mut n = Self::new();
        n.termios = t;
        n
    }

    /// True when `read` would return ≥1 byte or signal EOF. The tty core
    /// (T4) calls this under its lock to decide whether to park.
    /// # C: O(1)
    pub fn has_input(&self) -> bool {
        !self.readq.is_empty() || self.eof_pending
    }

    /// Bytes immediately drainable from the read queue.
    /// # C: O(1)
    pub fn available(&self) -> usize {
        self.readq.len()
    }

    fn cc(&self, idx: usize) -> u8 {
        self.termios[TERMIOS_OFF_CC + idx]
    }

    fn lflag(&self) -> u32 {
        read_lflag(&self.termios)
    }
    fn iflag(&self) -> u32 {
        read_iflag(&self.termios)
    }
    fn oflag(&self) -> u32 {
        read_oflag(&self.termios)
    }

    fn is_canon(&self) -> bool {
        self.lflag() & lflag::ICANON != 0
    }

    /// Echo one input byte the Linux way: printable verbatim, control as
    /// `^X` when ECHOCTL, CR/NL as the configured line ending. Goes
    /// through `driver_write`.
    fn echo_byte<D: TtyDriverHooks>(&self, drv: &mut D, b: u8) {
        let lf = self.lflag();
        if lf & lflag::ECHO == 0 {
            // ECHONL: NL still echoed with ECHO off.
            if b == b'\n' && lf & lflag::ECHONL != 0 {
                drv.driver_write(b"\n");
            }
            return;
        }
        match b {
            b'\n' => drv.driver_write(b"\n"),
            b'\t' => drv.driver_write(b"\t"),
            0x20..=0x7e => drv.driver_write(&[b]),
            // Control char (incl DEL): show ^X when ECHOCTL.
            _ => {
                if lf & lflag::ECHOCTL != 0 && b != b'\n' {
                    let sym = if b == 0x7f { b'?' } else { b ^ 0x40 };
                    drv.driver_write(&[b'^', sym]);
                }
            }
        }
    }

    /// VERASE: drop the last char of the current line; ECHOE renders the
    /// destructive "\b \b".
    fn do_erase<D: TtyDriverHooks>(&mut self, drv: &mut D) {
        if self.canon.pop_back().is_some() {
            let lf = self.lflag();
            if lf & lflag::ECHO != 0 && lf & lflag::ECHOE != 0 {
                drv.driver_write(b"\x08 \x08");
            }
        }
    }

    /// VWERASE: erase trailing whitespace then the preceding word.
    fn do_werase<D: TtyDriverHooks>(&mut self, drv: &mut D) {
        let erase_one = |q: &mut VecDeque<u8>| -> bool { q.pop_back().is_some() };
        let echo = self.lflag() & lflag::ECHO != 0 && self.lflag() & lflag::ECHOE != 0;
        let emit = |drv: &mut D| {
            if echo {
                drv.driver_write(b"\x08 \x08");
            }
        };
        // Skip trailing blanks.
        while matches!(self.canon.back(), Some(&b) if b == b' ' || b == b'\t') {
            if erase_one(&mut self.canon) {
                emit(drv);
            }
        }
        // Erase the word.
        while matches!(self.canon.back(), Some(&b) if b != b' ' && b != b'\t') {
            if erase_one(&mut self.canon) {
                emit(drv);
            }
        }
    }

    /// VKILL: clear the whole current line; ECHOK renders a fresh line.
    fn do_kill<D: TtyDriverHooks>(&mut self, drv: &mut D) {
        let lf = self.lflag();
        if lf & lflag::ECHO != 0 && lf & lflag::ECHOK != 0 {
            // Erase each echoed char back to line start.
            if lf & lflag::ECHOE != 0 {
                for _ in 0..self.canon.len() {
                    drv.driver_write(b"\x08 \x08");
                }
            } else {
                drv.driver_write(b"\n");
            }
        }
        self.canon.clear();
    }

    /// Move the completed canonical line (already includes any
    /// terminator byte) into the read queue.
    fn flush_line(&mut self) {
        while let Some(b) = self.canon.pop_front() {
            self.readq.push_back(b);
        }
    }

    /// ISIG dispatch: if `b` matches a signal cc and ISIG is set, raise
    /// it on the fg pgrp, drop the in-progress line, echo `^X`, and
    /// return true (byte consumed).
    fn handle_isig<D: TtyDriverHooks>(&mut self, drv: &mut D, b: u8) -> bool {
        if self.lflag() & lflag::ISIG == 0 {
            return false;
        }
        let vintr = self.cc(cc::VINTR);
        let vquit = self.cc(cc::VQUIT);
        let vsusp = self.cc(cc::VSUSP);
        let sig = if b != 0 && b == vintr {
            Sig::Int
        } else if b != 0 && b == vquit {
            Sig::Quit
        } else if b != 0 && b == vsusp {
            Sig::Tstp
        } else {
            return false;
        };
        // Echo the visible marker where the user typed (Linux ECHOCTL).
        if self.lflag() & lflag::ECHO != 0 && self.lflag() & lflag::ECHOCTL != 0 {
            drv.driver_write(&[b'^', b ^ 0x40]);
            drv.driver_write(b"\n");
        }
        if self.is_canon() {
            self.canon.clear();
        }
        drv.signal_fg_pgrp(sig);
        true
    }

    /// One input byte through the canonical editor. Returns true if the
    /// byte completed a line (caller flushes).
    fn canon_byte<D: TtyDriverHooks>(&mut self, drv: &mut D, b: u8) {
        let verase = self.cc(cc::VERASE);
        let vkill = self.cc(cc::VKILL);
        let vwerase = self.cc(cc::VWERASE);
        let veof = self.cc(cc::VEOF);
        let veol = self.cc(cc::VEOL);
        let veol2 = self.cc(cc::VEOL2);

        if verase != 0 && b == verase {
            self.do_erase(drv);
            return;
        }
        if vwerase != 0 && b == vwerase && self.lflag() & lflag::IEXTEN != 0 {
            self.do_werase(drv);
            return;
        }
        if vkill != 0 && b == vkill {
            self.do_kill(drv);
            return;
        }
        if veof != 0 && b == veof {
            // ^D: complete the line so far WITHOUT the ^D byte. At line
            // start that flushes an empty line → read returns 0 (EOF).
            if self.canon.is_empty() {
                self.eof_pending = true;
            } else {
                self.flush_line();
            }
            return;
        }
        // Echo (after edit keys handled — they echo their own visuals).
        self.echo_byte(drv, b);

        let is_eol = b == b'\n'
            || (veol != 0 && b == veol)
            || (veol2 != 0 && b == veol2 && self.lflag() & lflag::IEXTEN != 0);
        if is_eol {
            if self.canon.len() < CANON_CAP {
                self.canon.push_back(b);
            }
            self.flush_line();
            return;
        }
        if self.canon.len() < CANON_CAP {
            self.canon.push_back(b);
        }
    }

    /// Apply c_iflag CR/NL remapping to one raw byte. Returns None when
    /// the byte is dropped (IGNCR).
    fn map_input(&self, raw: u8) -> Option<u8> {
        let il = self.iflag();
        if raw == b'\r' {
            if il & iflag::IGNCR != 0 {
                return None;
            }
            if il & iflag::ICRNL != 0 {
                return Some(b'\n');
            }
            return Some(b'\r');
        }
        if raw == b'\n' && il & iflag::INLCR != 0 {
            return Some(b'\r');
        }
        Some(raw)
    }

    /// OPOST one output byte into `out`, tracking the column. ONLCR maps
    /// \n→\r\n, OCRNL maps \r→\n, tabs expand to the next tab stop.
    fn output_byte(&mut self, raw: u8, out: &mut alloc::vec::Vec<u8>) {
        let of = self.oflag();
        match raw {
            b'\n' => {
                if of & oflag::ONLCR != 0 {
                    out.push(b'\r');
                    out.push(b'\n');
                    self.out_col = 0;
                } else {
                    if of & oflag::ONLRET != 0 {
                        self.out_col = 0;
                    }
                    out.push(b'\n');
                }
            }
            b'\r' => {
                if of & oflag::OCRNL != 0 {
                    out.push(b'\n');
                } else {
                    self.out_col = 0;
                    out.push(b'\r');
                }
            }
            b'\t' => {
                let next = (self.out_col / TAB_WIDTH + 1) * TAB_WIDTH;
                while self.out_col < next {
                    out.push(b' ');
                    self.out_col += 1;
                }
            }
            0x08 => {
                if self.out_col > 0 {
                    self.out_col -= 1;
                }
                out.push(0x08);
            }
            _ => {
                if raw >= 0x20 {
                    self.out_col += 1;
                }
                out.push(raw);
            }
        }
    }
}

impl LdiscOps for NTty {
    fn receive_buf<D: TtyDriverHooks>(&mut self, drv: &mut D, input: &[u8]) {
        for &raw in input {
            let b = match self.map_input(raw) {
                Some(b) => b,
                None => continue,
            };
            if self.handle_isig(drv, b) {
                continue;
            }
            if self.is_canon() {
                self.canon_byte(drv, b);
            } else {
                // Raw mode: byte straight to the read queue. Echo only
                // when ECHO set (e.g. bash with ECHO on but ICANON off).
                self.echo_byte(drv, b);
                self.readq.push_back(b);
            }
        }
    }

    fn read(&mut self, buf: &mut [u8]) -> usize {
        if buf.is_empty() {
            return 0;
        }
        if self.is_canon() {
            // Canonical: return whole lines, never split a partial line.
            // Drain up to a newline/terminator or buf.len(), whichever
            // first. The terminator is part of the line.
            if self.readq.is_empty() {
                // EOF: ^D at line start with nothing queued → 0.
                if self.eof_pending {
                    self.eof_pending = false;
                }
                return 0;
            }
            let mut n = 0;
            while n < buf.len() {
                match self.readq.pop_front() {
                    Some(b) => {
                        buf[n] = b;
                        n += 1;
                        if b == b'\n' {
                            break;
                        }
                    }
                    None => break,
                }
            }
            n
        } else {
            // Raw: VMIN bytes minimum semantics — return what's available
            // up to buf.len(). VTIME is a documented simplification: we
            // do not implement the inter-byte timer (no clock at this
            // layer); the tty core's blocking honours VMIN.
            let vmin = self.cc(cc::VMIN) as usize;
            if self.readq.len() < vmin && vmin > 0 {
                return 0;
            }
            let mut n = 0;
            while n < buf.len() {
                match self.readq.pop_front() {
                    Some(b) => {
                        buf[n] = b;
                        n += 1;
                    }
                    None => break,
                }
            }
            n
        }
    }

    fn write<D: TtyDriverHooks>(&mut self, drv: &mut D, buf: &[u8]) -> usize {
        if self.oflag() & oflag::OPOST == 0 {
            drv.driver_write(buf);
            return buf.len();
        }
        let mut out = alloc::vec::Vec::with_capacity(buf.len() + 8);
        for &b in buf {
            self.output_byte(b, &mut out);
        }
        drv.driver_write(&out);
        buf.len()
    }

    fn poll(&self) -> u32 {
        let mut mask = pollmask::POLLOUT;
        if self.has_input() {
            mask |= pollmask::POLLIN;
        }
        mask
    }

    fn termios(&self) -> [u8; TERMIOS_BYTES] {
        self.termios
    }

    fn set_termios(&mut self, new: &[u8; TERMIOS_BYTES]) {
        self.termios = *new;
        // Switching out of ICANON exposes any half-built line as raw
        // input (Linux flushes the canon buffer into the read queue).
        if !self.is_canon() {
            while let Some(b) = self.canon.pop_front() {
                self.readq.push_back(b);
            }
        }
    }
}
