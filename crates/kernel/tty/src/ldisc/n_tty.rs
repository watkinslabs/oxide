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

/// Withheld-output cap while IXON-stopped. A producer that keeps writing
/// while flow is stopped is bounded here (Linux backpressures the writer;
/// at this lock-free layer we cap and drop past the limit — the visible
/// effect on resume is identical for the scroll-pause use case).
const HOLD_CAP: usize = 4096;

/// IXON input-byte classification (Linux `n_tty.c` flow control). Pure:
/// the caller supplies the live termios bits + the byte, and acts on the
/// verdict (set/clear `stopped`, consume the byte). Host-testable alone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowAction {
    /// VSTOP (^S): set `stopped`, consume the byte (not queued/echoed).
    Stop,
    /// VSTART (^Q) or any byte under IXANY while stopped: clear `stopped`,
    /// consume the byte.
    Start,
    /// Not a flow-control byte — process normally.
    Normal,
}

/// Classify one input byte for IXON flow control given the live termios.
///   * `iflag` — c_iflag (IXON / IXANY bits read via `crate::pty::iflag`)
///   * `vstop` = c_cc[VSTOP] (^S), `vstart` = c_cc[VSTART] (^Q)
///   * `b` = the (i-mapped) input byte, `stopped` = current flow state
///
/// Linux rules: IXON off → always Normal. VSTOP byte → Stop. VSTART byte
/// → Start. While `stopped` with IXANY set, ANY other byte → Start (Linux
/// restarts output on any key). A `0` cc disables that control char.
/// # C: O(1)
pub fn flow_action(iflag: u32, vstop: u8, vstart: u8, b: u8, stopped: bool) -> FlowAction {
    if iflag & crate::pty::iflag::IXON == 0 { return FlowAction::Normal; }
    if vstop != 0 && b == vstop { return FlowAction::Stop; }
    if vstart != 0 && b == vstart { return FlowAction::Start; }
    // IXANY: any byte resumes paused output (but is still processed).
    if stopped && iflag & crate::pty::iflag::IXANY != 0 { return FlowAction::Start; }
    FlowAction::Normal
}

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
    /// Set when the most recent `read` returned 0 because it consumed a
    /// pending EOF (^D at line start), cleared whenever `read` returns
    /// data or finds the queue genuinely empty. Lets the tty core (T4)
    /// distinguish "EOF → return 0 to user" from "nothing ready → park".
    eof_consumed: bool,
    /// IXON output-flow-control state (Linux `n_tty.c` `stop_flag`). A
    /// VSTOP byte (^S) in the input path sets it; VSTART (^Q) — or any
    /// byte under IXANY — clears it. While set, `write` withholds output
    /// into `out_hold` instead of pushing to the driver; the next clear
    /// flushes `out_hold`. Mirrors a real terminal pausing scroll.
    stopped: bool,
    /// OPOST-processed output bytes withheld while `stopped`. Flushed to
    /// the driver in order when flow resumes (^Q / IXANY). Bounded by the
    /// same cap as the canon buffer so a stuck ^S can't grow unbounded.
    out_hold: VecDeque<u8>,
    /// Set the moment a hangup is delivered (`TtyStruct::hangup` / pty
    /// master close). A hung-up ldisc: reads return EOF (0), writes are
    /// dropped, input is flushed. Linux `tty_hangup` drops the tty to a
    /// "ghost" state where operations short-circuit (28§5).
    hung_up: bool,
}

/// Noncanonical (raw-mode) VMIN/VTIME read decision (Linux `n_tty.c`
/// `n_tty_read` / `job_control` + the VMIN/VTIME state machine). Pure:
/// no clock, no lock — the tty core (T4) supplies elapsed values and
/// acts on the verdict. Host-testable in isolation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VmtDecision {
    /// Enough is satisfied — drain `n` bytes (`min(available, buf_len)`)
    /// and return. `n` may be 0 (polling / timeout with nothing queued).
    ReturnNow(usize),
    /// Block until an RX wake OR the monotonic clock reaches the carried
    /// deadline (relative ns from the read-entry base — caller adds its
    /// `now_ns` base). A VTIME timer.
    BlockUntil(u64),
    /// Block until an RX wake, no timer (MIN>0, TIME==0: wait for MIN
    /// bytes; or MIN>0, TIME>0 before the first byte arrives).
    BlockNoDeadline,
}

/// VTIME unit: tenths of a second, in nanoseconds (Linux c_cc[VTIME] is
/// in 1/10 s). `TIME * VTIME_TENTH_NS` is the timer length.
pub const VTIME_TENTH_NS: u64 = 100_000_000;

/// Decide a noncanonical read's next action from the 4 Linux VMIN/VTIME
/// cases. Inputs are all caller-measured so this stays a pure function:
///   * `min`  = c_cc[VMIN], `time` = c_cc[VTIME] (raw cc bytes)
///   * `avail` = bytes drainable now, `buf_len` = caller buffer
///   * `since_start_ns` = ns since read entry (for MIN==0,TIME>0)
///   * `since_byte_ns`  = ns since the most recent byte arrived, and
///     `got_any` = at least one byte has arrived this read (interbyte
///     timer, MIN>0 TIME>0)
///
/// The 4 Linux cases:
///   MIN==0,TIME==0: polling — return immediately (0 if empty).
///   MIN>0, TIME==0: block until ≥MIN available (no timer).
///   MIN==0,TIME>0 : read timer — first byte ends it; else BlockUntil
///                   start+TIME; on expiry return what's there (maybe 0).
///   MIN>0, TIME>0 : interbyte timer — before any byte: BlockNoDeadline;
///                   after first byte: return at MIN/buf-full, else
///                   BlockUntil last-byte+TIME; on interbyte expiry
///                   return what's there.
/// # C: O(1)
pub fn vmin_vtime_decision(
    min: u8, time: u8, avail: usize, buf_len: usize,
    since_start_ns: u64, since_byte_ns: u64, got_any: bool,
) -> VmtDecision {
    let min = min as usize;
    let take = avail.min(buf_len);
    match (min == 0, time == 0) {
        // MIN==0, TIME==0: pure polling read.
        (true, true) => VmtDecision::ReturnNow(take),
        // MIN>0, TIME==0: block until at least MIN bytes (or buf full).
        (false, true) => {
            if avail >= min || avail >= buf_len { VmtDecision::ReturnNow(take) }
            else { VmtDecision::BlockNoDeadline }
        }
        // MIN==0, TIME>0: read timer on the FIRST byte.
        (true, false) => {
            if avail > 0 { return VmtDecision::ReturnNow(take); }
            let dl = time as u64 * VTIME_TENTH_NS;
            if since_start_ns >= dl { VmtDecision::ReturnNow(0) }
            else { VmtDecision::BlockUntil(dl) }
        }
        // MIN>0, TIME>0: interbyte timer (starts after the first byte).
        (false, false) => {
            if avail >= min || avail >= buf_len { return VmtDecision::ReturnNow(take); }
            if !got_any { return VmtDecision::BlockNoDeadline; }
            let dl = time as u64 * VTIME_TENTH_NS;
            if since_byte_ns >= dl { VmtDecision::ReturnNow(take) }
            else { VmtDecision::BlockUntil(dl) }
        }
    }
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
            eof_consumed: false,
            stopped: false,
            out_hold: VecDeque::new(),
            hung_up: false,
        }
    }

    /// True when the most recent `read` returned 0 specifically because it
    /// consumed a pending EOF (vs the queue being empty). The tty core
    /// returns 0 to the user on EOF but parks on empty.
    /// # C: O(1)
    pub fn eof_consumed(&self) -> bool {
        self.eof_consumed
    }

    /// Build with a caller-supplied termios image (raw-mode ptys etc.).
    /// # C: O(1)
    pub fn with_termios(t: [u8; TERMIOS_BYTES]) -> Self {
        let mut n = Self::new();
        n.termios = t;
        n
    }

    /// True when `read` would return ≥1 byte or signal EOF. The tty core
    /// (T4) calls this under its lock to decide whether to park. A hung-up
    /// ldisc is always "ready" (read returns 0/EOF, never parks).
    /// # C: O(1)
    pub fn has_input(&self) -> bool {
        self.hung_up || !self.readq.is_empty() || self.eof_pending
    }

    /// Bytes immediately drainable from the read queue.
    /// # C: O(1)
    pub fn available(&self) -> usize {
        self.readq.len()
    }

    fn cc(&self, idx: usize) -> u8 {
        self.termios[TERMIOS_OFF_CC + idx]
    }

    /// True when ICANON is set (canonical line reads). The tty core (T4)
    /// branches on this: canonical reads block until a whole line; raw
    /// reads run the VMIN/VTIME state machine.
    /// # C: O(1)
    pub fn canonical(&self) -> bool {
        self.is_canon()
    }

    /// c_cc[VMIN] — noncanonical minimum byte count.
    /// # C: O(1)
    pub fn vmin(&self) -> u8 {
        self.cc(cc::VMIN)
    }

    /// c_cc[VTIME] — noncanonical read/interbyte timer in 1/10 s.
    /// # C: O(1)
    pub fn vtime(&self) -> u8 {
        self.cc(cc::VTIME)
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

    /// Flush all IXON-withheld output to the driver (called when ^Q /
    /// IXANY clears the stop). No-op when nothing is held.
    fn flush_hold<D: TtyDriverHooks>(&mut self, drv: &mut D) {
        if self.out_hold.is_empty() { return; }
        let bytes: alloc::vec::Vec<u8> = self.out_hold.drain(..).collect();
        drv.driver_write(&bytes);
    }

    /// True while IXON flow control has output stopped (^S seen, no ^Q
    /// yet). Introspection / tests.
    /// # C: O(1)
    pub fn stopped(&self) -> bool { self.stopped }

    /// True once a hangup has been delivered (reads return EOF, writes
    /// dropped). The tty core reports EOF on read in this state.
    /// # C: O(1)
    pub fn is_hung_up(&self) -> bool { self.hung_up }

    /// Hang up the ldisc (Linux `tty_ldisc_hangup`): flush every queue
    /// (input line, read queue, withheld output), clear flow state, and
    /// latch the hung-up flag. After this, `receive_buf` ignores input,
    /// `read` reports EOF, and `write` drops. Idempotent.
    /// # C: O(N) queued bytes dropped
    pub fn hangup(&mut self) {
        self.canon.clear();
        self.readq.clear();
        self.out_hold.clear();
        self.eof_pending = false;
        self.stopped = false;
        self.hung_up = true;
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

    /// Drain up to `buf.len()` raw bytes from the read queue, IGNORING
    /// VMIN (the tty core has already decided the read is satisfied — via
    /// `vmin_vtime_decision` ReturnNow, e.g. a VTIME timeout that returns
    /// fewer than VMIN bytes). Returns the count copied. Canonical-mode
    /// callers use `read` (line semantics); this is the raw drain the
    /// VMIN/VTIME state machine commits with.
    /// # C: O(N) bytes copied
    pub fn read_raw_drain(&mut self, buf: &mut [u8]) -> usize {
        self.eof_consumed = false;
        if self.hung_up && self.readq.is_empty() {
            self.eof_consumed = true;
            return 0;
        }
        let mut n = 0;
        while n < buf.len() {
            match self.readq.pop_front() {
                Some(b) => { buf[n] = b; n += 1; }
                None => break,
            }
        }
        n
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
        if self.hung_up { return; }
        for &raw in input {
            let b = match self.map_input(raw) {
                Some(b) => b,
                None => continue,
            };
            // IXON flow control runs BEFORE everything else in the input
            // path (Linux n_tty: ^S/^Q are intercepted before ISIG/canon).
            match flow_action(self.iflag(), self.cc(cc::VSTOP), self.cc(cc::VSTART), b, self.stopped) {
                FlowAction::Stop => { self.stopped = true; continue; }
                FlowAction::Start => {
                    self.stopped = false;
                    self.flush_hold(drv);
                    // VSTART/^S are consumed; an IXANY restart byte (other
                    // than ^S/^Q) still falls through to be processed.
                    if b == self.cc(cc::VSTART) || (self.cc(cc::VSTOP) != 0 && b == self.cc(cc::VSTOP)) {
                        continue;
                    }
                }
                FlowAction::Normal => {}
            }
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
        self.eof_consumed = false;
        if buf.is_empty() {
            return 0;
        }
        // Hung-up tty: any remaining queued bytes drain first, then EOF.
        if self.hung_up && self.readq.is_empty() {
            self.eof_consumed = true;
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
                    self.eof_consumed = true;
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
        // Hung-up tty: writes are dropped (Linux returns -EIO; the core
        // maps the hung-up state to EIO — here the byte goes nowhere).
        if self.hung_up { return buf.len(); }
        let mut out = alloc::vec::Vec::with_capacity(buf.len() + 8);
        if self.oflag() & oflag::OPOST == 0 {
            out.extend_from_slice(buf);
        } else {
            for &b in buf { self.output_byte(b, &mut out); }
        }
        // IXON: while flow is stopped (^S), withhold the processed bytes
        // in `out_hold`; they flush in order on ^Q (flush_hold). The
        // caller still sees full consumption (Linux blocks the writer; we
        // buffer, then drop past HOLD_CAP).
        if self.stopped {
            for b in out { if self.out_hold.len() < HOLD_CAP { self.out_hold.push_back(b); } }
        } else {
            drv.driver_write(&out);
        }
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
