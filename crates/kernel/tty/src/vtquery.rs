// Per-VT terminal output state machine + ANSI query responder.
//
// crossterm / tcell / bubbletea and most TUI libs emit DSR / DA
// query escapes at startup and BLOCK on the reply:
//   * `ESC[6n`  (DSR-CPR)  → terminal must answer `ESC[<row>;<col>R`
//   * `ESC[5n`  (DSR-OK)   → terminal must answer `ESC[0n`
//   * `ESC[c` / `ESC[0c`   (DA1) → terminal must answer `ESC[?1;2c`
// The size probe is "move cursor to 999;999, then DSR" — the move
// clamps to the screen, so the CPR reply reports the real size.
// Without a responder these reads block forever (the oxide console
// never generates a reply). This module is the responder.
//
// Design: a pure output-side parser (`TermState`) tracks the cursor
// (1-based, clamped to ROWS×COLS) and, on a recognized query, emits
// a reply into a fixed stack buffer (`Reply`). No alloc, no format!.
// `process_output` (kernel-only) feeds bytes through the per-VT
// `TermState` and injects each reply into that VT's RX ring + wakes
// parked readers, so a blocked `ConsoleInode::read` unblocks.
//
// The parser is split out (and not kernel-gated) so it is exercised
// by hosted `cargo test -p tty` against a capture buffer — QEMU boot
// is the final gate, not the dev loop (CLAUDE.md verify-left rule).

/// Console/VT geometry. Fixed 24×80 default, mirroring the winsize
/// `016_ioctl.rs:106` reports for CharDev fds. Cursor coordinates
/// clamp to these bounds.
pub const ROWS: u8 = 24;
pub const COLS: u8 = 80;

/// Escape-parser phase.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum Phase {
    /// Outside any escape sequence.
    Normal,
    /// Saw `ESC`; awaiting the next byte.
    Esc,
    /// Saw `ESC[`; accumulating CSI params until a final byte.
    Csi,
}

/// Max numeric params we retain from a CSI sequence (`row;col` needs 2;
/// keep 3 for headroom). Extra params past this are parsed but dropped.
const MAX_PARAMS: usize = 3;

/// Capacity of a single emitted reply. Longest reply is the CPR form
/// `ESC[24;80R` (8 bytes); 16 leaves headroom for 3-digit coords.
const REPLY_CAP: usize = 16;

/// A fixed-size reply byte string built without alloc. `process_output`
/// injects `as_bytes()` into the VT input ring.
pub struct Reply {
    buf: [u8; REPLY_CAP],
    len: usize,
}

impl Reply {
    const fn new() -> Self { Self { buf: [0; REPLY_CAP], len: 0 } }

    fn push(&mut self, b: u8) {
        if self.len < REPLY_CAP {
            self.buf[self.len] = b;
            self.len += 1;
        }
    }

    /// Append a u8 as decimal ASCII digits (no leading zeros; "0" for 0).
    /// Manual itoa — klog macros only take `&'static str`, and we want
    /// zero alloc on the output hot path.
    fn push_u8(&mut self, mut v: u8) {
        if v == 0 { self.push(b'0'); return; }
        let mut tmp = [0u8; 3];
        let mut n = 0;
        while v > 0 {
            tmp[n] = b'0' + (v % 10);
            v /= 10;
            n += 1;
        }
        while n > 0 {
            n -= 1;
            self.push(tmp[n]);
        }
    }

    /// The reply bytes ready to inject into the input ring.
    /// # C: O(1)
    pub fn as_bytes(&self) -> &[u8] { &self.buf[..self.len] }
}

/// Per-VT output-side terminal state. Pure: `step` mutates the cursor
/// and returns `Some(Reply)` when a query escape demands an answer.
pub struct TermState {
    /// 1-based cursor row, clamped to `1..=ROWS`.
    pub cursor_row: u8,
    /// 1-based cursor col, clamped to `1..=COLS`.
    pub cursor_col: u8,
    phase: Phase,
    /// Accumulated CSI numeric params. Slot `i` is meaningful only when
    /// bit `i` of `seen` is set; otherwise the param was omitted and the
    /// caller-supplied default applies (Linux `ESC[;5H` → row defaults).
    params: [u16; MAX_PARAMS],
    /// Index of the param slot currently being accumulated.
    cur: usize,
    /// Bitmask: bit `i` set ⇒ slot `i` received ≥1 digit.
    seen: u8,
    /// CSI private marker `?` (e.g. `ESC[?6n`) — suppresses the reply.
    private: bool,
}

impl TermState {
    /// Fresh state: cursor home (1,1), parser idle.
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            cursor_row: 1,
            cursor_col: 1,
            phase: Phase::Normal,
            params: [0; MAX_PARAMS],
            cur: 0,
            seen: 0,
            private: false,
        }
    }

    fn reset_csi(&mut self) {
        self.params = [0; MAX_PARAMS];
        self.cur = 0;
        self.seen = 0;
        self.private = false;
    }

    /// Param `i` if it received a digit, else `dflt`. An omitted param
    /// (`ESC[;5H`, `ESC[6n` slot 1) yields the default.
    fn param(&self, i: usize, dflt: u16) -> u16 {
        if i < MAX_PARAMS && (self.seen & (1 << i)) != 0 {
            self.params[i]
        } else {
            dflt
        }
    }

    /// Clamp a cursor row to `1..=ROWS`.
    fn clamp_row(v: u16) -> u8 { (v.clamp(1, ROWS as u16)) as u8 }
    /// Clamp a cursor col to `1..=COLS`.
    fn clamp_col(v: u16) -> u8 { (v.clamp(1, COLS as u16)) as u8 }

    /// Feed one output byte. Updates the cursor; returns a reply when
    /// the byte completed a query escape.
    /// # C: O(1)
    pub fn step(&mut self, b: u8) -> Option<Reply> {
        match self.phase {
            Phase::Normal => { self.step_normal(b); None }
            Phase::Esc => { self.step_esc(b); None }
            Phase::Csi => self.step_csi(b),
        }
    }

    fn step_normal(&mut self, b: u8) {
        match b {
            b'\r' => self.cursor_col = 1,
            b'\n' => self.cursor_row = (self.cursor_row + 1).min(ROWS),
            0x08 => self.cursor_col = self.cursor_col.saturating_sub(1).max(1),
            0x1b => self.phase = Phase::Esc,
            0x20..=0x7e => {
                self.cursor_col += 1;
                if self.cursor_col > COLS {
                    self.cursor_col = 1;
                    self.cursor_row = (self.cursor_row + 1).min(ROWS);
                }
            }
            _ => {}
        }
    }

    fn step_esc(&mut self, b: u8) {
        if b == b'[' {
            self.reset_csi();
            self.phase = Phase::Csi;
        } else {
            // Two-byte / unsupported escapes (e.g. ESC c, ESC M) — drop
            // the intermediate and return to Normal. Good enough for
            // cursor tracking; none of these queries demand a reply.
            self.phase = Phase::Normal;
        }
    }

    fn step_csi(&mut self, b: u8) -> Option<Reply> {
        match b {
            b'0'..=b'9' => {
                let d = (b - b'0') as u16;
                if self.cur < MAX_PARAMS {
                    let slot = &mut self.params[self.cur];
                    *slot = slot.saturating_mul(10).saturating_add(d);
                    self.seen |= 1 << self.cur;
                }
                None
            }
            b';' => {
                // Advance to next slot; extra params past MAX_PARAMS are
                // parsed-then-dropped (cur saturates so digits no-op).
                if self.cur < MAX_PARAMS { self.cur += 1; }
                None
            }
            b'?' => { self.private = true; None }
            _ => {
                let r = self.finish_csi(b);
                self.phase = Phase::Normal;
                r
            }
        }
    }

    fn finish_csi(&mut self, fin: u8) -> Option<Reply> {
        match fin {
            b'H' | b'f' => {
                self.cursor_row = Self::clamp_row(self.param(0, 1));
                self.cursor_col = Self::clamp_col(self.param(1, 1));
                None
            }
            b'A' => {
                let n = self.param(0, 1).min(ROWS as u16) as u8;
                self.cursor_row = self.cursor_row.saturating_sub(n).max(1);
                None
            }
            b'B' => {
                let n = self.param(0, 1).min(ROWS as u16) as u8;
                self.cursor_row = (self.cursor_row.saturating_add(n)).min(ROWS);
                None
            }
            b'C' => {
                let n = self.param(0, 1).min(COLS as u16) as u8;
                self.cursor_col = (self.cursor_col.saturating_add(n)).min(COLS);
                None
            }
            b'D' => {
                let n = self.param(0, 1).min(COLS as u16) as u8;
                self.cursor_col = self.cursor_col.saturating_sub(n).max(1);
                None
            }
            b'n' if !self.private => {
                match self.param(0, 0) {
                    6 => {
                        // DSR-CPR: ESC[<row>;<col>R
                        let mut r = Reply::new();
                        r.push(0x1b);
                        r.push(b'[');
                        r.push_u8(self.cursor_row);
                        r.push(b';');
                        r.push_u8(self.cursor_col);
                        r.push(b'R');
                        Some(r)
                    }
                    5 => {
                        // DSR-OK: ESC[0n
                        let mut r = Reply::new();
                        r.push(0x1b);
                        r.push(b'[');
                        r.push(b'0');
                        r.push(b'n');
                        Some(r)
                    }
                    _ => None,
                }
            }
            b'c' if !self.private => {
                // DA1 (Primary Device Attributes). `ESC[c` / `ESC[0c`.
                // Answer VT100 with Advanced Video Option: ESC[?1;2c.
                let mut r = Reply::new();
                r.push(0x1b);
                r.push(b'[');
                r.push(b'?');
                r.push(b'1');
                r.push(b';');
                r.push(b'2');
                r.push(b'c');
                Some(r)
            }
            // J, K, m, r, h, l, private `?...n`/`?...c`, etc. — consume,
            // no cursor change, no reply.
            _ => None,
        }
    }
}

impl Default for TermState {
    fn default() -> Self { Self::new() }
}

#[cfg(target_os = "oxide-kernel")]
pub use kernel_glue::process_output;

#[cfg(target_os = "oxide-kernel")]
mod kernel_glue {
    use super::TermState;
    use sync::{Spinlock, Tty as TtyClass};

    /// Per-VT output-side terminal state, mirroring `live::VT_RINGS`
    /// indexing (`live::vt_index`).
    static VT_TERM: [Spinlock<TermState, TtyClass>; crate::live::N_VT] =
        [const { Spinlock::new(TermState::new()) }; crate::live::N_VT];

    /// Feed VT `vt`'s output bytes through its terminal state machine,
    /// tracking the cursor and answering DSR/DA queries by injecting
    /// the reply into the VT's RX input ring (and waking parked readers).
    /// Called from `ConsoleInode::write` before the UART emit; the raw
    /// `buf` is processed here, the UART path is unchanged.
    /// # C: O(buf.len())
    pub fn process_output(vt: u8, buf: &[u8]) {
        let idx = crate::live::vt_index_pub(vt);
        let mut st = VT_TERM[idx].lock();
        for &b in buf {
            if let Some(reply) = st.step(b) {
                crate::live::inject_and_wake(vt, reply.as_bytes());
            }
        }
    }
}

#[cfg(test)]
mod tests;
