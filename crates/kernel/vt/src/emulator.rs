// ECMA-48 / vt102 emulator (Linux `vt.c` `do_con_trol`). Relocated and
// adapted from `fbcon::Console`'s parser: same CSI/SGR/ESC/OSC/UTF-8
// state machine, but it mutates a `Vc` cell grid instead of blitting
// pixels. One `feed(&mut Vc, byte)` advances the machine.
//
// Parity scope (matches fbcon + standard vt102): printable w/ UTF-8 +
// DECAWM autowrap, LF/CR/BS/TAB/BEL, CSI cursor moves
// (CUU/CUD/CUF/CUB/CNL/CPL/CHA/VPA/CUP/HVP), ED(J)/EL(K), SGR(m) incl
// 16-color + bright + 256-color + truecolor parse, DECSC/DECRC (ESC 7/8
// and CSI s/u), IND/RI (ESC D/M), RIS (ESC c), DECSET/RST autowrap
// (?7h/?7l), scroll region (CSI r), IL/DL/ICH/DCH, SU/SD. Unknown
// sequences are tolerated (consumed, no panic).

use crate::vc::{Attr, Vc, TAB_WIDTH};

/// Parser superstate (mirrors fbcon `CsiState`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CsiState {
    Ground,
    Esc,
    CsiParam,
    CsiInter,
    Osc,
    OscString,
    DcsString,
}

impl Default for CsiState {
    fn default() -> Self {
        CsiState::Ground
    }
}

const MAX_PARAMS: usize = 16;
const MAX_INTER: usize = 4;

/// Emulator parser state. Holds no screen data — that lives in `Vc`.
#[derive(Clone, Debug)]
pub struct Emulator {
    state: CsiState,
    params: [u32; MAX_PARAMS],
    /// Number of params seen minus 1 (index of the current param).
    param_count: u8,
    /// Whether the current param slot has received any digit.
    param_seen: bool,
    intermediate: [u8; MAX_INTER],
    inter_count: u8,
    private: bool,
    utf8_pending: [u8; 4],
    utf8_len: u8,
}

impl Default for Emulator {
    fn default() -> Self {
        Emulator {
            state: CsiState::Ground,
            params: [0; MAX_PARAMS],
            param_count: 0,
            param_seen: false,
            intermediate: [0; MAX_INTER],
            inter_count: 0,
            private: false,
            utf8_pending: [0; 4],
            utf8_len: 0,
        }
    }
}

impl Emulator {
    /// New emulator in the ground state.
    /// # C: O(1).
    pub fn new() -> Self {
        Emulator::default()
    }

    /// Current parser superstate (test/debug).
    /// # C: O(1).
    pub fn state(&self) -> CsiState {
        self.state
    }

    /// Feed a slice of bytes through the emulator, mutating `vc`.
    /// # C: O(n) plus O(cols*rows) per scroll/erase byte.
    pub fn feed_bytes(&mut self, vc: &mut Vc, bytes: &[u8]) {
        for &b in bytes {
            self.feed(vc, b);
        }
    }

    /// Feed one byte through the state machine, mutating `vc`. Never
    /// panics and never indexes the grid out of bounds.
    /// # C: O(1) amortized; O(cols*rows) on a scroll/erase byte.
    pub fn feed(&mut self, vc: &mut Vc, byte: u8) {
        match self.state {
            CsiState::Ground => self.ground(vc, byte),
            CsiState::Esc => self.esc(vc, byte),
            CsiState::CsiParam => self.csi_param(vc, byte),
            CsiState::CsiInter => self.csi_inter(vc, byte),
            CsiState::Osc => {
                // OSC opening byte (e.g. the parameter digit); discard
                // and enter the string-collection state.
                self.state = CsiState::OscString;
                self.osc_string(byte);
            }
            CsiState::OscString => self.osc_string(byte),
            CsiState::DcsString => {
                // Collect until ST (ESC \) / BEL; we only need to not
                // misinterpret the payload as commands.
                if byte == 0x07 {
                    self.state = CsiState::Ground;
                } else if byte == 0x1b {
                    // crude: treat following byte handling via Esc state
                    self.state = CsiState::Esc;
                }
            }
        }
    }

    fn ground(&mut self, vc: &mut Vc, byte: u8) {
        match byte {
            0x1b => {
                self.state = CsiState::Esc;
            }
            0x07 => {} // BEL — no screen effect
            0x08 => self.backspace(vc),
            0x09 => self.tab(vc),
            0x0a | 0x0b | 0x0c => self.line_feed(vc), // LF/VT/FF
            0x0d => {
                vc.x = 0;
                vc.wrap_pending = false;
            }
            b if (0x20..0x7f).contains(&b) => self.print(vc, b as u32),
            // UTF-8 lead byte
            b if (0xc2..0xf5).contains(&b) => {
                self.utf8_pending[0] = b;
                self.utf8_len = 1;
            }
            // UTF-8 continuation
            b if (b & 0xc0) == 0x80 && self.utf8_len > 0 => {
                let i = self.utf8_len as usize;
                if i < 4 {
                    self.utf8_pending[i] = b;
                    self.utf8_len += 1;
                }
                if self.utf8_full() {
                    let cp = self.utf8_decode();
                    self.utf8_len = 0;
                    self.print(vc, cp);
                }
            }
            _ => {
                // C0 control we don't handle, or stray continuation.
                self.utf8_len = 0;
            }
        }
    }

    fn esc(&mut self, vc: &mut Vc, byte: u8) {
        match byte {
            b'[' => {
                self.state = CsiState::CsiParam;
                self.params = [0; MAX_PARAMS];
                self.param_count = 0;
                self.param_seen = false;
                self.intermediate = [0; MAX_INTER];
                self.inter_count = 0;
                self.private = false;
            }
            b']' => self.state = CsiState::Osc,
            b'P' => self.state = CsiState::DcsString,
            b'7' => {
                vc.save_cursor();
                self.state = CsiState::Ground;
            }
            b'8' => {
                vc.restore_cursor();
                self.state = CsiState::Ground;
            }
            b'D' => {
                self.index(vc);
                self.state = CsiState::Ground;
            }
            b'M' => {
                self.reverse_index(vc);
                self.state = CsiState::Ground;
            }
            b'c' => {
                self.full_reset(vc);
                self.state = CsiState::Ground;
            }
            // ESC ( / ESC ) charset designators — consume one more byte.
            b'(' | b')' | b'*' | b'+' => {
                self.intermediate[0] = byte;
                self.inter_count = 1;
                self.state = CsiState::CsiInter; // reuse to swallow next
            }
            _ => self.state = CsiState::Ground,
        }
    }

    fn csi_param(&mut self, vc: &mut Vc, byte: u8) {
        match byte {
            b'0'..=b'9' => {
                let i = self.param_count as usize;
                if i < MAX_PARAMS {
                    self.params[i] = self.params[i]
                        .saturating_mul(10)
                        .saturating_add((byte - b'0') as u32);
                }
                self.param_seen = true;
            }
            b';' => {
                if (self.param_count as usize) < MAX_PARAMS - 1 {
                    self.param_count += 1;
                }
                self.param_seen = false;
            }
            // Private markers < = > ?
            0x3c..=0x3f => {
                self.private = true;
                let i = self.inter_count as usize;
                if i < MAX_INTER {
                    self.intermediate[i] = byte;
                    self.inter_count += 1;
                }
            }
            // Intermediate bytes (space..slash)
            0x20..=0x2f => {
                let i = self.inter_count as usize;
                if i < MAX_INTER {
                    self.intermediate[i] = byte;
                    self.inter_count += 1;
                }
                self.state = CsiState::CsiInter;
            }
            0x40..=0x7e => {
                self.csi_final(vc, byte);
                self.state = CsiState::Ground;
            }
            _ => self.state = CsiState::Ground,
        }
    }

    fn csi_inter(&mut self, _vc: &mut Vc, byte: u8) {
        // Either a CSI with intermediates, or an ESC-designator swallow.
        // In both cases the next final/letter ends the sequence; we do
        // not act on charset designators (kept ASCII-only).
        match byte {
            0x20..=0x2f => {
                let i = self.inter_count as usize;
                if i < MAX_INTER {
                    self.intermediate[i] = byte;
                    self.inter_count += 1;
                }
            }
            _ => self.state = CsiState::Ground,
        }
    }

    fn osc_string(&mut self, byte: u8) {
        match byte {
            0x07 => self.state = CsiState::Ground, // BEL terminates
            b'\\' => self.state = CsiState::Ground, // ST tail
            _ => {} // collect/ignore title bytes
        }
    }

    // ---- printable + C0 effects -------------------------------------

    fn print(&mut self, vc: &mut Vc, cp: u32) {
        if vc.wrap_pending && vc.autowrap {
            vc.x = 0;
            self.line_feed(vc);
            vc.wrap_pending = false;
        }
        vc.put_glyph(cp);
        if vc.x + 1 >= vc.cols {
            if vc.autowrap {
                // Defer the wrap (Linux/xterm pending-wrap): stay in the
                // last column; the next printable triggers the wrap.
                vc.wrap_pending = true;
            } else {
                vc.x = vc.cols - 1;
            }
        } else {
            vc.x += 1;
        }
    }

    fn backspace(&mut self, vc: &mut Vc) {
        vc.wrap_pending = false;
        if vc.x > 0 {
            vc.x -= 1;
        }
    }

    fn tab(&mut self, vc: &mut Vc) {
        vc.wrap_pending = false;
        let next = ((vc.x / TAB_WIDTH) + 1) * TAB_WIDTH;
        vc.x = next.min(vc.cols - 1);
    }

    fn line_feed(&mut self, vc: &mut Vc) {
        vc.wrap_pending = false;
        if vc.y >= vc.scroll_bot {
            vc.scroll_up(1);
            vc.y = vc.scroll_bot;
        } else if vc.y + 1 < vc.rows {
            vc.y += 1;
        }
    }

    fn index(&mut self, vc: &mut Vc) {
        // IND: like LF but no CR.
        self.line_feed(vc);
    }

    fn reverse_index(&mut self, vc: &mut Vc) {
        vc.wrap_pending = false;
        if vc.y <= vc.scroll_top {
            vc.scroll_down(1);
            vc.y = vc.scroll_top;
        } else {
            vc.y -= 1;
        }
    }

    fn full_reset(&mut self, vc: &mut Vc) {
        vc.attr = Attr::default();
        vc.autowrap = true;
        vc.scroll_top = 0;
        vc.scroll_bot = vc.rows - 1;
        vc.clear();
        *self = Emulator::new();
    }

    // ---- CSI final dispatch -----------------------------------------

    /// Value of param `i` (0-based) or `default` if unset/zero-as-unset
    /// per `default_one`.
    fn param(&self, i: usize, default: u32) -> u32 {
        let count = self.param_count as usize + 1;
        if i < count && (i < self.param_count as usize || self.param_seen) {
            self.params[i]
        } else {
            default
        }
    }

    /// Param `i` treated as a count: 0 or unset → 1 (ECMA-48 default).
    fn count_param(&self, i: usize) -> u16 {
        let v = self.param(i, 1);
        if v == 0 {
            1
        } else {
            v.min(u16::MAX as u32) as u16
        }
    }

    fn csi_final(&mut self, vc: &mut Vc, byte: u8) {
        match byte {
            b'A' => vc.y = vc.y.saturating_sub(self.count_param(0)).max(vc.scroll_top),
            b'B' => {
                vc.y = (vc.y + self.count_param(0)).min(vc.rows - 1);
            }
            b'C' => {
                vc.x = (vc.x + self.count_param(0)).min(vc.cols - 1);
                vc.wrap_pending = false;
            }
            b'D' => {
                vc.x = vc.x.saturating_sub(self.count_param(0));
                vc.wrap_pending = false;
            }
            b'E' => {
                // CNL: down n, col 0.
                vc.y = (vc.y + self.count_param(0)).min(vc.rows - 1);
                vc.x = 0;
                vc.wrap_pending = false;
            }
            b'F' => {
                // CPL: up n, col 0.
                vc.y = vc.y.saturating_sub(self.count_param(0));
                vc.x = 0;
                vc.wrap_pending = false;
            }
            b'G' | b'`' => {
                // CHA / HPA: column n (1-based).
                let c = self.count_param(0).saturating_sub(1);
                vc.x = c.min(vc.cols - 1);
                vc.wrap_pending = false;
            }
            b'd' => {
                // VPA: row n (1-based).
                let r = self.count_param(0).saturating_sub(1);
                vc.y = r.min(vc.rows - 1);
                vc.wrap_pending = false;
            }
            b'H' | b'f' => {
                let r = self.count_param(0).saturating_sub(1);
                let c = self.count_param(1).saturating_sub(1);
                vc.y = r.min(vc.rows - 1);
                vc.x = c.min(vc.cols - 1);
                vc.wrap_pending = false;
            }
            b'J' => vc.erase_display(self.param(0, 0)),
            b'K' => vc.erase_line(self.param(0, 0)),
            b'L' => self.insert_lines(vc, self.count_param(0)),
            b'M' => self.delete_lines(vc, self.count_param(0)),
            b'@' => self.insert_blanks(vc, self.count_param(0)),
            b'P' => self.delete_chars(vc, self.count_param(0)),
            b'S' => vc.scroll_up(self.count_param(0)),
            b'T' => vc.scroll_down(self.count_param(0)),
            b'r' => self.set_scroll_region(vc),
            b'm' => self.sgr(vc),
            b's' => vc.save_cursor(),
            b'u' => vc.restore_cursor(),
            b'h' | b'l' => self.set_mode(vc, byte == b'h'),
            _ => {} // tolerate unknown final
        }
    }

    fn set_mode(&mut self, vc: &mut Vc, set: bool) {
        if !self.private {
            return; // only DEC private modes acted on (e.g. ?7)
        }
        let m = self.param(0, 0);
        if m == 7 {
            vc.autowrap = set;
            vc.wrap_pending = false;
        }
    }

    fn set_scroll_region(&mut self, vc: &mut Vc) {
        let top = self.count_param(0).saturating_sub(1).min(vc.rows - 1);
        let bot = self.param(1, vc.rows as u32);
        let bot = (bot.saturating_sub(1)).min((vc.rows - 1) as u32) as u16;
        if top < bot {
            vc.scroll_top = top;
            vc.scroll_bot = bot;
        } else {
            vc.scroll_top = 0;
            vc.scroll_bot = vc.rows - 1;
        }
        vc.x = 0;
        vc.y = vc.scroll_top;
        vc.wrap_pending = false;
    }

    fn insert_lines(&mut self, vc: &mut Vc, n: u16) {
        if vc.y < vc.scroll_top || vc.y > vc.scroll_bot {
            return;
        }
        let save = vc.scroll_top;
        vc.scroll_top = vc.y;
        vc.scroll_down(n);
        vc.scroll_top = save;
    }

    fn delete_lines(&mut self, vc: &mut Vc, n: u16) {
        if vc.y < vc.scroll_top || vc.y > vc.scroll_bot {
            return;
        }
        let save = vc.scroll_top;
        vc.scroll_top = vc.y;
        vc.scroll_up(n);
        vc.scroll_top = save;
    }

    fn insert_blanks(&mut self, vc: &mut Vc, n: u16) {
        let n = n.min(vc.cols - vc.x);
        let row = vc.y;
        // Shift right within the row from cursor.
        for c in (vc.x..vc.cols).rev() {
            if c >= vc.x + n {
                if let Some(src) = vc.cell_at(c - n, row) {
                    vc.set_cell(c, row, src);
                }
            } else {
                vc.blank_cell(c, row);
            }
        }
        vc.wrap_pending = false;
    }

    fn delete_chars(&mut self, vc: &mut Vc, n: u16) {
        let n = n.min(vc.cols - vc.x);
        let row = vc.y;
        for c in vc.x..vc.cols {
            if c + n < vc.cols {
                if let Some(src) = vc.cell_at(c + n, row) {
                    vc.set_cell(c, row, src);
                }
            } else {
                vc.blank_cell(c, row);
            }
        }
        vc.wrap_pending = false;
    }

    fn sgr(&mut self, vc: &mut Vc) {
        let n = self.param_count as usize + 1;
        let mut i = 0;
        if n == 1 && !self.param_seen {
            // bare CSI m == CSI 0 m
            vc.attr.reset();
            return;
        }
        while i < n {
            let p = self.params[i];
            match p {
                0 => vc.attr.reset(),
                1 => vc.attr.bold = true,
                4 => vc.attr.underline = true,
                7 => vc.attr.reverse = true,
                22 => vc.attr.bold = false,
                24 => vc.attr.underline = false,
                27 => vc.attr.reverse = false,
                30..=37 => vc.attr.fg = (p - 30) as u8,
                90..=97 => vc.attr.fg = (p - 90 + 8) as u8,
                40..=47 => vc.attr.bg = (p - 40) as u8,
                100..=107 => vc.attr.bg = (p - 100 + 8) as u8,
                39 => vc.attr.fg = crate::vc::DEFAULT_FG,
                49 => vc.attr.bg = crate::vc::DEFAULT_BG,
                38 => {
                    if i + 2 < n && self.params[i + 1] == 5 {
                        vc.attr.fg = self.params[i + 2].min(255) as u8;
                        i += 2;
                    } else if i + 4 < n && self.params[i + 1] == 2 {
                        // truecolor → nearest is out of scope; keep index
                        // path simple: store the red channel byte.
                        vc.attr.fg = self.params[i + 2].min(255) as u8;
                        i += 4;
                    }
                }
                48 => {
                    if i + 2 < n && self.params[i + 1] == 5 {
                        vc.attr.bg = self.params[i + 2].min(255) as u8;
                        i += 2;
                    } else if i + 4 < n && self.params[i + 1] == 2 {
                        vc.attr.bg = self.params[i + 2].min(255) as u8;
                        i += 4;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    // ---- UTF-8 ------------------------------------------------------

    fn utf8_full(&self) -> bool {
        let lead = self.utf8_pending[0];
        let need = if (lead & 0xe0) == 0xc0 {
            2
        } else if (lead & 0xf0) == 0xe0 {
            3
        } else if (lead & 0xf8) == 0xf0 {
            4
        } else {
            1
        };
        self.utf8_len as usize >= need
    }

    fn utf8_decode(&self) -> u32 {
        let b = &self.utf8_pending[..self.utf8_len as usize];
        match b.len() {
            2 => ((b[0] & 0x1f) as u32) << 6 | (b[1] & 0x3f) as u32,
            3 => {
                ((b[0] & 0x0f) as u32) << 12
                    | ((b[1] & 0x3f) as u32) << 6
                    | (b[2] & 0x3f) as u32
            }
            4 => {
                ((b[0] & 0x07) as u32) << 18
                    | ((b[1] & 0x3f) as u32) << 12
                    | ((b[2] & 0x3f) as u32) << 6
                    | (b[3] & 0x3f) as u32
            }
            _ => b[0] as u32,
        }
    }
}
