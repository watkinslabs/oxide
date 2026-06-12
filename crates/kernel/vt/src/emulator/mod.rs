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

use crate::vc::{Attr, Charset, Vc};

mod osc;
mod sgr;
use osc::OSC_CAP;

/// Parser superstate (mirrors fbcon `CsiState`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CsiState {
    Ground,
    Esc,
    CsiParam,
    CsiInter,
    /// `ESC (` / `)` / `*` / `+` — awaiting the charset designator byte.
    Charset,
    /// `ESC #` — awaiting the DEC private byte (e.g. `8` = DECALN).
    Hash,
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

/// Reply-buffer capacity. Longest reply is CPR `ESC[<r>;<c>R` — at most
/// `2 + 5 + 1 + 5 + 1` bytes for 16-bit row/col decimals. 24 is ample.
const REPLY_CAP: usize = 24;

/// An owned, drained terminal answerback (DSR/CPR reply). Carries the
/// fixed-size buffer + valid length so the caller can drop the borrow on
/// the `Emulator` before injecting the bytes into the tty input ring.
#[derive(Copy, Clone)]
pub struct ReplyBytes {
    bytes: [u8; REPLY_CAP],
    len: usize,
}

impl ReplyBytes {
    /// The valid reply bytes (empty when no reply was pending). # C: O(1).
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Whether any reply is pending. # C: O(1).
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

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
    /// Which Gn slot an `ESC ( / ) / * / +` designator targets: the raw
    /// intermediate byte (`(`=G0, `)`=G1, `*`=G2, `+`=G3). VT100/VT102
    /// only render via G0/G1 (GL), but we accept all four designators.
    charset_slot: u8,
    utf8_pending: [u8; 4],
    utf8_len: u8,
    /// Linux console font-mapping mode (`SGR 11`/`12`, `vt.c` disp_ctrl):
    /// when set, incoming bytes are NOT UTF-8 decoded — each raw byte maps
    /// through CP437 to a glyph (this is how ncurses on `TERM=linux` draws
    /// box-drawing: `smacs`=`\E[11m`, raw CP437 bytes, `rmacs`=`\E[10m`).
    disp_ctrl: bool,
    /// `SGR 12` second alternate font: like `disp_ctrl` but XOR each byte
    /// with 0x80 first (Linux `toggle_meta`).
    toggle_meta: bool,
    /// IRM insert/replace mode (ANSI mode 4, `CSI 4h`/`CSI 4l`). When set,
    /// each printed glyph shifts the rest of the line right by its width
    /// before being placed (Linux `vt.c` `decim`); default replace.
    insert_mode: bool,
    /// Saw `ESC` (0x1b) inside an OSC/DCS string: the next byte decides if
    /// this is a 7-bit ST (`ESC \`) terminator or just payload. Prevents a
    /// bare `\` in a title from ending the string early (`57§14`).
    str_esc: bool,
    /// Collected OSC payload bytes (between `ESC ]` and the terminator),
    /// parsed by `osc::osc_dispatch` for color-control OSCs.
    osc_buf: [u8; OSC_CAP],
    osc_len: u16,
    /// Pending terminal answerback bytes (DSR/CPR reply per `CSI n`). The
    /// console driver drains this after each `feed`/`feed_bytes` and
    /// injects it into the tty INPUT ring so the program that issued the
    /// query reads its reply back (Linux `respond_string` →
    /// `tty_insert_flip_string`). Pure data here — no I/O in `vtdata`.
    reply: [u8; REPLY_CAP],
    reply_len: u8,
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
            charset_slot: 0,
            utf8_pending: [0; 4],
            utf8_len: 0,
            disp_ctrl: false,
            toggle_meta: false,
            insert_mode: false,
            str_esc: false,
            osc_buf: [0; OSC_CAP],
            osc_len: 0,
            reply: [0; REPLY_CAP],
            reply_len: 0,
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
        // Any byte can move the cursor (print advance, CR, CSI move);
        // flag it so `consw::render` repaints the cursor cell. Cheap
        // and correct — over-marking only costs one extra cell blit.
        vc.mark_cursor_dirty();
        // CAN (0x18) / SUB (0x1a) abort any escape/control sequence and
        // return to ground without executing it (ECMA-48 / vt102). SUB in
        // some terminals prints a substitution glyph; Linux just aborts.
        if (byte == 0x18 || byte == 0x1a) && self.state != CsiState::Ground {
            self.state = CsiState::Ground;
            return;
        }
        match self.state {
            CsiState::Ground => self.ground(vc, byte),
            CsiState::Esc => self.esc(vc, byte),
            CsiState::CsiParam => self.csi_param(vc, byte),
            CsiState::CsiInter => self.csi_inter(vc, byte),
            CsiState::Charset => self.charset_designate(vc, byte),
            CsiState::Hash => self.hash(vc, byte),
            CsiState::Osc => {
                // First OSC payload byte: enter the string-collection state
                // and start the buffer fresh.
                self.osc_len = 0;
                self.state = CsiState::OscString;
                self.osc_string(vc, byte);
            }
            CsiState::OscString => self.osc_string(vc, byte),
            CsiState::DcsString => self.dcs_string(byte),
        }
    }

    fn ground(&mut self, vc: &mut Vc, byte: u8) {
        // Linux font-mapping mode (after `\E[11m`/`\E[12m`): bytes are raw
        // CP437 glyphs, NOT UTF-8 — this is how ncurses draws box-drawing on
        // TERM=linux. ESC still breaks out so the closing `\E[10m` is parsed.
        if self.disp_ctrl && byte != 0x1b {
            let b = if self.toggle_meta { byte ^ 0x80 } else { byte };
            self.print(vc, crate::cp437::to_unicode(b));
            return;
        }
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
            0x0e => vc.gl = 1, // SO — invoke G1 into GL
            0x0f => vc.gl = 0, // SI — invoke G0 into GL
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
            // C1 8-bit controls (0x80..0x9f): only when NOT inside a UTF-8
            // sequence (the continuation arm above claims those first). Each
            // is the single-byte form of an `ESC Fe` two-byte control.
            b if (0x80..=0x9f).contains(&b) => self.c1(vc, b),
            _ => {
                // C0 control we don't handle, or stray continuation.
                self.utf8_len = 0;
            }
        }
    }

    /// C1 8-bit control (`0x80..0x9f`) = the single-byte equivalent of an
    /// `ESC Fe` sequence (`0x9b`=CSI, `0x9d`=OSC, `0x90`=DCS, `0x84`=IND,
    /// `0x85`=NEL, `0x88`=HTS, `0x8d`=RI, `0x9c`=ST). Others have no screen
    /// effect on a vt102 (`57§3`).
    fn c1(&mut self, vc: &mut Vc, byte: u8) {
        match byte {
            0x84 => self.index(vc), // IND
            0x85 => {
                // NEL: index + CR.
                self.line_feed(vc);
                vc.x = 0;
                vc.wrap_pending = false;
            }
            0x88 => vc.set_tab(),         // HTS
            0x8d => self.reverse_index(vc), // RI
            0x90 => self.state = CsiState::DcsString, // DCS
            0x9b => {
                // CSI: begin a control sequence (reset accumulators).
                self.state = CsiState::CsiParam;
                self.params = [0; MAX_PARAMS];
                self.param_count = 0;
                self.param_seen = false;
                self.intermediate = [0; MAX_INTER];
                self.inter_count = 0;
                self.private = false;
            }
            0x9d => self.state = CsiState::Osc, // OSC
            _ => {}                              // ST (0x9c) in ground / others
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
            b'E' => {
                // NEL: next line = CR + LF (IND semantics, then col 0).
                self.line_feed(vc);
                vc.x = 0;
                vc.wrap_pending = false;
                self.state = CsiState::Ground;
            }
            b'H' => {
                // HTS: set a tab stop at the cursor column.
                vc.set_tab();
                self.state = CsiState::Ground;
            }
            b'c' => {
                self.full_reset(vc);
                self.state = CsiState::Ground;
            }
            b'Z' => {
                // DECID (obsolete) — same answerback as primary DA.
                self.answer_da();
                self.state = CsiState::Ground;
            }
            // ESC ( / ) / * / + — charset designator; next byte selects.
            b'(' | b')' | b'*' | b'+' => {
                self.charset_slot = byte;
                self.state = CsiState::Charset;
            }
            // ESC # — DEC private; next byte (e.g. `8` = DECALN).
            b'#' => self.state = CsiState::Hash,
            _ => self.state = CsiState::Ground,
        }
    }

    /// `ESC ( / ) / * / +` final byte: designate Gn = ASCII (`B`) or DEC
    /// Special Graphics (`0`). Other designators (UK `A`, etc.) fall back
    /// to ASCII — VT100/VT102 render only ASCII + special graphics.
    fn charset_designate(&mut self, vc: &mut Vc, byte: u8) {
        let set = match byte {
            b'0' => Charset::DecSpecial,
            _ => Charset::Ascii, // B (ASCII), A (UK), etc.
        };
        match self.charset_slot {
            b'(' => vc.g0 = set,
            b')' => vc.g1 = set,
            // G2/G3 (`*`/`+`): accepted but unused by GL on a vt102.
            _ => {}
        }
        self.state = CsiState::Ground;
    }

    /// `ESC #` final byte. `8` = DECALN screen-alignment fill. Others are
    /// DEC double-width/height line attrs — tolerated (no cell effect on a
    /// single-width emulator).
    fn hash(&mut self, vc: &mut Vc, byte: u8) {
        if byte == b'8' {
            vc.decaln();
        }
        self.state = CsiState::Ground;
    }

    fn csi_param(&mut self, vc: &mut Vc, byte: u8) {
        // C0 controls embedded in a CSI execute immediately, then parsing
        // resumes in the same state (ECMA-48 / vt102 do_con_trol).
        if byte < 0x20 {
            self.exec_c0(vc, byte);
            return;
        }
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

    fn csi_inter(&mut self, vc: &mut Vc, byte: u8) {
        // CSI with intermediate bytes. C0 controls execute in place; a
        // final byte (0x40..0x7e) dispatches the (intermediate-bearing)
        // sequence; another intermediate accumulates.
        if byte < 0x20 {
            self.exec_c0(vc, byte);
            return;
        }
        match byte {
            0x20..=0x2f => {
                let i = self.inter_count as usize;
                if i < MAX_INTER {
                    self.intermediate[i] = byte;
                    self.inter_count += 1;
                }
            }
            0x40..=0x7e => {
                self.csi_final(vc, byte);
                self.state = CsiState::Ground;
            }
            _ => self.state = CsiState::Ground,
        }
    }

    /// Execute a C0 control encountered mid-CSI (BS/HT/LF/VT/FF/CR/SO/SI/
    /// BEL). Mirrors the ground-state handling so embedded controls have
    /// their normal effect without aborting the sequence. # parse-helper.
    fn exec_c0(&mut self, vc: &mut Vc, byte: u8) {
        match byte {
            0x08 => self.backspace(vc),
            0x09 => self.tab(vc),
            0x0a | 0x0b | 0x0c => self.line_feed(vc),
            0x0d => {
                vc.x = 0;
                vc.wrap_pending = false;
            }
            0x0e => vc.gl = 1,
            0x0f => vc.gl = 0,
            _ => {} // BEL / others: no screen effect
        }
    }

    /// DCS string collection. Identical termination rules to OSC (`BEL`,
    /// `ESC \`, or C1 `ST`); the payload is consumed without being executed
    /// as commands (`57§14`). We answer no DCS requests on a vt102 console.
    fn dcs_string(&mut self, byte: u8) {
        if self.str_esc {
            self.str_esc = false;
            if byte == b'\\' {
                self.state = CsiState::Ground;
            }
            return;
        }
        match byte {
            0x07 | 0x9c => self.state = CsiState::Ground,
            0x1b => self.str_esc = true,
            _ => {}
        }
    }

    // ---- printable + C0 effects -------------------------------------

    fn print(&mut self, vc: &mut Vc, cp: u32) {
        // East-Asian width: 0 = combining (composes onto the prior cell — a
        // single-glyph cell can't store the mark, so drop it without moving
        // the cursor, preserving alignment), 1 = narrow, 2 = wide (`57§9.2`).
        let w = crate::eaw::char_width(cp);
        if w == 0 {
            return;
        }
        // Resolve a pending wrap left by a prior last-column write.
        if vc.wrap_pending && vc.autowrap {
            vc.x = 0;
            self.line_feed(vc);
            vc.wrap_pending = false;
        }
        // A width-2 glyph that would straddle the right margin wraps first
        // (autowrap) or is dropped (no autowrap — it can't fit one column).
        if w == 2 && vc.x + 1 >= vc.cols {
            if vc.autowrap {
                vc.x = 0;
                self.line_feed(vc);
                vc.wrap_pending = false;
            } else {
                return;
            }
        }
        // IRM: shift the rest of the line right by the glyph width before
        // placing it, so existing cells are pushed aside rather than
        // overwritten (Linux `vt.c` insert mode).
        if self.insert_mode {
            self.insert_blanks(vc, w as u16);
        }
        vc.put_glyph_w(cp, w == 2);
        let adv = w as u16;
        if vc.x + adv >= vc.cols {
            if vc.autowrap {
                // Pending-wrap (Linux/xterm): stay in the last column; the
                // next printable triggers the wrap.
                vc.x = vc.cols - 1;
                vc.wrap_pending = true;
            } else {
                vc.x = vc.cols - 1;
            }
        } else {
            vc.x += adv;
        }
    }

    fn backspace(&mut self, vc: &mut Vc) {
        vc.wrap_pending = false;
        if vc.x > 0 {
            vc.x -= 1;
        }
    }

    fn tab(&mut self, vc: &mut Vc) {
        // HT advances to the next SET tab stop (TBC/HTS-editable bitmap),
        // clamped at the right margin (VT100). Pending-wrap is cleared.
        vc.wrap_pending = false;
        vc.x = vc.next_tab();
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
        // RIS (`ESC c`): default attrs, all modes/charsets/tabs reset,
        // scroll region full, cursor home, screen cleared (DEC STD 070).
        vc.attr = Attr::default();
        vc.autowrap = true;
        vc.origin_mode = false;
        vc.cursor_visible = true;
        vc.g0 = Charset::Ascii;
        vc.g1 = Charset::Ascii;
        vc.gl = 0;
        vc.scroll_top = 0;
        vc.scroll_bot = vc.rows - 1;
        vc.reset_tabs();
        vc.reset_palette(None);
        vc.set_default_fg(crate::vc::DEFAULT_FG_RGB);
        vc.set_default_bg(crate::vc::DEFAULT_BG_RGB);
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
            b'A' => {
                // CUU: up n, no scroll. If the cursor starts at/above the
                // region top, clamp at row 0; else clamp at the region top
                // (VT100 confines cursor moves to the region from inside).
                let n = self.count_param(0);
                let floor = if vc.y >= vc.scroll_top { vc.scroll_top } else { 0 };
                vc.y = vc.y.saturating_sub(n).max(floor);
                vc.wrap_pending = false;
            }
            b'B' => {
                // CUD: down n, no scroll. Clamp at the region bottom when
                // starting inside the region, else at the last row.
                let n = self.count_param(0);
                let ceil = if vc.y <= vc.scroll_bot { vc.scroll_bot } else { vc.rows - 1 };
                vc.y = (vc.y + n).min(ceil);
                vc.wrap_pending = false;
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
                // CUP / HVP: 1-based (row,col). Origin mode makes the row
                // relative to the scroll region (Vc::move_to handles it).
                let r = self.count_param(0).saturating_sub(1);
                let c = self.count_param(1).saturating_sub(1);
                vc.move_to(r, c);
            }
            b'J' => vc.erase_display(self.param(0, 0)),
            b'K' => vc.erase_line(self.param(0, 0)),
            b'X' => vc.erase_chars(self.count_param(0)), // ECH

            b'g' => {
                // TBC: 0 = clear stop at cursor, 3 = clear all stops.
                match self.param(0, 0) {
                    3 => vc.clear_all_tabs(),
                    _ => vc.clear_tab(),
                }
            }
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
            b'n' => self.device_status_report(vc),
            // DA (primary device attributes). Only the plain/`0` request
            // (non-private) is answered; `CSI > c` (secondary) is skipped.
            b'c' => if !self.private { self.answer_da() },
            b'h' | b'l' => self.set_mode(vc, byte == b'h'),
            _ => {} // tolerate unknown final
        }
    }

    fn set_mode(&mut self, vc: &mut Vc, set: bool) {
        if !self.private {
            // ANSI modes (no `?`). IRM (4) = insert/replace; the rest are
            // unused on a vt102 console.
            if self.param(0, 0) == 4 {
                self.insert_mode = set;
            }
            return;
        }
        match self.param(0, 0) {
            // DECOM origin mode: cursor confined to + addressed relative to
            // the scroll region. Per DEC, toggling DECOM homes the cursor.
            6 => {
                vc.origin_mode = set;
                vc.home();
            }
            // DECAWM autowrap.
            7 => {
                vc.autowrap = set;
                vc.wrap_pending = false;
            }
            // DECTCEM cursor visibility (renderer-only flag).
            25 => vc.cursor_visible = set,
            // Alternate screen buffer. ?47/?1047 switch buffers; ?1049 also
            // saves/restores the cursor (covered by enter_alt/leave_alt).
            // htop/top/vim/less use these (smcup/rmcup).
            47 | 1047 | 1049 => if set { vc.enter_alt() } else { vc.leave_alt() },
            _ => {}
        }
    }

    /// DSR / CPR (`CSI n`, non-private) — Linux `do_con_trol` `'n'` /
    /// `status_report` + `cursor_report`. Builds the answerback into the
    /// reply buffer; the console driver drains it via `take_reply` and
    /// feeds it back into the tty INPUT ring (Linux `respond_string`).
    ///   `CSI 5 n` (DSR) → `CSI 0 n` ("terminal OK").
    ///   `CSI 6 n` (CPR) → `CSI <row> ; <col> R`, row/col 1-based.
    /// Private-prefixed `CSI ? n` (DEC DSR) is ignored here (no DEC
    /// extended reports wired).
    fn device_status_report(&mut self, vc: &Vc) {
        if self.private {
            return;
        }
        match self.param(0, 0) {
            5 => {
                self.reply_len = 0;
                self.push_reply(b"\x1b[0n");
            }
            6 => {
                let row = (vc.y as u32) + 1;
                let col = (vc.x as u32) + 1;
                self.reply_len = 0;
                self.push_reply(b"\x1b[");
                self.push_reply_dec(row);
                self.push_reply(b";");
                self.push_reply_dec(col);
                self.push_reply(b"R");
            }
            _ => {}
        }
    }

    /// Primary DA (`CSI c` / DECID `ESC Z`) answerback. Linux console
    /// replies the VT102 id `ESC [ ? 6 c` (`vt.c` `VT102ID`); the console
    /// driver injects it into the tty input ring like CPR. # parse-helper.
    fn answer_da(&mut self) {
        self.reply_len = 0;
        self.push_reply(b"\x1b[?6c");
    }

    /// Append literal bytes to the reply buffer (clamped to `REPLY_CAP`).
    /// # parse-helper.
    fn push_reply(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let i = self.reply_len as usize;
            if i < REPLY_CAP {
                self.reply[i] = b;
                self.reply_len += 1;
            }
        }
    }

    /// Append a decimal-encoded `u32` to the reply buffer. # parse-helper.
    fn push_reply_dec(&mut self, mut v: u32) {
        let mut buf = [0u8; 10];
        let mut n = 0;
        loop {
            buf[n] = b'0' + (v % 10) as u8;
            v /= 10;
            n += 1;
            if v == 0 {
                break;
            }
        }
        // Digits were produced least-significant-first; emit reversed.
        while n > 0 {
            n -= 1;
            let d = buf[n];
            let i = self.reply_len as usize;
            if i < REPLY_CAP {
                self.reply[i] = d;
                self.reply_len += 1;
            }
        }
    }

    /// Drain the pending answerback (DSR/CPR) reply, if any. Returns the
    /// bytes and clears the buffer; empty slice when no reply is pending.
    /// The console driver calls this after `feed`/`feed_bytes` and injects
    /// the result into the tty INPUT ring (Linux `respond_string`).
    /// # C: O(reply_len).
    pub fn take_reply(&mut self) -> ReplyBytes {
        let len = self.reply_len as usize;
        self.reply_len = 0;
        ReplyBytes { bytes: self.reply, len }
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
        // DECSTBM moves the cursor to home (region-top under origin mode,
        // absolute (0,0) otherwise).
        vc.home();
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
