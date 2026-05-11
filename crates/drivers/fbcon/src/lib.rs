// Kernel framebuffer console per docs/49. PSF font parsing,
// xterm-256color ANSI/CSI parser, software glyph blit + scroll.
// Drives a per-VT backing dumb-buffer; the VT layer (50) calls
// `put` / `flush` for each connected console.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

use alloc::vec::Vec;

// ============================================================
// PSF font header (per linux/include/uapi/linux/kd.h notes +
// kernel `pcscreen_font.h`)
// ============================================================

pub const PSF1_MAGIC: [u8; 2] = [0x36, 0x04];
pub const PSF2_MAGIC: [u8; 4] = [0x72, 0xb5, 0x4a, 0x86];

pub const PSF1_MODE512:  u8 = 0x01;
pub const PSF1_MODEHASTAB: u8 = 0x02;
pub const PSF1_MODESEQ:  u8 = 0x04;

pub const PSF2_HAS_UNICODE_TABLE: u32 = 0x01;

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct Psf1Header {
    pub magic: [u8; 2],
    pub mode:  u8,
    pub charsize: u8,
}

#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct Psf2Header {
    pub magic:      [u8; 4],
    pub version:    u32,
    pub headersize: u32,
    pub flags:      u32,
    pub length:     u32,
    pub charsize:   u32,
    pub height:     u32,
    pub width:      u32,
}

// ============================================================
// ANSI / CSI parser state (vt102 + xterm-256color subset)
// ============================================================

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CsiState {
    Ground,
    Esc,         // saw \x1b
    Csi,         // \x1b[
    CsiParam,    // accumulating params
    CsiInter,    // intermediate char (space..slash)
    Osc,         // \x1b]
    OscString,
    Ss2, Ss3,    // \x1b N / \x1b O
    DcsEntry, DcsParam, DcsPassthrough, DcsString,
}

impl Default for CsiState { fn default() -> Self { CsiState::Ground } }

#[derive(Copy, Clone, Debug, Default)]
pub struct ParserState {
    pub state:       CsiState,
    pub params:      [u32; 16],
    pub param_count: u8,
    pub intermediate:[u8; 4],
    pub inter_count: u8,
    pub utf8_pending:[u8; 4],
    pub utf8_len:    u8,
}

/// Parse one input byte; returns the action the renderer should take.
/// # C: O(1)
pub fn step(state: &mut ParserState, byte: u8) -> Action {
    match state.state {
        CsiState::Ground => match byte {
            0x07 => Action::Bell,
            0x08 => Action::Backspace,
            0x09 => Action::Tab,
            0x0a => Action::Linefeed,
            0x0d => Action::CarriageReturn,
            0x1b => { state.state = CsiState::Esc; Action::None }
            b if b >= 0x20 && b < 0x7f => Action::PutChar(b as u32),
            // UTF-8 lead bytes
            b if b >= 0xc2 && b < 0xf5 => { state.utf8_pending[0] = b; state.utf8_len = 1; Action::None }
            // UTF-8 continuation
            b if (b & 0xc0) == 0x80 && state.utf8_len > 0 => {
                state.utf8_pending[state.utf8_len as usize] = b;
                state.utf8_len += 1;
                if utf8_full(state) {
                    let cp = utf8_decode(&state.utf8_pending[..state.utf8_len as usize]);
                    state.utf8_len = 0;
                    Action::PutChar(cp)
                } else { Action::None }
            }
            _ => Action::None,
        },
        CsiState::Esc => match byte {
            b'[' => { state.state = CsiState::CsiParam;
                      state.param_count = 0;
                      state.params = [0; 16];
                      state.intermediate = [0; 4];
                      state.inter_count = 0;
                      Action::None }
            b']' => { state.state = CsiState::Osc; Action::None }
            b'P' => { state.state = CsiState::DcsEntry; Action::None }
            b'7' => { state.state = CsiState::Ground; Action::SaveCursor }
            b'8' => { state.state = CsiState::Ground; Action::RestoreCursor }
            b'D' => { state.state = CsiState::Ground; Action::Index }
            b'M' => { state.state = CsiState::Ground; Action::ReverseIndex }
            b'c' => { state.state = CsiState::Ground; Action::FullReset }
            _    => { state.state = CsiState::Ground; Action::None }
        },
        CsiState::CsiParam => match byte {
            b'0'..=b'9' => {
                let i = state.param_count as usize;
                if i < 16 {
                    state.params[i] = state.params[i].saturating_mul(10) + (byte - b'0') as u32;
                }
                Action::None
            }
            b';' => {
                if state.param_count < 15 { state.param_count += 1; }
                Action::None
            }
            0x3c..=0x3f => {
                // Private-marker prefix: < = > ? per ECMA-48 §5.4.
                let i = state.inter_count as usize;
                if i < 4 { state.intermediate[i] = byte; state.inter_count += 1; }
                Action::None
            }
            0x20..=0x2f => {
                let i = state.inter_count as usize;
                if i < 4 { state.intermediate[i] = byte; state.inter_count += 1; }
                state.state = CsiState::CsiInter;
                Action::None
            }
            0x40..=0x7e => {
                let action = csi_final(state, byte);
                state.state = CsiState::Ground;
                action
            }
            _ => { state.state = CsiState::Ground; Action::None }
        },
        CsiState::CsiInter => match byte {
            0x40..=0x7e => {
                let action = csi_final(state, byte);
                state.state = CsiState::Ground;
                action
            }
            _ => { state.state = CsiState::Ground; Action::None }
        },
        CsiState::Osc => {
            state.state = CsiState::OscString;
            // OSC param byte (one digit + ;)
            Action::None
        }
        CsiState::OscString => match byte {
            0x07 => { state.state = CsiState::Ground; Action::None }    // BEL terminates OSC
            0x1b => Action::None,                                        // expecting \
            b'\\' => { state.state = CsiState::Ground; Action::None }   // ST
            _ => Action::None,
        },
        _ => { state.state = CsiState::Ground; Action::None }
    }
}

fn csi_final(state: &mut ParserState, byte: u8) -> Action {
    let n = state.param_count as usize + 1;
    let p1 = state.params[0];
    let p2 = if n > 1 { state.params[1] } else { 0 };
    match byte {
        b'A' => Action::CursorUp(p1.max(1)),
        b'B' => Action::CursorDown(p1.max(1)),
        b'C' => Action::CursorForward(p1.max(1)),
        b'D' => Action::CursorBackward(p1.max(1)),
        b'E' => Action::CursorNextLine(p1.max(1)),
        b'F' => Action::CursorPrevLine(p1.max(1)),
        b'G' => Action::CursorColumn(p1.max(1)),
        b'H' | b'f' => Action::CursorPosition(p1.max(1), p2.max(1)),
        b'J' => Action::EraseDisplay(p1),
        b'K' => Action::EraseLine(p1),
        b'L' => Action::InsertLine(p1.max(1)),
        b'M' => Action::DeleteLine(p1.max(1)),
        b'P' => Action::DeleteChar(p1.max(1)),
        b'@' => Action::InsertBlanks(p1.max(1)),
        b'S' => Action::ScrollUp(p1.max(1)),
        b'T' => Action::ScrollDown(p1.max(1)),
        b'd' => Action::CursorRow(p1.max(1)),
        b'r' => Action::SetScrollRegion(p1.max(1), p2.max(1)),
        b'm' => Action::SetGraphicRendition(state.params, n as u8),
        b'n' => Action::DeviceStatusReport(p1),
        b'h' | b'l' => {
            let set = byte == b'h';
            if state.intermediate[..state.inter_count as usize].first() == Some(&b'?') {
                Action::SetMode(p1, set)
            } else { Action::None }
        }
        _ => Action::None,
    }
}

fn utf8_full(state: &ParserState) -> bool {
    let lead = state.utf8_pending[0];
    let need = if (lead & 0xe0) == 0xc0 { 2 }
               else if (lead & 0xf0) == 0xe0 { 3 }
               else if (lead & 0xf8) == 0xf0 { 4 }
               else { 1 };
    state.utf8_len as usize >= need
}

fn utf8_decode(bytes: &[u8]) -> u32 {
    match bytes.len() {
        2 => ((bytes[0] & 0x1f) as u32) << 6 | (bytes[1] & 0x3f) as u32,
        3 => ((bytes[0] & 0x0f) as u32) << 12
           | ((bytes[1] & 0x3f) as u32) << 6
           | (bytes[2] & 0x3f) as u32,
        4 => ((bytes[0] & 0x07) as u32) << 18
           | ((bytes[1] & 0x3f) as u32) << 12
           | ((bytes[2] & 0x3f) as u32) << 6
           | (bytes[3] & 0x3f) as u32,
        _ => bytes[0] as u32,
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Action {
    None,
    PutChar(u32),
    Bell, Backspace, Tab, Linefeed, CarriageReturn,
    SaveCursor, RestoreCursor, Index, ReverseIndex, FullReset,
    CursorUp(u32), CursorDown(u32), CursorForward(u32), CursorBackward(u32),
    CursorNextLine(u32), CursorPrevLine(u32),
    CursorColumn(u32), CursorRow(u32),
    CursorPosition(u32, u32),
    EraseDisplay(u32), EraseLine(u32),
    InsertLine(u32), DeleteLine(u32),
    InsertBlanks(u32), DeleteChar(u32),
    ScrollUp(u32), ScrollDown(u32),
    SetScrollRegion(u32, u32),
    SetGraphicRendition([u32; 16], u8),
    DeviceStatusReport(u32),
    SetMode(u32, bool),
}

// ============================================================
// 16-color VGA palette (per Linux drivers/video/console/vgacon.c)
// ============================================================

pub const VGA_PALETTE: [[u8; 3]; 16] = [
    [0x00, 0x00, 0x00], [0xaa, 0x00, 0x00], [0x00, 0xaa, 0x00], [0xaa, 0x55, 0x00],
    [0x00, 0x00, 0xaa], [0xaa, 0x00, 0xaa], [0x00, 0xaa, 0xaa], [0xaa, 0xaa, 0xaa],
    [0x55, 0x55, 0x55], [0xff, 0x55, 0x55], [0x55, 0xff, 0x55], [0xff, 0xff, 0x55],
    [0x55, 0x55, 0xff], [0xff, 0x55, 0xff], [0x55, 0xff, 0xff], [0xff, 0xff, 0xff],
];

// ============================================================
// Console — owns a backing BGRA32 pixel buffer + cell grid + cursor
// ============================================================

#[derive(Clone, Debug)]
pub struct Console {
    pub xres:    u32,
    pub yres:    u32,
    pub pitch:   u32,             // bytes per scanline (xres * 4 for BGRA32)
    pub fb:      Vec<u8>,         // backing pixel buffer (size = pitch * yres)
    pub cell_w:  u32,             // glyph width  (8 for built-in font)
    pub cell_h:  u32,             // glyph height (16 for built-in font)
    pub cols:    u32,             // xres / cell_w
    pub rows:    u32,             // yres / cell_h
    pub cur_col: u32,
    pub cur_row: u32,
    pub fg:      [u8; 3],
    pub bg:      [u8; 3],
    pub parser:  ParserState,
}

impl Console {
    /// Allocate a console for the given resolution (BGRA32, 8×16 cells).
    /// # C: O(xres * yres) for the zero-fill.
    pub fn new(xres: u32, yres: u32) -> Self {
        let pitch = xres * 4;
        let mut fb = Vec::with_capacity((pitch * yres) as usize);
        fb.resize((pitch * yres) as usize, 0);
        let cell_w = 8;
        let cell_h = 16;
        Self {
            xres, yres, pitch, fb, cell_w, cell_h,
            cols: xres / cell_w, rows: yres / cell_h,
            cur_col: 0, cur_row: 0,
            fg: [0xff, 0xff, 0xff],
            bg: [0x00, 0x00, 0x00],
            parser: ParserState::default(),
        }
    }

    /// Feed one byte through the ANSI parser; apply the resulting
    /// Action against the backing buffer.
    /// # C: O(cell_w * cell_h) for PutChar (glyph blit).
    pub fn put_byte(&mut self, byte: u8) {
        let action = step(&mut self.parser, byte);
        self.apply(action);
    }

    /// Feed a buffer of bytes.
    /// # C: O(N * cell_w * cell_h) — bounded glyph blit per byte.
    pub fn put(&mut self, bytes: &[u8]) {
        for &b in bytes { self.put_byte(b); }
    }

    fn apply(&mut self, action: Action) {
        match action {
            Action::None => {}
            Action::PutChar(cp) => {
                self.blit_glyph(cp);
                self.advance_cursor();
            }
            Action::Backspace => {
                if self.cur_col > 0 { self.cur_col -= 1; }
                else if self.cur_row > 0 { self.cur_row -= 1; self.cur_col = self.cols - 1; }
            }
            Action::Tab => {
                let next = ((self.cur_col / 8) + 1) * 8;
                self.cur_col = next.min(self.cols - 1);
            }
            Action::Linefeed => { self.cur_row += 1; if self.cur_row >= self.rows { self.scroll_up(1); self.cur_row = self.rows - 1; } }
            Action::CarriageReturn => { self.cur_col = 0; }
            Action::CursorUp(n)        => { self.cur_row = self.cur_row.saturating_sub(n); }
            Action::CursorDown(n)      => { self.cur_row = (self.cur_row + n).min(self.rows.saturating_sub(1)); }
            Action::CursorForward(n)   => { self.cur_col = (self.cur_col + n).min(self.cols.saturating_sub(1)); }
            Action::CursorBackward(n)  => { self.cur_col = self.cur_col.saturating_sub(n); }
            Action::CursorColumn(n)    => { self.cur_col = (n.saturating_sub(1)).min(self.cols.saturating_sub(1)); }
            Action::CursorRow(n)       => { self.cur_row = (n.saturating_sub(1)).min(self.rows.saturating_sub(1)); }
            Action::CursorPosition(r, c) => {
                self.cur_row = (r.saturating_sub(1)).min(self.rows.saturating_sub(1));
                self.cur_col = (c.saturating_sub(1)).min(self.cols.saturating_sub(1));
            }
            Action::EraseDisplay(_) => {
                for px in self.fb.iter_mut() { *px = 0; }
            }
            Action::EraseLine(_) => {
                let row_pixel = self.cur_row * self.cell_h;
                for y in row_pixel..(row_pixel + self.cell_h).min(self.yres) {
                    let off = (y * self.pitch) as usize;
                    for x in 0..self.pitch as usize {
                        self.fb[off + x] = 0;
                    }
                }
            }
            Action::ScrollUp(n)   => self.scroll_up(n),
            Action::ScrollDown(_) => {}
            Action::SetGraphicRendition(p, n) => self.apply_sgr(&p[..n as usize]),
            Action::FullReset => {
                for px in self.fb.iter_mut() { *px = 0; }
                self.cur_col = 0; self.cur_row = 0;
                self.fg = [0xff, 0xff, 0xff];
                self.bg = [0, 0, 0];
            }
            _ => {}
        }
    }

    fn advance_cursor(&mut self) {
        self.cur_col += 1;
        if self.cur_col >= self.cols {
            self.cur_col = 0;
            self.cur_row += 1;
            if self.cur_row >= self.rows {
                self.scroll_up(1);
                self.cur_row = self.rows - 1;
            }
        }
    }

    fn scroll_up(&mut self, n: u32) {
        let n_px = (n * self.cell_h).min(self.yres);
        let pitch = self.pitch as usize;
        let total = (self.yres * self.pitch) as usize;
        let shift = (n_px * self.pitch) as usize;
        // Fill scrolled-in (or whole-frame) area with the current bg
        // color, not zero — otherwise rows scroll into solid black.
        let bg_b = self.bg[2]; let bg_g = self.bg[1]; let bg_r = self.bg[0];
        let fill_bg = |slice: &mut [u8]| {
            let mut k = 0;
            while k + 3 < slice.len() {
                slice[k] = bg_b; slice[k+1] = bg_g; slice[k+2] = bg_r; slice[k+3] = 0xff;
                k += 4;
            }
        };
        if shift >= total { fill_bg(&mut self.fb[..]); return; }
        self.fb.copy_within(shift..total, 0);
        fill_bg(&mut self.fb[total - shift..]);
        let _ = pitch;
    }

    fn apply_sgr(&mut self, params: &[u32]) {
        let mut i = 0;
        while i < params.len() {
            let p = params[i];
            match p {
                0 => { self.fg = [0xff, 0xff, 0xff]; self.bg = [0, 0, 0]; }
                30..=37 => {
                    let pal = VGA_PALETTE[(p - 30) as usize];
                    self.fg = pal;
                }
                90..=97 => {
                    let pal = VGA_PALETTE[(p - 90 + 8) as usize];
                    self.fg = pal;
                }
                40..=47 => {
                    let pal = VGA_PALETTE[(p - 40) as usize];
                    self.bg = pal;
                }
                100..=107 => {
                    let pal = VGA_PALETTE[(p - 100 + 8) as usize];
                    self.bg = pal;
                }
                38 if i + 2 < params.len() && params[i + 1] == 5 => {
                    self.fg = xterm_256(params[i + 2]); i += 2;
                }
                48 if i + 2 < params.len() && params[i + 1] == 5 => {
                    self.bg = xterm_256(params[i + 2]); i += 2;
                }
                38 if i + 4 < params.len() && params[i + 1] == 2 => {
                    self.fg = [params[i + 2] as u8, params[i + 3] as u8, params[i + 4] as u8];
                    i += 4;
                }
                48 if i + 4 < params.len() && params[i + 1] == 2 => {
                    self.bg = [params[i + 2] as u8, params[i + 3] as u8, params[i + 4] as u8];
                    i += 4;
                }
                39 => self.fg = [0xff, 0xff, 0xff],
                49 => self.bg = [0, 0, 0],
                _ => {}
            }
            i += 1;
        }
    }

    fn blit_glyph(&mut self, codepoint: u32) {
        // Map any codepoint outside ASCII to '?'. The built-in
        // 8×16 font (BUILTIN_FONT) only covers 0x20..0x7e; non-ASCII
        // gets a placeholder.
        let g = if codepoint >= 0x20 && codepoint < 0x7f {
            (codepoint - 0x20) as usize
        } else { ('?' as usize) - 0x20 };

        let font = BUILTIN_FONT;
        let cw = self.cell_w as usize;
        let ch = self.cell_h as usize;
        let pitch = self.pitch as usize;
        let cell_x = (self.cur_col * self.cell_w) as usize;
        let cell_y = (self.cur_row * self.cell_h) as usize;
        for py in 0..ch {
            let row = font[g * ch + py];
            let buf_row_off = (cell_y + py) * pitch + cell_x * 4;
            for px in 0..cw {
                let bit = (row >> (7 - px)) & 1;
                let color = if bit == 1 { self.fg } else { self.bg };
                if buf_row_off + px * 4 + 3 < self.fb.len() {
                    self.fb[buf_row_off + px * 4]     = color[2];     // B
                    self.fb[buf_row_off + px * 4 + 1] = color[1];     // G
                    self.fb[buf_row_off + px * 4 + 2] = color[0];     // R
                    self.fb[buf_row_off + px * 4 + 3] = 0xff;         // A
                }
            }
        }
    }
}

/// Built-in 8×16 font — minimum viable: spaces for 0x20-0x7e where
/// every glyph is solid for testing the blit path. Real PSF font
/// data lands when KDFONTOP is wired (`50§14`).
const BUILTIN_FONT_LEN: usize = 95 * 16;
const BUILTIN_FONT: &[u8; BUILTIN_FONT_LEN] = &builtin_font_pattern();

const fn builtin_font_pattern() -> [u8; BUILTIN_FONT_LEN] {
    let mut out = [0u8; BUILTIN_FONT_LEN];
    let mut g = 0;
    while g < 95 {
        // ASCII char `0x20 + g`.
        // Render a centered solid rectangle (rows 4..12, cols 1..7)
        // so every glyph looks distinct from background; real glyphs
        // load via KDFONTOP.
        let mut row = 4;
        while row < 12 {
            // bits 1..6 set
            out[g * 16 + row] = 0b0111_1110;
            row += 1;
        }
        g += 1;
    }
    out
}

/// Resolve an SGR 256-color cube index to RGB per xterm.
/// 0..15  = VGA palette
/// 16..231 = 6×6×6 cube
/// 232..255 = 24-step grayscale ramp
/// # C: O(1)
pub fn xterm_256(idx: u32) -> [u8; 3] {
    if idx < 16 { return VGA_PALETTE[idx as usize]; }
    if idx < 232 {
        let i = idx - 16;
        let r = (i / 36) as u8;
        let g = ((i / 6) % 6) as u8;
        let b = (i % 6) as u8;
        let level = |x: u8| if x == 0 { 0u8 } else { 55 + 40 * x };
        return [level(r), level(g), level(b)];
    }
    let g = 8u8 + 10u8 * ((idx - 232) as u8);
    [g, g, g]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psf2_header_layout() {
        // 4 + 7×u32 = 32 bytes
        assert_eq!(core::mem::size_of::<Psf2Header>(), 32);
    }

    #[test]
    fn step_emits_putchar_for_ascii() {
        let mut s = ParserState::default();
        assert_eq!(step(&mut s, b'A'), Action::PutChar('A' as u32));
    }

    #[test]
    fn step_csi_cup_decodes_pos() {
        let mut s = ParserState::default();
        for &b in b"\x1b[10;20H" { step(&mut s, b); }
        // The terminal H consumed produces CursorPosition(10, 20)
        // — confirmed by re-running the last byte's action capture:
        let mut s2 = ParserState::default();
        let mut last = Action::None;
        for &b in b"\x1b[10;20H" { last = step(&mut s2, b); }
        assert_eq!(last, Action::CursorPosition(10, 20));
    }

    #[test]
    fn step_csi_sgr_collects_params() {
        let mut s = ParserState::default();
        let mut last = Action::None;
        for &b in b"\x1b[1;31;47m" { last = step(&mut s, b); }
        if let Action::SetGraphicRendition(p, n) = last {
            assert_eq!(n, 3);
            assert_eq!(&p[..3], &[1, 31, 47]);
        } else {
            assert!(false, "expected SetGraphicRendition");
        }
    }

    #[test]
    fn step_decset_25_show_cursor() {
        let mut s = ParserState::default();
        let mut last = Action::None;
        for &b in b"\x1b[?25h" { last = step(&mut s, b); }
        assert_eq!(last, Action::SetMode(25, true));
    }

    #[test]
    fn step_utf8_decode_two_byte() {
        let mut s = ParserState::default();
        // 'é' = U+00E9 = 0xC3 0xA9
        step(&mut s, 0xc3);
        let act = step(&mut s, 0xa9);
        assert_eq!(act, Action::PutChar(0xe9));
    }

    #[test]
    fn xterm_256_cube_mid() {
        let rgb = xterm_256(124);   // 124 = 16 + 108 = (3,0,0) in cube
        // r=3 → 55+120=175 (decimal); g=0 → 0; b=0 → 0
        assert_eq!(rgb, [175, 0, 0]);
    }

    #[test]
    fn xterm_256_grayscale() {
        // 232 → first gray = 8
        assert_eq!(xterm_256(232), [8, 8, 8]);
    }

    #[test]
    fn vga_palette_size() {
        assert_eq!(VGA_PALETTE.len(), 16);
    }

    #[test]
    fn console_new_dims() {
        let c = Console::new(640, 480);
        assert_eq!(c.cols, 80);
        assert_eq!(c.rows, 30);
        assert_eq!(c.fb.len(), 640 * 480 * 4);
    }

    #[test]
    fn put_advances_cursor() {
        let mut c = Console::new(640, 480);
        c.put(b"abc");
        assert_eq!((c.cur_col, c.cur_row), (3, 0));
    }

    #[test]
    fn newline_advances_row_only() {
        // Raw LF moves down without column reset (Linux semantics).
        // \r\n is the cooked tty line discipline's job.
        let mut c = Console::new(640, 480);
        c.put(b"abc\nx");
        assert_eq!(c.cur_col, 4);
        assert_eq!(c.cur_row, 1);
    }

    #[test]
    fn carriage_return_resets_column() {
        let mut c = Console::new(640, 480);
        c.put(b"abc\rx");
        assert_eq!((c.cur_col, c.cur_row), (1, 0));
    }

    #[test]
    fn ansi_csi_h_positions_cursor() {
        let mut c = Console::new(640, 480);
        c.put(b"\x1b[10;20H");
        assert_eq!((c.cur_row, c.cur_col), (9, 19));
    }

    #[test]
    fn sgr_red_changes_fg() {
        let mut c = Console::new(640, 480);
        c.put(b"\x1b[31m");
        assert_eq!(c.fg, VGA_PALETTE[1]);   // VGA red
    }

    #[test]
    fn glyph_blit_writes_pixels() {
        let mut c = Console::new(64, 32);   // 8×2 cells
        c.fg = [0xff, 0, 0];
        c.put(b"X");
        // Built-in placeholder glyph fills rows 4..12 cols 1..6.
        // Check pixel at (cell_x=1, cell_y=4) is foreground RGB.
        let off = (4 * 64 + 1) * 4;
        assert_eq!(c.fb[off], 0);             // B
        assert_eq!(c.fb[off + 2], 0xff);      // R
    }
}


// ---- Kernel-side klog → framebuffer driver (B07) -----------------
//
// `kernel_init` is called once after virtio-gpu sets up its scanout.
// Caller passes the framebuffer base VA (HHDM-mapped), dimensions,
// and a flush thunk that copies fbcon's Vec<u8> backing into the
// HHDM-mapped fb + triggers virtio-gpu transfer+flush.
//
// After `kernel_init`, every klog event also lands on the GPU display
// via the `klog::set_aux_sink(fbcon::klog_sink)` hookup.

#[cfg(target_os = "oxide-kernel")]
pub mod kernel {
    extern crate alloc;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicPtr, AtomicBool, Ordering};
    use sync::{Spinlock, Tty as TtyClass};
    use super::Console;

    static CONSOLE: Spinlock<Option<Console>, TtyClass> = Spinlock::new(None);

    /// Flush thunk: copies fbcon's pixel buffer to the live FB and
    /// pokes the GPU to repaint. Provided by drv-virtio-gpu at boot.
    pub type FlushFn = fn(pixels: &[u8]);
    static FLUSH_FN: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

    /// True once `kernel_init` has finished. Klog sink no-ops before.
    static READY: AtomicBool = AtomicBool::new(false);

    /// Set by `klog_sink` when the console backing has changed. Drained
    /// by `tick_drain()` which the kernel calls from the timer ISR.
    /// Deferring the GPU flush off the klog hot path is essential — a
    /// full 4 MiB transfer + virtio flush per klog line is too slow.
    static DIRTY: AtomicBool = AtomicBool::new(false);

    /// Initialize the kernel-side fbcon driver. Called once by the
    /// virtio-gpu boot probe after the scanout is active.
    /// # C: O(xres * yres) — Console::new zero-fills its backing.
    /// Softirq handler installed at `kernel_init`. Runs in
    /// process-level context with IRQs unmasked (per softirq runner
    /// contract), so virtio-gpu submit_one can wait on the device's
    /// MSI-X used-idx ack without deadlocking the way it would in
    /// a raw ISR context.
    fn flush_softirq() {
        if !DIRTY.swap(false, Ordering::AcqRel) { return; }
        repaint();
    }

    /// Initialize the kernel-side fbcon driver. Called once by the
    /// virtio-gpu boot probe after the scanout is active.
    /// # C: O(xres * yres) — Console::new + bg-fill backing.
    pub fn kernel_init(xres: u32, yres: u32, flush: FlushFn) {
        softirq::set_handler(softirq::Slot::FbconFlush, flush_softirq);
        let mut c = Console::new(xres, yres);
        c.fg = [0xff, 0xff, 0xff];
        c.bg = [0x10, 0x30, 0x80];
        // EraseDisplay zeros the backing — we want the bg color
        // covering the whole frame instead so glyphs read against
        // a visible navy field rather than solid black.
        let pitch = (xres * 4) as usize;
        for y in 0..(yres as usize) {
            let off = y * pitch;
            for x in 0..(xres as usize) {
                c.fb[off + x*4]     = c.bg[2];
                c.fb[off + x*4 + 1] = c.bg[1];
                c.fb[off + x*4 + 2] = c.bg[0];
                c.fb[off + x*4 + 3] = 0xff;
            }
        }
        *CONSOLE.lock() = Some(c);
        FLUSH_FN.store(flush as *mut (), Ordering::Release);
        READY.store(true, Ordering::Release);
        repaint();
    }

    /// `klog::LogSink` impl. Routes klog bytes through the ANSI
    /// parser and marks the backing dirty. The actual GPU flush is
    /// deferred to `tick_drain`, called from the timer ISR — a
    /// synchronous flush per klog line is too slow (4 MiB transfer).
    /// # C: O(N_bytes * cell_blit)
    pub fn klog_sink(bytes: &[u8]) {
        if !READY.load(Ordering::Acquire) { return; }
        if let Some(mut g) = CONSOLE.try_lock() {
            if let Some(c) = g.as_mut() { c.put(bytes); }
            DIRTY.store(true, Ordering::Release);
        }
        // Always raise — even if we dropped the byte: the next
        // klog will mark dirty and this slot dedupes naturally.
        softirq::raise(softirq::Slot::FbconFlush);
    }

    /// Legacy no-op kept for API stability — the softirq mechanism
    /// in `flush_softirq` is now the only drain path. Will be
    /// removed once no callers remain.
    /// # C: O(1)
    pub fn tick_drain() { /* superseded by softirq::Slot::FbconFlush */ }

    /// Push the current fbcon backing to the GPU via the installed
    /// flush thunk. No-op if the thunk isn't installed.
    /// # C: O(xres * yres) — full-frame transfer.
    fn repaint() {
        let raw = FLUSH_FN.load(Ordering::Acquire);
        if raw.is_null() { return; }
        // SAFETY: FLUSH_FN is only populated via kernel_init with a non-null FlushFn cast through `as *mut ()`; reverse-cast restores the original.
        let f: FlushFn = unsafe { core::mem::transmute(raw) };
        let guard = CONSOLE.lock();
        if let Some(c) = guard.as_ref() {
            f(&c.fb);
        }
    }
}
