// Kernel framebuffer console per docs/49. PSF font parsing,
// xterm-256color ANSI/CSI parser, software glyph blit + scroll.
// Drives a per-VT backing dumb-buffer; the VT layer (50) calls
// `put` / `flush` for each connected console.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

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
}
