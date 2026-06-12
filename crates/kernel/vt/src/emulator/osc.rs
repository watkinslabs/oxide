// OSC (Operating System Command) handling, split out for the file cap.
// `ESC ] Ps ; Pt (BEL | ST)`. We act on color-control OSCs (`57§14`):
//   Ps 4   — set palette entry: `4 ; idx ; spec [; idx ; spec]…`
//   Ps 104 — reset palette: no args = all, else each listed index
//   Ps 10  — set default fg to `spec`
//   Ps 11  — set default bg to `spec`
// Ps 0/1/2 (window/icon title) are captured + ignored (no kernel-VT
// titlebar). Unknown Ps are consumed and ignored. `spec` accepts the
// xterm forms `rgb:R/G/B` (1..4 hex digits/channel, scaled to 8-bit) and
// `#RGB`/`#RRGGBB`.

use super::{CsiState, Emulator};
use crate::vc::Vc;

/// OSC payload buffer capacity. A multi-entry `OSC 4` palette set is the
/// longest realistic payload; 128 bytes covers several entries. Overflow
/// bytes are dropped (the prefix still parses). # C: const.
pub(super) const OSC_CAP: usize = 128;

impl Emulator {
    /// Append one OSC payload byte (clamped to `OSC_CAP`). # parse-helper.
    fn osc_push(&mut self, byte: u8) {
        let i = self.osc_len as usize;
        if i < OSC_CAP {
            self.osc_buf[i] = byte;
            self.osc_len += 1;
        }
    }

    /// Feed one byte while collecting an OSC string. Terminates on `BEL`,
    /// C1 `ST` (0x9c), or 7-bit `ST` (`ESC \`); a lone `\` is payload, not a
    /// terminator (`57§14`). On termination the payload is dispatched.
    pub(super) fn osc_string(&mut self, vc: &mut Vc, byte: u8) {
        if self.str_esc {
            self.str_esc = false;
            if byte == b'\\' {
                self.osc_dispatch(vc);
                self.state = CsiState::Ground;
            } else {
                // ESC not followed by `\`: the ESC was payload; keep this
                // byte too and stay in the string.
                self.osc_push(byte);
            }
            return;
        }
        match byte {
            0x07 | 0x9c => {
                self.osc_dispatch(vc);
                self.state = CsiState::Ground;
            }
            0x1b => self.str_esc = true,
            _ => self.osc_push(byte),
        }
    }

    /// Parse the collected OSC payload and apply color-control commands.
    /// # parse-helper.
    fn osc_dispatch(&mut self, vc: &mut Vc) {
        let buf = self.osc_buf;
        let len = self.osc_len as usize;
        self.osc_len = 0;
        let payload = &buf[..len];
        let mut it = payload.split(|&b| b == b';');
        let ps = match it.next().and_then(parse_u32) {
            Some(v) => v,
            None => return,
        };
        match ps {
            4 => {
                // index ; spec [; index ; spec]…
                loop {
                    let idx = match it.next().and_then(parse_u32) {
                        Some(v) => v,
                        None => break,
                    };
                    match it.next().and_then(parse_color) {
                        Some(rgb) if idx < 256 => vc.set_palette(idx as u8, rgb),
                        _ => break,
                    }
                }
            }
            104 => {
                let mut any = false;
                for tok in it {
                    any = true;
                    if let Some(i) = parse_u32(tok) {
                        if i < 256 {
                            vc.reset_palette(Some(i as u8));
                        }
                    }
                }
                if !any {
                    vc.reset_palette(None);
                }
            }
            10 => {
                if let Some(rgb) = it.next().and_then(parse_color) {
                    vc.set_default_fg(rgb);
                }
            }
            11 => {
                if let Some(rgb) = it.next().and_then(parse_color) {
                    vc.set_default_bg(rgb);
                }
            }
            _ => {} // title / unknown — consumed, no screen effect
        }
    }
}

/// Parse an ASCII decimal token to `u32`. Empty / non-digit → `None`.
/// # C: O(len).
fn parse_u32(bytes: &[u8]) -> Option<u32> {
    if bytes.is_empty() {
        return None;
    }
    let mut v: u32 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.saturating_mul(10).saturating_add((b - b'0') as u32);
    }
    Some(v)
}

/// Parse an xterm color spec: `rgb:R/G/B` (1..4 hex digits/channel) or
/// `#RGB`/`#RRGGBB`. Returns 0x00RRGGBB. # C: O(len).
fn parse_color(spec: &[u8]) -> Option<u32> {
    if let Some(rest) = spec.strip_prefix(b"rgb:") {
        let mut ch = rest.split(|&b| b == b'/');
        let r = scale_hex(ch.next()?)?;
        let g = scale_hex(ch.next()?)?;
        let b = scale_hex(ch.next()?)?;
        return Some(crate::palette::rgb([r, g, b]));
    }
    if let Some(rest) = spec.strip_prefix(b"#") {
        // #RGB or #RRGGBB (3 or 6 hex digits, evenly split).
        let n = rest.len();
        if n != 3 && n != 6 {
            return None;
        }
        let w = n / 3;
        let r = scale_hex(&rest[0..w])?;
        let g = scale_hex(&rest[w..2 * w])?;
        let b = scale_hex(&rest[2 * w..3 * w])?;
        return Some(crate::palette::rgb([r, g, b]));
    }
    None
}

/// Parse 1..4 hex digits and scale the value to an 8-bit channel: a width-`w`
/// field in `[0, 16^w - 1]` maps linearly onto `[0, 255]`. # C: O(len).
fn scale_hex(digits: &[u8]) -> Option<u8> {
    let w = digits.len();
    if w == 0 || w > 4 {
        return None;
    }
    let mut v: u32 = 0;
    for &b in digits {
        let d = (b as char).to_digit(16)?;
        v = v * 16 + d;
    }
    let max = (1u32 << (4 * w)) - 1;
    Some(((v * 255 + max / 2) / max) as u8)
}
