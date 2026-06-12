// SGR (Select Graphic Rendition, `CSI … m`) handling, split out of the
// emulator core for the file-length cap (`08§7`). Index colors resolve
// through the active per-VC palette (`vc.set_fg_index`/`set_bg_index`) so
// `OSC 4` redefinition takes effect; truecolor stores RGB verbatim.

use super::Emulator;
use crate::vc::Vc;

impl Emulator {
    /// Apply the accumulated SGR parameters to `vc.attr`. `pub(super)` so
    /// the parent emulator module can dispatch it.
    pub(super) fn sgr(&mut self, vc: &mut Vc) {
        let n = self.param_count as usize + 1;
        let mut i = 0;
        if n == 1 && !self.param_seen {
            // bare CSI m == CSI 0 m
            self.reset_attr(vc);
            return;
        }
        while i < n {
            let p = self.params[i];
            match p {
                0 => self.reset_attr(vc),
                1 => vc.attr.bold = true,
                2 => vc.attr.faint = true,
                3 => vc.attr.italic = true,
                4 => vc.attr.underline = true,
                5 => vc.attr.blink = true,
                7 => vc.attr.reverse = true,
                8 => vc.attr.conceal = true,
                9 => vc.attr.strike = true,
                // Linux console font select (vt.c): 10 = primary font /
                // exit alternate, 11 = first alternate (CP437 direct), 12 =
                // second alternate (CP437 with high-bit toggle). Drives the
                // `disp_ctrl` byte path — NOT a color/attr.
                10 => { self.disp_ctrl = false; self.toggle_meta = false; }
                11 => { self.disp_ctrl = true; self.toggle_meta = false; }
                12 => { self.disp_ctrl = true; self.toggle_meta = true; }
                21 => vc.attr.underline = true, // double-underline → underline
                22 => { vc.attr.bold = false; vc.attr.faint = false; }
                23 => vc.attr.italic = false,
                24 => vc.attr.underline = false,
                25 => vc.attr.blink = false,
                27 => vc.attr.reverse = false,
                28 => vc.attr.conceal = false,
                29 => vc.attr.strike = false,
                // 16-color fg/bg: resolve index→RGB through the VC palette
                // now (bold brightens a basic 0..7 fg at resolve time).
                30..=37 => vc.set_fg_index(p - 30),
                90..=97 => vc.set_fg_index(p - 90 + 8),
                40..=47 => vc.set_bg_index(p - 40),
                100..=107 => vc.set_bg_index(p - 100 + 8),
                39 => vc.attr.fg = vc.default_fg(),
                49 => vc.attr.bg = vc.default_bg(),
                38 => {
                    if i + 2 < n && self.params[i + 1] == 5 {
                        vc.set_fg_index(self.params[i + 2].min(255));
                        i += 2;
                    } else if i + 4 < n && self.params[i + 1] == 2 {
                        // 38;2;r;g;b truecolor → store RGB verbatim.
                        vc.attr.fg = crate::palette::rgb([
                            self.params[i + 2].min(255) as u8,
                            self.params[i + 3].min(255) as u8,
                            self.params[i + 4].min(255) as u8,
                        ]);
                        i += 4;
                    }
                }
                48 => {
                    if i + 2 < n && self.params[i + 1] == 5 {
                        vc.set_bg_index(self.params[i + 2].min(255));
                        i += 2;
                    } else if i + 4 < n && self.params[i + 1] == 2 {
                        vc.attr.bg = crate::palette::rgb([
                            self.params[i + 2].min(255) as u8,
                            self.params[i + 3].min(255) as u8,
                            self.params[i + 4].min(255) as u8,
                        ]);
                        i += 4;
                    }
                }
                _ => {}
            }
            i += 1;
        }
    }

    /// SGR reset (`0`): clear all attrs, then point fg/bg at the VC's
    /// current defaults (which `OSC 10/11` may have redefined). # parse-helper.
    fn reset_attr(&self, vc: &mut Vc) {
        vc.attr.reset();
        vc.attr.fg = vc.default_fg();
        vc.attr.bg = vc.default_bg();
    }
}
