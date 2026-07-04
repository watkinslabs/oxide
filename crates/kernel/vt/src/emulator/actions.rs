use crate::vc::{Attr, Charset, Vc};

use super::Emulator;

impl Emulator {
    pub(super) fn print(&mut self, vc: &mut Vc, cp: u32) {
        let w = crate::eaw::char_width(cp);
        if w == 0 {
            return;
        }
        if vc.wrap_pending && vc.autowrap {
            vc.x = 0;
            self.line_feed(vc);
            vc.wrap_pending = false;
        }
        if w == 2 && vc.x + 1 >= vc.cols {
            if vc.autowrap {
                vc.x = 0;
                self.line_feed(vc);
                vc.wrap_pending = false;
            } else {
                return;
            }
        }
        if self.insert_mode {
            self.insert_blanks(vc, w as u16);
        }
        vc.put_glyph_w(cp, w == 2);
        let adv = w as u16;
        if vc.x + adv >= vc.cols {
            if vc.autowrap {
                vc.x = vc.cols - 1;
                vc.wrap_pending = true;
            } else {
                vc.x = vc.cols - 1;
            }
        } else {
            vc.x += adv;
        }
    }

    pub(super) fn backspace(&mut self, vc: &mut Vc) {
        vc.wrap_pending = false;
        if vc.x > 0 {
            vc.x -= 1;
        }
    }

    pub(super) fn tab(&mut self, vc: &mut Vc) {
        vc.wrap_pending = false;
        vc.x = vc.next_tab();
    }

    pub(super) fn line_feed(&mut self, vc: &mut Vc) {
        vc.wrap_pending = false;
        if vc.y >= vc.scroll_bot {
            vc.scroll_up(1);
            vc.y = vc.scroll_bot;
        } else if vc.y + 1 < vc.rows {
            vc.y += 1;
        }
    }

    pub(super) fn index(&mut self, vc: &mut Vc) {
        self.line_feed(vc);
    }

    pub(super) fn reverse_index(&mut self, vc: &mut Vc) {
        vc.wrap_pending = false;
        if vc.y <= vc.scroll_top {
            vc.scroll_down(1);
            vc.y = vc.scroll_top;
        } else {
            vc.y -= 1;
        }
    }

    pub(super) fn full_reset(&mut self, vc: &mut Vc) {
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

    pub(super) fn param(&self, i: usize, default: u32) -> u32 {
        let count = self.param_count as usize + 1;
        if i < count && (i < self.param_count as usize || self.param_seen) {
            self.params[i]
        } else {
            default
        }
    }

    pub(super) fn count_param(&self, i: usize) -> u16 {
        let v = self.param(i, 1);
        if v == 0 { 1 } else { v.min(u16::MAX as u32) as u16 }
    }

    pub(super) fn utf8_full(&self) -> bool {
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

    pub(super) fn utf8_decode(&self) -> u32 {
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
