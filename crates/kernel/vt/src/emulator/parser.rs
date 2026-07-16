use crate::vc::{Charset, Vc};

use super::{CsiState, Emulator, MAX_INTER, MAX_PARAMS};

impl Emulator {
    pub(super) fn ground(&mut self, vc: &mut Vc, byte: u8) {
        if self.disp_ctrl && byte != C0_ESC {
            let b = if self.toggle_meta { byte ^ 0x80 } else { byte };
            self.print(vc, crate::cp437::to_unicode(b));
            return;
        }
        match byte {
            C0_ESC => self.state = CsiState::Esc,
            C0_BEL => {}
            C0_BS => self.backspace(vc),
            C0_HT => self.tab(vc),
            C0_LF | C0_VT | C0_FF => self.line_feed(vc),
            C0_CR => {
                vc.x = 0;
                vc.wrap_pending = false;
            }
            C0_SO => vc.gl = 1,
            C0_SI => vc.gl = 0,
            b if (0x20..0x7f).contains(&b) => self.print(vc, b as u32),
            b if (0xc2..0xf5).contains(&b) => {
                self.utf8_pending[0] = b;
                self.utf8_len = 1;
            }
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
            b if (0x80..=0x9f).contains(&b) => self.c1(vc, b),
            _ => self.utf8_len = 0,
        }
    }

    pub(super) fn c1(&mut self, vc: &mut Vc, byte: u8) {
        match byte {
            0x84 => self.index(vc),
            0x85 => {
                self.line_feed(vc);
                vc.x = 0;
                vc.wrap_pending = false;
            }
            0x88 => vc.set_tab(),
            0x8d => self.reverse_index(vc),
            0x90 => self.state = CsiState::DcsString,
            0x9b => {
                self.state = CsiState::CsiParam;
                self.params = [0; MAX_PARAMS];
                self.param_count = 0;
                self.param_seen = false;
                self.intermediate = [0; MAX_INTER];
                self.inter_count = 0;
                self.private = false;
            }
            0x9d => self.state = CsiState::Osc,
            _ => {}
        }
    }

    pub(super) fn esc(&mut self, vc: &mut Vc, byte: u8) {
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
                self.line_feed(vc);
                vc.x = 0;
                vc.wrap_pending = false;
                self.state = CsiState::Ground;
            }
            b'H' => {
                vc.set_tab();
                self.state = CsiState::Ground;
            }
            b'c' => {
                self.full_reset(vc);
                self.state = CsiState::Ground;
            }
            b'Z' => {
                self.answer_da();
                self.state = CsiState::Ground;
            }
            b'(' | b')' | b'*' | b'+' => {
                self.charset_slot = byte;
                self.state = CsiState::Charset;
            }
            b'#' => self.state = CsiState::Hash,
            _ => self.state = CsiState::Ground,
        }
    }

    pub(super) fn charset_designate(&mut self, vc: &mut Vc, byte: u8) {
        let set = match byte {
            b'0' => Charset::DecSpecial,
            _ => Charset::Ascii,
        };
        match self.charset_slot {
            b'(' => vc.g0 = set,
            b')' => vc.g1 = set,
            _ => {}
        }
        self.state = CsiState::Ground;
    }

    pub(super) fn hash(&mut self, vc: &mut Vc, byte: u8) {
        if byte == b'8' {
            vc.decaln();
        }
        self.state = CsiState::Ground;
    }

    pub(super) fn csi_param(&mut self, vc: &mut Vc, byte: u8) {
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
            0x3c..=0x3f => {
                self.private = true;
                let i = self.inter_count as usize;
                if i < MAX_INTER {
                    self.intermediate[i] = byte;
                    self.inter_count += 1;
                }
            }
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

    pub(super) fn csi_inter(&mut self, vc: &mut Vc, byte: u8) {
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

    pub(super) fn exec_c0(&mut self, vc: &mut Vc, byte: u8) {
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
            _ => {}
        }
    }

    pub(super) fn dcs_string(&mut self, byte: u8) {
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
}
const C0_ESC: u8 = 0x1b;
const C0_BEL: u8 = 0x07;
const C0_BS: u8 = 0x08;
const C0_HT: u8 = 0x09;
const C0_LF: u8 = 0x0a;
const C0_VT: u8 = 0x0b;
const C0_FF: u8 = 0x0c;
const C0_CR: u8 = 0x0d;
const C0_SO: u8 = 0x0e;
const C0_SI: u8 = 0x0f;
