use crate::vc::Vc;

use super::{Emulator, ReplyBytes, REPLY_CAP};

impl Emulator {
    pub(super) fn csi_final(&mut self, vc: &mut Vc, byte: u8) {
        match byte {
            b'A' => {
                let n = self.count_param(0);
                let floor = if vc.y >= vc.scroll_top { vc.scroll_top } else { 0 };
                vc.y = vc.y.saturating_sub(n).max(floor);
                vc.wrap_pending = false;
            }
            b'B' => {
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
                vc.y = (vc.y + self.count_param(0)).min(vc.rows - 1);
                vc.x = 0;
                vc.wrap_pending = false;
            }
            b'F' => {
                vc.y = vc.y.saturating_sub(self.count_param(0));
                vc.x = 0;
                vc.wrap_pending = false;
            }
            b'G' | b'`' => {
                let c = self.count_param(0).saturating_sub(1);
                vc.x = c.min(vc.cols - 1);
                vc.wrap_pending = false;
            }
            b'd' => {
                let r = self.count_param(0).saturating_sub(1);
                vc.y = r.min(vc.rows - 1);
                vc.wrap_pending = false;
            }
            b'H' | b'f' => {
                let r = self.count_param(0).saturating_sub(1);
                let c = self.count_param(1).saturating_sub(1);
                vc.move_to(r, c);
            }
            b'J' => vc.erase_display(self.param(0, 0)),
            b'K' => vc.erase_line(self.param(0, 0)),
            b'X' => vc.erase_chars(self.count_param(0)),
            b'g' => match self.param(0, 0) {
                3 => vc.clear_all_tabs(),
                _ => vc.clear_tab(),
            },
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
            b'c' => {
                if !self.private {
                    self.answer_da();
                }
            }
            b'h' | b'l' => self.set_mode(vc, byte == b'h'),
            _ => {}
        }
    }

    pub(super) fn set_mode(&mut self, vc: &mut Vc, set: bool) {
        if !self.private {
            if self.param(0, 0) == 4 {
                self.insert_mode = set;
            }
            return;
        }
        match self.param(0, 0) {
            1 => self.app_cursor = set,
            6 => {
                vc.origin_mode = set;
                vc.home();
            }
            7 => {
                vc.autowrap = set;
                vc.wrap_pending = false;
            }
            25 => vc.cursor_visible = set,
            47 | 1047 | 1049 => {
                if set { vc.enter_alt() } else { vc.leave_alt() }
            }
            2004 => self.bracketed_paste = set,
            _ => {}
        }
    }

    pub fn app_cursor(&self) -> bool {
        self.app_cursor
    }

    pub fn bracketed_paste(&self) -> bool {
        self.bracketed_paste
    }

    pub(super) fn device_status_report(&mut self, vc: &Vc) {
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

    pub(super) fn answer_da(&mut self) {
        self.reply_len = 0;
        self.push_reply(b"\x1b[?6c");
    }

    pub(super) fn push_reply(&mut self, bytes: &[u8]) {
        for &b in bytes {
            let i = self.reply_len as usize;
            if i < REPLY_CAP {
                self.reply[i] = b;
                self.reply_len += 1;
            }
        }
    }

    pub(super) fn push_reply_dec(&mut self, mut v: u32) {
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

    pub fn take_reply(&mut self) -> ReplyBytes {
        let len = self.reply_len as usize;
        self.reply_len = 0;
        ReplyBytes { bytes: self.reply, len }
    }

    pub(super) fn set_scroll_region(&mut self, vc: &mut Vc) {
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
        vc.home();
    }

    pub(super) fn insert_lines(&mut self, vc: &mut Vc, n: u16) {
        if vc.y < vc.scroll_top || vc.y > vc.scroll_bot {
            return;
        }
        let save = vc.scroll_top;
        vc.scroll_top = vc.y;
        vc.scroll_down(n);
        vc.scroll_top = save;
    }

    pub(super) fn delete_lines(&mut self, vc: &mut Vc, n: u16) {
        if vc.y < vc.scroll_top || vc.y > vc.scroll_bot {
            return;
        }
        let save = vc.scroll_top;
        vc.scroll_top = vc.y;
        vc.scroll_up(n);
        vc.scroll_top = save;
    }

    pub(super) fn insert_blanks(&mut self, vc: &mut Vc, n: u16) {
        let n = n.min(vc.cols - vc.x);
        let row = vc.y;
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

    pub(super) fn delete_chars(&mut self, vc: &mut Vc, n: u16) {
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
}
