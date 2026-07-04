extern crate alloc;

use alloc::vec::Vec;

use crate::{font, parser::{step, Action, ParserState}};

pub const VGA_PALETTE: [[u8; 3]; 16] = [
    [0x00, 0x00, 0x00], [0xaa, 0x00, 0x00], [0x00, 0xaa, 0x00], [0xaa, 0x55, 0x00],
    [0x00, 0x00, 0xaa], [0xaa, 0x00, 0xaa], [0x00, 0xaa, 0xaa], [0xaa, 0xaa, 0xaa],
    [0x55, 0x55, 0x55], [0xff, 0x55, 0x55], [0x55, 0xff, 0x55], [0xff, 0xff, 0x55],
    [0x55, 0x55, 0xff], [0xff, 0x55, 0xff], [0x55, 0xff, 0xff], [0xff, 0xff, 0xff],
];

#[derive(Clone, Debug)]
pub struct Console {
    pub xres: u32,
    pub yres: u32,
    pub pitch: u32,
    pub fb: Vec<u8>,
    pub cell_w: u32,
    pub cell_h: u32,
    pub cols: u32,
    pub rows: u32,
    pub cur_col: u32,
    pub cur_row: u32,
    pub fg: [u8; 3],
    pub bg: [u8; 3],
    pub parser: ParserState,
}

impl Console {
    pub fn new(xres: u32, yres: u32) -> Self {
        let pitch = xres * 4;
        let mut fb = Vec::with_capacity((pitch * yres) as usize);
        fb.resize((pitch * yres) as usize, 0);
        let cell_w = 8;
        let cell_h = 16;
        Self {
            xres,
            yres,
            pitch,
            fb,
            cell_w,
            cell_h,
            cols: xres / cell_w,
            rows: yres / cell_h,
            cur_col: 0,
            cur_row: 0,
            fg: [0xff, 0xff, 0xff],
            bg: [0x00, 0x00, 0x00],
            parser: ParserState::default(),
        }
    }

    pub fn put_byte(&mut self, byte: u8) {
        let action = step(&mut self.parser, byte);
        self.apply(action);
    }

    pub fn put(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.put_byte(b);
        }
    }

    fn apply(&mut self, action: Action) {
        match action {
            Action::None => {}
            Action::PutChar(cp) => {
                self.blit_glyph(cp);
                self.advance_cursor();
            }
            Action::Backspace => {
                if self.cur_col > 0 {
                    self.cur_col -= 1;
                } else if self.cur_row > 0 {
                    self.cur_row -= 1;
                    self.cur_col = self.cols - 1;
                }
            }
            Action::Tab => {
                let next = ((self.cur_col / 8) + 1) * 8;
                self.cur_col = next.min(self.cols - 1);
            }
            Action::Linefeed => {
                self.cur_row += 1;
                if self.cur_row >= self.rows {
                    self.scroll_up(1);
                    self.cur_row = self.rows - 1;
                }
            }
            Action::CarriageReturn => self.cur_col = 0,
            Action::CursorUp(n) => self.cur_row = self.cur_row.saturating_sub(n),
            Action::CursorDown(n) => self.cur_row = (self.cur_row + n).min(self.rows.saturating_sub(1)),
            Action::CursorForward(n) => self.cur_col = (self.cur_col + n).min(self.cols.saturating_sub(1)),
            Action::CursorBackward(n) => self.cur_col = self.cur_col.saturating_sub(n),
            Action::CursorColumn(n) => self.cur_col = (n.saturating_sub(1)).min(self.cols.saturating_sub(1)),
            Action::CursorRow(n) => self.cur_row = (n.saturating_sub(1)).min(self.rows.saturating_sub(1)),
            Action::CursorPosition(r, c) => {
                self.cur_row = (r.saturating_sub(1)).min(self.rows.saturating_sub(1));
                self.cur_col = (c.saturating_sub(1)).min(self.cols.saturating_sub(1));
            }
            Action::EraseDisplay(_) => {
                for px in &mut self.fb {
                    *px = 0;
                }
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
            Action::ScrollUp(n) => self.scroll_up(n),
            Action::ScrollDown(_) => {}
            Action::SetGraphicRendition(p, n) => self.apply_sgr(&p[..n as usize]),
            Action::FullReset => {
                for px in &mut self.fb {
                    *px = 0;
                }
                self.cur_col = 0;
                self.cur_row = 0;
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
        let total = (self.yres * self.pitch) as usize;
        let shift = (n_px * self.pitch) as usize;
        let bg_b = self.bg[2];
        let bg_g = self.bg[1];
        let bg_r = self.bg[0];
        let fill_bg = |slice: &mut [u8]| {
            let mut k = 0;
            while k + 3 < slice.len() {
                slice[k] = bg_b;
                slice[k + 1] = bg_g;
                slice[k + 2] = bg_r;
                slice[k + 3] = 0xff;
                k += 4;
            }
        };
        if shift >= total {
            fill_bg(&mut self.fb[..]);
            return;
        }
        self.fb.copy_within(shift..total, 0);
        fill_bg(&mut self.fb[total - shift..]);
    }

    fn apply_sgr(&mut self, params: &[u32]) {
        let mut i = 0;
        while i < params.len() {
            let p = params[i];
            match p {
                0 => {
                    self.fg = [0xff, 0xff, 0xff];
                    self.bg = [0, 0, 0];
                }
                30..=37 => self.fg = VGA_PALETTE[(p - 30) as usize],
                90..=97 => self.fg = VGA_PALETTE[(p - 90 + 8) as usize],
                40..=47 => self.bg = VGA_PALETTE[(p - 40) as usize],
                100..=107 => self.bg = VGA_PALETTE[(p - 100 + 8) as usize],
                38 if i + 2 < params.len() && params[i + 1] == 5 => {
                    self.fg = xterm_256(params[i + 2]);
                    i += 2;
                }
                48 if i + 2 < params.len() && params[i + 1] == 5 => {
                    self.bg = xterm_256(params[i + 2]);
                    i += 2;
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
        let font = font::active();
        let g = font.glyph_index(codepoint);
        let cw = self.cell_w as usize;
        let ch = self.cell_h as usize;
        let pitch = self.pitch as usize;
        let cell_x = (self.cur_col * self.cell_w) as usize;
        let cell_y = (self.cur_row * self.cell_h) as usize;
        for py in 0..ch {
            let row = font.glyph_row(g, py);
            let buf_row_off = (cell_y + py) * pitch + cell_x * 4;
            for px in 0..cw {
                let bit = (row >> (7 - px)) & 1;
                let color = if bit == 1 { self.fg } else { self.bg };
                if buf_row_off + px * 4 + 3 < self.fb.len() {
                    self.fb[buf_row_off + px * 4] = color[2];
                    self.fb[buf_row_off + px * 4 + 1] = color[1];
                    self.fb[buf_row_off + px * 4 + 2] = color[0];
                    self.fb[buf_row_off + px * 4 + 3] = 0xff;
                }
            }
        }
    }
}

pub fn xterm_256(idx: u32) -> [u8; 3] {
    if idx < 16 {
        return VGA_PALETTE[idx as usize];
    }
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
