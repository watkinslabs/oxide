use alloc::vec;
use alloc::vec::Vec;

use super::{Cell, Vc};

impl Vc {
    /// Scroll the scroll region up by `n` rows. # C: O(cols*rows).
    pub fn scroll_up(&mut self, n: u16) {
        let top = self.scroll_top as usize;
        let bot = self.scroll_bot as usize;
        if bot < top {
            return;
        }
        let region_rows = bot - top + 1;
        let n = (n as usize).min(region_rows);
        let cols = self.cols as usize;
        if top == 0 {
            for r in 0..n {
                let base = r * cols;
                let row: Vec<Cell> = self.cells[base..base + cols].to_vec();
                self.push_history(row);
            }
        }
        for r in 0..(region_rows - n) {
            let dst = (top + r) * cols;
            let src = (top + r + n) * cols;
            for c in 0..cols {
                self.cells[dst + c] = self.cells[src + c];
            }
        }
        let blank = Cell::blank(self.attr);
        for r in (region_rows - n)..region_rows {
            let base = (top + r) * cols;
            for c in 0..cols {
                self.cells[base + c] = blank;
            }
        }
        for r in top..=bot {
            self.mark_row_dirty(r as u16);
        }
    }

    /// Scroll the scroll region down by `n` rows. # C: O(cols*rows).
    pub fn scroll_down(&mut self, n: u16) {
        let top = self.scroll_top as usize;
        let bot = self.scroll_bot as usize;
        if bot < top {
            return;
        }
        let region_rows = bot - top + 1;
        let n = (n as usize).min(region_rows);
        let cols = self.cols as usize;
        for r in (n..region_rows).rev() {
            let dst = (top + r) * cols;
            let src = (top + r - n) * cols;
            for c in 0..cols {
                self.cells[dst + c] = self.cells[src + c];
            }
        }
        let blank = Cell::blank(self.attr);
        for r in 0..n {
            let base = (top + r) * cols;
            for c in 0..cols {
                self.cells[base + c] = blank;
            }
        }
        for r in top..=bot {
            self.mark_row_dirty(r as u16);
        }
    }

    /// Resize the grid to `new_cols`×`new_rows`. # C: O(cols*rows).
    pub fn resize(&mut self, new_cols: u16, new_rows: u16) {
        let new_cols = new_cols.max(1);
        let new_rows = new_rows.max(1);
        if new_cols == self.cols && new_rows == self.rows {
            return;
        }
        let old_rows = self.rows;
        let old_cols = self.cols;
        let was_full_region = self.scroll_bot == old_rows.saturating_sub(1);

        let mut next = vec![Cell::blank(self.attr); new_cols as usize * new_rows as usize];
        let copy_rows = new_rows.min(old_rows);
        let copy_cols = new_cols.min(old_cols);
        let src_top = old_rows.saturating_sub(new_rows);
        for r in 0..copy_rows {
            let src_r = src_top + r;
            for c in 0..copy_cols {
                next[r as usize * new_cols as usize + c as usize] =
                    self.cells[src_r as usize * old_cols as usize + c as usize];
            }
        }
        self.cells = next;
        self.cols = new_cols;
        self.rows = new_rows;
        self.tab_stops = super::default_tab_stops(new_cols);
        self.x = self.x.min(new_cols - 1);
        self.y = self.y.saturating_sub(src_top).min(new_rows - 1);
        if was_full_region {
            self.scroll_top = 0;
            self.scroll_bot = new_rows - 1;
        } else {
            self.scroll_top = self.scroll_top.min(new_rows - 1);
            self.scroll_bot = self.scroll_bot.min(new_rows - 1);
            if self.scroll_top >= self.scroll_bot {
                self.scroll_top = 0;
                self.scroll_bot = new_rows - 1;
            }
        }
        self.wrap_pending = false;
        self.dirty = vec![true; new_rows as usize];
        self.cursor_dirty = true;
        self.view_offset = 0;
    }
}
