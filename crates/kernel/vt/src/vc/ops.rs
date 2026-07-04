use super::default_tab_stops;
use super::{map_charset, Attr, Cell, Vc, ATTR_WIDE};

impl Vc {
    /// Write a narrow (width-1) glyph at the cursor with the current attr.
    /// # C: O(1).
    pub fn put_glyph(&mut self, cp: u32) {
        self.put_glyph_w(cp, false)
    }

    /// Write a glyph at the cursor (no advance). # C: O(1).
    pub fn put_glyph_w(&mut self, cp: u32, wide: bool) {
        self.snap_to_bottom();
        let mapped = map_charset(cp, self.active_charset());
        self.invalidate_wide_at(self.x, self.y);
        let i = self.idx(self.x, self.y);
        let extra = if wide { ATTR_WIDE } else { 0 };
        self.cells[i] = Cell::glyph_flags(mapped, self.attr, extra);
        if wide && self.x + 1 < self.cols {
            self.invalidate_wide_at(self.x + 1, self.y);
            let j = self.idx(self.x + 1, self.y);
            self.cells[j] = Cell::wide_spacer(self.attr);
        }
        self.mark_row_dirty(self.y);
    }

    /// Clear a stale wide-char half at `(col,row)`. # C: O(1).
    fn invalidate_wide_at(&mut self, col: u16, row: u16) {
        let i = self.idx(col, row);
        let c = self.cells[i];
        if c.is_wide() && col + 1 < self.cols {
            let j = self.idx(col + 1, row);
            let attr = Attr::from_cell(self.cells[j]);
            self.cells[j] = Cell::blank(attr);
        }
        if c.is_wide_spacer() && col > 0 {
            let j = self.idx(col - 1, row);
            let attr = Attr::from_cell(self.cells[j]);
            self.cells[j] = Cell::blank(attr);
        }
    }

    /// Set a tab stop at the cursor column (HTS / `ESC H`). # C: O(1).
    pub fn set_tab(&mut self) {
        if let Some(s) = self.tab_stops.get_mut(self.x as usize) {
            *s = true;
        }
    }

    /// Clear the tab stop at the cursor column (TBC 0 / `CSI g`). # C: O(1).
    pub fn clear_tab(&mut self) {
        if let Some(s) = self.tab_stops.get_mut(self.x as usize) {
            *s = false;
        }
    }

    /// Clear all tab stops (TBC 3 / `CSI 3 g`). # C: O(cols).
    pub fn clear_all_tabs(&mut self) {
        for s in self.tab_stops.iter_mut() {
            *s = false;
        }
    }

    /// Reset tab stops to the default (every `TAB_WIDTH`). # C: O(cols).
    pub fn reset_tabs(&mut self) {
        self.tab_stops = default_tab_stops(self.cols);
    }

    /// Column of the next set tab stop strictly right of the cursor.
    /// # C: O(cols).
    pub fn next_tab(&self) -> u16 {
        let mut c = self.x + 1;
        while c < self.cols {
            if self.tab_stops.get(c as usize).copied().unwrap_or(false) {
                return c;
            }
            c += 1;
        }
        self.cols - 1
    }

    /// Is a tab stop set at `col`? Test helper. # C: O(1).
    #[cfg(test)]
    pub fn tab_set(&self, col: u16) -> bool {
        self.tab_stops.get(col as usize).copied().unwrap_or(false)
    }

    /// DECALN (`ESC # 8`): fill the whole screen with uppercase `E`.
    /// # C: O(cols*rows).
    pub fn decaln(&mut self) {
        let cell = Cell::glyph('E' as u32, Attr::default());
        for c in self.cells.iter_mut() {
            *c = cell;
        }
        self.x = 0;
        self.y = 0;
        self.wrap_pending = false;
        self.mark_all_dirty();
    }

    /// Overwrite the cell at (col,row) with `cell` (in-bounds only). # C: O(1).
    pub fn set_cell(&mut self, col: u16, row: u16, cell: Cell) {
        if col < self.cols && row < self.rows {
            let i = self.idx(col, row);
            self.cells[i] = cell;
            self.mark_row_dirty(row);
        }
    }

    /// Blank the cell at (col,row) with the current attr. # C: O(1).
    pub fn blank_cell(&mut self, col: u16, row: u16) {
        let blank = Cell::blank(self.attr);
        self.set_cell(col, row, blank);
    }

    /// Clear the whole screen to blanks (current attr) and home cursor.
    /// # C: O(cols*rows).
    pub fn clear(&mut self) {
        let blank = Cell::blank(self.attr);
        for c in self.cells.iter_mut() {
            *c = blank;
        }
        self.x = 0;
        self.y = 0;
        self.wrap_pending = false;
        self.mark_all_dirty();
    }

    /// Fill a half-open cell range [start,end) with blanks. # C: O(end-start).
    pub(super) fn fill(&mut self, start: usize, end: usize) {
        let blank = Cell::blank(self.attr);
        let end = end.min(self.cells.len());
        let start = start.min(end);
        for c in &mut self.cells[start..end] {
            *c = blank;
        }
        if start < end {
            let cols = self.cols as usize;
            let first_row = (start / cols) as u16;
            let last_row = ((end - 1) / cols) as u16;
            for r in first_row..=last_row {
                self.mark_row_dirty(r);
            }
        }
    }

    /// Erase in line per CSI K. # C: O(cols).
    pub fn erase_line(&mut self, mode: u32) {
        let row_start = self.idx(0, self.y);
        let cur = self.idx(self.x, self.y);
        let row_end = row_start + self.cols as usize;
        match mode {
            0 => self.fill(cur, row_end),
            1 => self.fill(row_start, cur + 1),
            2 => self.fill(row_start, row_end),
            _ => {}
        }
    }

    /// Erase in display per CSI J. # C: O(cols*rows).
    pub fn erase_display(&mut self, mode: u32) {
        let cur = self.idx(self.x, self.y);
        let total = self.cells.len();
        match mode {
            0 => self.fill(cur, total),
            1 => self.fill(0, cur + 1),
            2 => self.fill(0, total),
            3 => {
                self.fill(0, total);
                self.history.clear();
                self.view_offset = 0;
            }
            _ => {}
        }
    }
}
