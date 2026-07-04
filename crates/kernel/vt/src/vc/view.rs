#[cfg(test)]
use alloc::string::String;
use alloc::vec::Vec;

use super::{Attr, Cell, Vc, SCROLLBACK_LINES};

impl Vc {
    /// Number of scrolled-off rows held in history. # C: O(1).
    #[inline]
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Current scrollback view offset (0 = live bottom). # C: O(1).
    #[inline]
    pub fn view_offset(&self) -> usize {
        self.view_offset
    }

    /// Push a scrolled-off top row into history, evicting the oldest when
    /// the ring is full. # C: O(cols) (one row copy).
    pub(super) fn push_history(&mut self, row: Vec<Cell>) {
        if self.history.len() >= SCROLLBACK_LINES {
            self.history.pop_front();
        }
        self.history.push_back(row);
    }

    /// Snap the view to the live bottom (Linux: any new output/input echo
    /// returns from scrollback). Marks all rows dirty if it moved.
    /// # C: O(rows) when it moves, else O(1).
    pub fn snap_to_bottom(&mut self) {
        if self.view_offset != 0 {
            self.view_offset = 0;
            self.mark_all_dirty();
        }
    }

    /// Scroll the view up (back into history) by `n`, clamped to
    /// `history_len`. Marks all rows dirty on change. # C: O(rows).
    pub fn scroll_view_up(&mut self, n: usize) {
        let next = (self.view_offset + n).min(self.history.len());
        if next != self.view_offset {
            self.view_offset = next;
            self.mark_all_dirty();
        }
    }

    /// Scroll the view down (toward the live bottom) by `n`, clamped to 0.
    /// Marks all rows dirty on change. # C: O(rows).
    pub fn scroll_view_down(&mut self, n: usize) {
        let next = self.view_offset.saturating_sub(n);
        if next != self.view_offset {
            self.view_offset = next;
            self.mark_all_dirty();
        }
    }

    /// Cell visible at screen position (col,row) given `view_offset`.
    /// # C: O(1).
    pub fn visible_cell_at(&self, col: u16, row: u16) -> Option<Cell> {
        if col >= self.cols || row >= self.rows {
            return None;
        }
        let off = self.view_offset;
        if off == 0 {
            return self.cell_at(col, row);
        }
        let hist = self.history.len();
        let stream_top = (hist + self.rows as usize).saturating_sub(off + self.rows as usize);
        let si = stream_top + row as usize;
        if si < hist {
            self.history.get(si).and_then(|r| r.get(col as usize).copied())
        } else {
            let lr = (si - hist) as u16;
            self.cell_at(col, lr)
        }
    }

    /// Mark row `row` dirty (needs repaint). Out-of-range is ignored.
    /// # C: O(1).
    #[inline]
    pub fn mark_row_dirty(&mut self, row: u16) {
        if let Some(d) = self.dirty.get_mut(row as usize) {
            *d = true;
        }
    }

    /// Mark all rows dirty (full-screen repaint; used on VT switch).
    /// # C: O(rows).
    pub fn mark_all_dirty(&mut self) {
        for d in self.dirty.iter_mut() {
            *d = true;
        }
        self.cursor_dirty = true;
    }

    /// Mark the cursor cell as needing repaint.
    /// # C: O(1).
    #[inline]
    pub fn mark_cursor_dirty(&mut self) {
        self.cursor_dirty = true;
    }

    /// Is row `row` dirty? # C: O(1).
    #[inline]
    pub fn is_row_dirty(&self, row: u16) -> bool {
        self.dirty.get(row as usize).copied().unwrap_or(false)
    }

    /// Is the cursor cell dirty? # C: O(1).
    #[inline]
    pub fn is_cursor_dirty(&self) -> bool {
        self.cursor_dirty
    }

    /// Position of the cursor block the renderer last drew. # C: O(1).
    #[inline]
    pub fn last_cursor(&self) -> Option<(u16, u16)> {
        self.last_cursor
    }

    /// Record the cell the renderer just drew the cursor block into.
    /// # C: O(1).
    #[inline]
    pub fn set_last_cursor(&mut self, pos: Option<(u16, u16)>) {
        self.last_cursor = pos;
    }

    /// Clear all dirty marks (called by the renderer after a pass).
    /// # C: O(rows).
    pub fn clear_dirty(&mut self) {
        for d in self.dirty.iter_mut() {
            *d = false;
        }
        self.cursor_dirty = false;
    }

    /// Linear index of (col,row). Caller guarantees in-bounds.
    /// # C: O(1).
    #[inline]
    pub(super) fn idx(&self, col: u16, row: u16) -> usize {
        row as usize * self.cols as usize + col as usize
    }

    /// Read the cell at (col,row), or `None` if out of bounds.
    /// # C: O(1).
    pub fn cell_at(&self, col: u16, row: u16) -> Option<Cell> {
        if col < self.cols && row < self.rows {
            Some(self.cells[self.idx(col, row)])
        } else {
            None
        }
    }

    /// Glyph codepoint at (col,row), or `' '` if out of bounds.
    /// # C: O(1).
    pub fn glyph_at(&self, col: u16, row: u16) -> u32 {
        self.cell_at(col, row).map(|c| c.glyph).unwrap_or(' ' as u32)
    }

    /// Glyph at visible screen (col,row) honoring `view_offset`.
    /// # C: O(1).
    pub fn visible_glyph_at(&self, col: u16, row: u16) -> u32 {
        self.visible_cell_at(col, row).map(|c| c.glyph).unwrap_or(' ' as u32)
    }

    /// `Attr` at visible screen (col,row) honoring `view_offset`.
    /// # C: O(1).
    pub fn visible_attr_at(&self, col: u16, row: u16) -> Option<Attr> {
        self.visible_cell_at(col, row).map(Attr::from_cell)
    }

    /// Full decoded `Attr` at (col,row). `None` if out of bounds. # C: O(1).
    pub fn attr_at(&self, col: u16, row: u16) -> Option<Attr> {
        self.cell_at(col, row).map(Attr::from_cell)
    }

    /// Row `row` as a String. Test/debug helper. # C: O(cols).
    #[cfg(test)]
    pub fn row_string(&self, row: u16) -> String {
        let mut s = String::new();
        if row >= self.rows {
            return s;
        }
        for c in 0..self.cols {
            let g = self.glyph_at(c, row);
            s.push(char::from_u32(g).unwrap_or('\u{fffd}'));
        }
        s
    }
}
