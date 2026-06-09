// `Vc` — per-VT screen buffer (Linux `struct vc_data`). Cell grid +
// cursor + current SGR attr + saved cursor + modes (DECAWM…) + G0/G1
// charset. The emulator (emulator.rs) is the only mutator of the grid
// beyond the structural helpers here. No rendering: a `Cell` carries a
// glyph codepoint + packed attr; consw/fbcon (T2) blits them later.

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec;
use alloc::vec::Vec;

use crate::palette::{xterm_256_rgb, VGA_PALETTE};

/// Number of virtual terminals (Linux `MAX_NR_CONSOLES` default).
/// # C: const.
pub const N_VT: usize = 63;

/// Tab stop width (Linux fixed 8-column hardware tabs).
pub const TAB_WIDTH: u16 = 8;

/// Default foreground SGR color index (light grey, VGA 7).
pub const DEFAULT_FG: u8 = 7;
/// Default background SGR color index (black, VGA 0).
pub const DEFAULT_BG: u8 = 0;

/// Default foreground as resolved 0x00RRGGBB (light grey, VGA 7).
/// # C: const.
pub const DEFAULT_FG_RGB: u32 =
    ((VGA_PALETTE[DEFAULT_FG as usize][0] as u32) << 16)
        | ((VGA_PALETTE[DEFAULT_FG as usize][1] as u32) << 8)
        | (VGA_PALETTE[DEFAULT_FG as usize][2] as u32);
/// Default background as resolved 0x00RRGGBB (black, VGA 0).
/// # C: const.
pub const DEFAULT_BG_RGB: u32 =
    ((VGA_PALETTE[DEFAULT_BG as usize][0] as u32) << 16)
        | ((VGA_PALETTE[DEFAULT_BG as usize][1] as u32) << 8)
        | (VGA_PALETTE[DEFAULT_BG as usize][2] as u32);

/// Bound on scrolled-off history rows kept per `Vc`. At up-to-`cols`
/// cells/row this is the dominant `Vc` allocation; fine for one active
/// VT (per-VT lazy alloc is a later task).
pub const SCROLLBACK_LINES: usize = 1000;

// Cells now carry FULLY-RESOLVED 24-bit RGB (Linux per-cell attributes,
// but truecolor-faithful): SGR 16/256-color indices are resolved to RGB
// at set-time via the canonical `palette`; SGR 38;2/48;2 truecolor is
// stored verbatim. The renderer reads `cell.fg`/`cell.bg` directly and
// no longer does a palette lookup. `flags` keeps bold/underline/reverse.

/// Flag bit: bold/bright intensity (SGR 1).
pub const ATTR_BOLD: u16 = 1;
/// Flag bit: underline (SGR 4).
pub const ATTR_UNDERLINE: u16 = 2;
/// Flag bit: reverse video (SGR 7).
pub const ATTR_REVERSE: u16 = 4;

/// Cell/cursor attribute: fg/bg as resolved 0x00RRGGBB RGB + bold/
/// underline/reverse flags. SGR index colors are resolved to RGB at
/// set-time (see `set_fg_index`/`set_bg_index`); truecolor SGR stores
/// RGB directly. `bold` brightens a basic 0..7 index to 8..15 at resolve
/// time, so the cell holds the bright RGB (VGA bright convention).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Attr {
    pub fg: u32,
    pub bg: u32,
    pub bold: bool,
    pub underline: bool,
    pub reverse: bool,
}

impl Default for Attr {
    fn default() -> Self {
        Attr {
            fg: DEFAULT_FG_RGB,
            bg: DEFAULT_BG_RGB,
            bold: false,
            underline: false,
            reverse: false,
        }
    }
}

impl Attr {
    /// Pack the bold/underline/reverse flags into a u16 (`ATTR_*`).
    /// # C: O(1).
    pub fn flags(self) -> u16 {
        let mut f = 0u16;
        if self.bold {
            f |= ATTR_BOLD;
        }
        if self.underline {
            f |= ATTR_UNDERLINE;
        }
        if self.reverse {
            f |= ATTR_REVERSE;
        }
        f
    }

    /// Build an `Attr` from a `Cell`'s fg/bg RGB + packed flags.
    /// # C: O(1).
    pub fn from_cell(c: Cell) -> Self {
        Attr {
            fg: c.fg,
            bg: c.bg,
            bold: c.flags & ATTR_BOLD != 0,
            underline: c.flags & ATTR_UNDERLINE != 0,
            reverse: c.flags & ATTR_REVERSE != 0,
        }
    }

    /// Set fg from an SGR 16/256-color index, resolving to RGB now. A
    /// basic 0..7 index brightens to 8..15 when `bold` (VGA convention).
    /// # C: O(1).
    pub fn set_fg_index(&mut self, idx: u32) {
        let i = if self.bold && idx < 8 { idx + 8 } else { idx };
        self.fg = xterm_256_rgb(i);
    }

    /// Set bg from an SGR 16/256-color index, resolving to RGB now.
    /// # C: O(1).
    pub fn set_bg_index(&mut self, idx: u32) {
        self.bg = xterm_256_rgb(idx);
    }

    /// Reset to SGR defaults (SGR 0).
    /// # C: O(1).
    pub fn reset(&mut self) {
        *self = Attr::default();
    }
}

/// One screen cell: a glyph codepoint, fully-resolved fg/bg 0x00RRGGBB,
/// and packed `ATTR_*` flags. A blank cell is `glyph == ' '` with the
/// prevailing attr.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Cell {
    pub glyph: u32,
    pub fg: u32,
    pub bg: u32,
    pub flags: u16,
}

impl Default for Cell {
    fn default() -> Self {
        Cell::blank(Attr::default())
    }
}

impl Cell {
    /// Blank cell carrying `attr` (used for erase/scroll fill).
    /// # C: O(1).
    pub fn blank(attr: Attr) -> Self {
        Cell { glyph: ' ' as u32, fg: attr.fg, bg: attr.bg, flags: attr.flags() }
    }

    /// Cell with `glyph` and `attr` applied.
    /// # C: O(1).
    pub fn glyph(glyph: u32, attr: Attr) -> Self {
        Cell { glyph, fg: attr.fg, bg: attr.bg, flags: attr.flags() }
    }
}

/// Per-VT screen buffer + emulator-visible state.
#[derive(Clone, Debug)]
pub struct Vc {
    pub cols: u16,
    pub rows: u16,
    cells: Vec<Cell>,
    /// Cursor column [0,cols).
    pub x: u16,
    /// Cursor row [0,rows).
    pub y: u16,
    /// Current SGR attribute applied to printed glyphs.
    pub attr: Attr,
    /// Saved cursor (DECSC / ESC 7).
    pub saved_x: u16,
    pub saved_y: u16,
    pub saved_attr: Attr,
    /// DECAWM autowrap mode (default on, Linux/xterm default).
    pub autowrap: bool,
    /// Deferred-wrap latch: set after printing into the last column with
    /// autowrap on; the NEXT printable wraps first (Linux/xterm
    /// pending-wrap semantics so the rightmost column is usable).
    pub wrap_pending: bool,
    /// Top of the scroll region (inclusive), 0-based. Default 0.
    pub scroll_top: u16,
    /// Bottom of the scroll region (inclusive), 0-based. Default rows-1.
    pub scroll_bot: u16,
    /// Per-row dirty flags (len == rows). A row is marked when any cell
    /// in it changes; the renderer (`consw::render`) blits dirty rows
    /// then clears the marks. Bridges the emulator (data) to consw
    /// (pixels) without the emulator depending on a concrete renderer.
    dirty: Vec<bool>,
    /// Set when the cursor moves or its row changes; the renderer
    /// repaints the cursor cell and clears it.
    cursor_dirty: bool,
    /// Scrolled-off rows, oldest at the front. Each entry is a full row
    /// of `cols` cells. Bounded by `SCROLLBACK_LINES` (evict oldest).
    history: VecDeque<Vec<Cell>>,
    /// Lines scrolled back: 0 = live bottom, N = N lines into history.
    /// Clamped to `[0, history.len()]`. Output/echo snaps it to 0.
    view_offset: usize,
}

impl Vc {
    /// Allocate a `cols`×`rows` VT, cleared to blanks, cursor at (0,0).
    /// # C: O(cols*rows) — grid zero-fill.
    pub fn new(cols: u16, rows: u16) -> Self {
        let cols = cols.max(1);
        let rows = rows.max(1);
        Vc {
            cols,
            rows,
            cells: vec![Cell::default(); cols as usize * rows as usize],
            x: 0,
            y: 0,
            attr: Attr::default(),
            saved_x: 0,
            saved_y: 0,
            saved_attr: Attr::default(),
            autowrap: true,
            wrap_pending: false,
            scroll_top: 0,
            scroll_bot: rows - 1,
            dirty: vec![true; rows as usize],
            cursor_dirty: true,
            history: VecDeque::new(),
            view_offset: 0,
        }
    }

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
    fn push_history(&mut self, row: Vec<Cell>) {
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

    /// Cell visible at screen position (col,row) given `view_offset`. With
    /// offset>0 the top `view_offset` screen rows come from history (with
    /// the live screen shifted down underneath), the rest from the live
    /// grid. `None` if out of bounds. # C: O(1).
    pub fn visible_cell_at(&self, col: u16, row: u16) -> Option<Cell> {
        if col >= self.cols || row >= self.rows {
            return None;
        }
        let off = self.view_offset;
        if off == 0 {
            return self.cell_at(col, row);
        }
        // Screen rows [0, rows) map onto a window ending `off` lines above
        // the live bottom. `rel` is the row index counting from the top of
        // the (history ++ live) stream's visible window.
        let hist = self.history.len();
        // Index into the virtual stream: history rows then live rows.
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
    fn idx(&self, col: u16, row: u16) -> usize {
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

    /// Glyph at visible screen (col,row) honoring `view_offset` (history
    /// when scrolled back). `' '` if out of bounds. # C: O(1).
    pub fn visible_glyph_at(&self, col: u16, row: u16) -> u32 {
        self.visible_cell_at(col, row).map(|c| c.glyph).unwrap_or(' ' as u32)
    }

    /// `Attr` at visible screen (col,row) honoring `view_offset`. `None`
    /// if out of bounds. # C: O(1).
    pub fn visible_attr_at(&self, col: u16, row: u16) -> Option<Attr> {
        self.visible_cell_at(col, row).map(Attr::from_cell)
    }

    /// Full decoded `Attr` at (col,row) (fg/bg RGB + flags). `None` if
    /// out of bounds. # C: O(1).
    pub fn attr_at(&self, col: u16, row: u16) -> Option<Attr> {
        self.cell_at(col, row).map(Attr::from_cell)
    }

    /// Row `row` as a String (glyphs decoded to chars; trailing blanks
    /// kept). Test/debug helper.
    /// # C: O(cols).
    #[cfg(test)]
    pub fn row_string(&self, row: u16) -> alloc::string::String {
        let mut s = alloc::string::String::new();
        if row >= self.rows {
            return s;
        }
        for c in 0..self.cols {
            let g = self.glyph_at(c, row);
            s.push(char::from_u32(g).unwrap_or('\u{fffd}'));
        }
        s
    }

    /// Write a glyph at the cursor with the current attr (no advance).
    /// # C: O(1).
    pub fn put_glyph(&mut self, cp: u32) {
        self.snap_to_bottom();
        let i = self.idx(self.x, self.y);
        self.cells[i] = Cell::glyph(cp, self.attr);
        self.mark_row_dirty(self.y);
    }

    /// Overwrite the cell at (col,row) with `cell` (in-bounds only).
    /// Used by ICH/DCH row shifts. # C: O(1).
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

    /// Fill a half-open cell range [start,end) with blanks (current attr).
    /// Indices clamped to the grid. # C: O(end-start).
    fn fill(&mut self, start: usize, end: usize) {
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

    /// Erase in line per CSI K. mode 0: cursor→eol, 1: bol→cursor,
    /// 2: whole line. # C: O(cols).
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

    /// Erase in display per CSI J. mode 0: cursor→end, 1: start→cursor,
    /// 2/3: whole screen. # C: O(cols*rows).
    pub fn erase_display(&mut self, mode: u32) {
        let cur = self.idx(self.x, self.y);
        let total = self.cells.len();
        match mode {
            0 => self.fill(cur, total),
            1 => self.fill(0, cur + 1),
            2 | 3 => self.fill(0, total),
            _ => {}
        }
    }

    /// Scroll the scroll region up by `n` rows; vacated bottom rows are
    /// filled with blanks (current attr). # C: O(cols*rows).
    pub fn scroll_up(&mut self, n: u16) {
        let top = self.scroll_top as usize;
        let bot = self.scroll_bot as usize;
        if bot < top {
            return;
        }
        let region_rows = bot - top + 1;
        let n = (n as usize).min(region_rows);
        let cols = self.cols as usize;
        // Lines scrolling off the *screen top* (region anchored at row 0)
        // go into scrollback history, oldest first. Region scrolls that
        // don't touch the top (DECSTBM sub-regions) don't feed history —
        // matching Linux, which only keeps the main-screen scrollback.
        if top == 0 {
            for r in 0..n {
                let base = r * cols;
                let row: Vec<Cell> = self.cells[base..base + cols].to_vec();
                self.push_history(row);
            }
        }
        // Move rows top+n..=bot up to top..
        for r in 0..(region_rows - n) {
            let dst = (top + r) * cols;
            let src = (top + r + n) * cols;
            for c in 0..cols {
                self.cells[dst + c] = self.cells[src + c];
            }
        }
        // Blank the freed bottom n rows.
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

    /// Scroll the scroll region down by `n` rows; vacated top rows are
    /// blanked. # C: O(cols*rows).
    pub fn scroll_down(&mut self, n: u16) {
        let top = self.scroll_top as usize;
        let bot = self.scroll_bot as usize;
        if bot < top {
            return;
        }
        let region_rows = bot - top + 1;
        let n = (n as usize).min(region_rows);
        let cols = self.cols as usize;
        // Move rows from bottom toward top.
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

    /// Resize the grid to `cols`×`rows`, preserving overlapping content
    /// (top-left anchored) and clamping the cursor. # C: O(cols*rows).
    pub fn resize(&mut self, cols: u16, rows: u16) {
        let cols = cols.max(1);
        let rows = rows.max(1);
        let mut next = vec![Cell::blank(self.attr); cols as usize * rows as usize];
        let copy_rows = rows.min(self.rows);
        let copy_cols = cols.min(self.cols);
        for r in 0..copy_rows {
            for c in 0..copy_cols {
                next[r as usize * cols as usize + c as usize] =
                    self.cells[self.idx(c, r)];
            }
        }
        self.cells = next;
        self.cols = cols;
        self.rows = rows;
        self.x = self.x.min(cols - 1);
        self.y = self.y.min(rows - 1);
        self.scroll_top = 0;
        self.scroll_bot = rows - 1;
        self.wrap_pending = false;
        self.dirty = vec![true; rows as usize];
        self.cursor_dirty = true;
        // History rows hold the old column count; snap to live bottom so
        // the renderer never blits a mismatched-width history row.
        self.view_offset = 0;
    }

    /// Save cursor + attr (DECSC / ESC 7). # C: O(1).
    pub fn save_cursor(&mut self) {
        self.saved_x = self.x;
        self.saved_y = self.y;
        self.saved_attr = self.attr;
    }

    /// Restore cursor + attr (DECRC / ESC 8). # C: O(1).
    pub fn restore_cursor(&mut self) {
        self.x = self.saved_x.min(self.cols - 1);
        self.y = self.saved_y.min(self.rows - 1);
        self.attr = self.saved_attr;
        self.wrap_pending = false;
        self.cursor_dirty = true;
    }
}
