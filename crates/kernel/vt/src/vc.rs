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

/// Default tab stop width (DEC/VT100 hardware tabs every 8 columns).
pub const TAB_WIDTH: u16 = 8;

/// Selected character set for a G0/G1 slot. VT100/VT102 support ASCII
/// (DEC `B`) and the DEC Special Graphics line-drawing set (DEC `0`).
/// # C: const enum.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Charset {
    /// US ASCII (`ESC ( B`). Codepoints pass through unchanged.
    Ascii,
    /// DEC Special Graphics + line drawing (`ESC ( 0`). Codepoints
    /// 0x60..0x7e map to Unicode box-drawing/symbol glyphs.
    DecSpecial,
}

impl Default for Charset {
    fn default() -> Self {
        Charset::Ascii
    }
}

/// DEC Special Graphics map: input byte `0x60 + i` → Unicode codepoint.
/// Indexed `[byte - 0x60]` for bytes in `0x60..=0x7e`. Matches the VT100
/// special-graphics ROM (DEC STD 070) as adopted by xterm/Linux `vt.c`.
/// `0x00` entries fall through to the literal byte (no special glyph).
/// # C: const table.
pub const DEC_SPECIAL_GRAPHICS: [u32; 0x1f] = [
    0x0020, // 0x60 ` blank (DEC: no glyph; xterm: space)
    0x25c6, // 0x61 a ◆ diamond
    0x2592, // 0x62 b ▒ checkerboard (medium shade)
    0x2409, // 0x63 c ␉ HT symbol
    0x240c, // 0x64 d ␌ FF symbol
    0x240d, // 0x65 e ␍ CR symbol
    0x240a, // 0x66 f ␊ LF symbol
    0x00b0, // 0x67 g ° degree
    0x00b1, // 0x68 h ± plus/minus
    0x2424, // 0x69 i ␤ NL symbol
    0x2518, // 0x6a j ┘ lower-right corner
    0x2510, // 0x6b k ┐ upper-right corner
    0x250c, // 0x6c l ┌ upper-left corner
    0x2514, // 0x6d m └ lower-left corner
    0x253c, // 0x6e n ┼ crossing
    0x23ba, // 0x6f o ⎺ scan line 1 (top)
    0x23bb, // 0x70 p ⎻ scan line 3
    0x2500, // 0x71 q ─ horizontal line (scan line 5, middle)
    0x23bc, // 0x72 r ⎼ scan line 7
    0x23bd, // 0x73 s ⎽ scan line 9 (bottom)
    0x251c, // 0x74 t ├ left tee
    0x2524, // 0x75 u ┤ right tee
    0x2534, // 0x76 v ┴ bottom tee
    0x252c, // 0x77 w ┬ top tee
    0x2502, // 0x78 x │ vertical line
    0x2264, // 0x79 y ≤ less-than-or-equal
    0x2265, // 0x7a z ≥ greater-than-or-equal
    0x03c0, // 0x7b { π pi
    0x2260, // 0x7c | ≠ not-equal
    0x00a3, // 0x7d } £ sterling
    0x00b7, // 0x7e ~ · middle dot
];

/// Map one codepoint through the active GL charset. ASCII passes through;
/// DEC Special Graphics translates 0x60..0x7e per `DEC_SPECIAL_GRAPHICS`.
/// # C: O(1).
#[inline]
pub fn map_charset(cp: u32, set: Charset) -> u32 {
    match set {
        Charset::Ascii => cp,
        Charset::DecSpecial => {
            if (0x60..=0x7e).contains(&cp) {
                DEC_SPECIAL_GRAPHICS[(cp - 0x60) as usize]
            } else {
                cp
            }
        }
    }
}

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
    /// Saved cursor state (DECSC / ESC 7): position + SGR attr + both
    /// charset slots + GL selector + origin mode + pending-wrap. A VT100
    /// DECSC saves the FULL graphic rendition + character-set state, not
    /// just the position (DEC STD 070 / VT100 user guide).
    pub saved_x: u16,
    pub saved_y: u16,
    pub saved_attr: Attr,
    saved_g0: Charset,
    saved_g1: Charset,
    saved_gl: u8,
    saved_origin: bool,
    saved_wrap_pending: bool,
    /// G0 charset slot (`ESC ( B` / `ESC ( 0`). Default ASCII.
    pub g0: Charset,
    /// G1 charset slot (`ESC ) B` / `ESC ) 0`). Default ASCII.
    pub g1: Charset,
    /// GL selector: 0 = G0 (after SI `\x0f`), 1 = G1 (after SO `\x0e`).
    pub gl: u8,
    /// DECOM origin mode (`?6h/l`): cursor addressing relative to the
    /// scroll region and confined to it when set. Default off (absolute).
    pub origin_mode: bool,
    /// DECTCEM cursor-visible flag (`?25h/l`). Renderer-only; default on.
    pub cursor_visible: bool,
    /// Tab-stop bitmap, one bool per column (true = stop set). HTS/TBC
    /// edit it; HT advances to the next set stop. Default every 8 cols.
    tab_stops: Vec<bool>,
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
    /// Position of the cursor block last drawn by the renderer. When the
    /// cursor moves, the renderer must first repaint THIS cell with its
    /// normal (non-reverse) attributes so the reverse-video block leaves
    /// no artifact behind (Linux fbcon erases the prior cursor cell before
    /// drawing the new one). `None` = no cursor block currently on screen.
    last_cursor: Option<(u16, u16)>,
    /// Scrolled-off rows, oldest at the front. Each entry is a full row
    /// of `cols` cells. Bounded by `SCROLLBACK_LINES` (evict oldest).
    history: VecDeque<Vec<Cell>>,
    /// Lines scrolled back: 0 = live bottom, N = N lines into history.
    /// Clamped to `[0, history.len()]`. Output/echo snaps it to 0.
    view_offset: usize,
    /// Alternate screen buffer (`CSI ?47/?1047/?1049h`). `Some` while on the
    /// alt screen, holding the saved MAIN-screen cells + cursor/attr to
    /// restore on `…l`. Full-screen apps (htop/top/vim/less) draw their UI on
    /// the alt screen, then restore the shell on exit. Linux
    /// `drivers/tty/vt/vt.c` `set_mode`/`save_screen`.
    alt_screen: Option<AltScreen>,
}

/// Saved MAIN-screen state captured on alt-screen entry. # C: O(cols*rows).
#[derive(Clone, Debug)]
struct AltScreen {
    cells: Vec<Cell>,
    x: u16,
    y: u16,
    attr: Attr,
}

/// Default tab-stop bitmap: a stop every `TAB_WIDTH` columns (col 0 has
/// no stop; HT always moves at least one column). # C: O(cols).
fn default_tab_stops(cols: u16) -> Vec<bool> {
    let mut v = vec![false; cols as usize];
    let mut c = TAB_WIDTH;
    while (c as usize) < v.len() {
        v[c as usize] = true;
        c += TAB_WIDTH;
    }
    v
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
            saved_g0: Charset::Ascii,
            saved_g1: Charset::Ascii,
            saved_gl: 0,
            saved_origin: false,
            saved_wrap_pending: false,
            g0: Charset::Ascii,
            g1: Charset::Ascii,
            gl: 0,
            origin_mode: false,
            cursor_visible: true,
            tab_stops: default_tab_stops(cols),
            autowrap: true,
            wrap_pending: false,
            scroll_top: 0,
            scroll_bot: rows - 1,
            dirty: vec![true; rows as usize],
            cursor_dirty: true,
            last_cursor: None,
            history: VecDeque::new(),
            view_offset: 0,
            alt_screen: None,
        }
    }

    /// Erase `n` cells from the cursor (CSI `n X`, ECH): overwrite with
    /// blanks in the current attr WITHOUT moving the cursor, clamped to the
    /// row end. # C: O(n).
    pub fn erase_chars(&mut self, n: u16) {
        let cur = self.idx(self.x, self.y);
        let row_end = self.idx(0, self.y) + self.cols as usize;
        let end = (cur + n.max(1) as usize).min(row_end);
        self.fill(cur, end);
    }

    /// Enter the alternate screen (`CSI ?47/?1047/?1049h`): save the main
    /// screen + cursor, then blank the alt screen. No-op if already on alt.
    /// # C: O(cols*rows).
    pub fn enter_alt(&mut self) {
        if self.alt_screen.is_some() { return; }
        self.alt_screen = Some(AltScreen {
            cells: self.cells.clone(), x: self.x, y: self.y, attr: self.attr,
        });
        let total = self.cells.len();
        self.fill(0, total);
        self.x = 0; self.y = 0;
        self.mark_all_dirty();
    }

    /// Leave the alternate screen (`CSI ?47/?1047/?1049l`): restore the saved
    /// main screen + cursor. No-op if not on alt. # C: O(cols*rows).
    pub fn leave_alt(&mut self) {
        if let Some(a) = self.alt_screen.take() {
            self.cells = a.cells;
            self.x = a.x; self.y = a.y; self.attr = a.attr;
            self.mark_all_dirty();
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

    /// Position of the cursor block the renderer last drew (`None` if no
    /// block is on screen). The renderer erases this cell before drawing
    /// the cursor at the new position. # C: O(1).
    #[inline]
    pub fn last_cursor(&self) -> Option<(u16, u16)> {
        self.last_cursor
    }

    /// Record the cell the renderer just drew the cursor block into (or
    /// `None` after erasing it, e.g. when hidden). # C: O(1).
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

    /// Active GL charset (G0 when `gl==0`, else G1). # C: O(1).
    #[inline]
    pub fn active_charset(&self) -> Charset {
        if self.gl == 1 {
            self.g1
        } else {
            self.g0
        }
    }

    /// Write a glyph at the cursor with the current attr (no advance). The
    /// codepoint is mapped through the active GL charset first, so a DEC
    /// Special Graphics byte (e.g. `q`) lands as its box-drawing glyph.
    /// # C: O(1).
    pub fn put_glyph(&mut self, cp: u32) {
        self.snap_to_bottom();
        let mapped = map_charset(cp, self.active_charset());
        let i = self.idx(self.x, self.y);
        self.cells[i] = Cell::glyph(mapped, self.attr);
        self.mark_row_dirty(self.y);
    }

    // ---- tab stops --------------------------------------------------

    /// Set a tab stop at the cursor column (HTS / `ESC H`). # C: O(1).
    pub fn set_tab(&mut self) {
        if let Some(s) = self.tab_stops.get_mut(self.x as usize) {
            *s = true;
        }
    }

    /// Clear the tab stop at the cursor column (TBC 0 / `CSI g`).
    /// # C: O(1).
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

    /// Column of the next set tab stop strictly right of the cursor, or
    /// the last column if none (HT clamps at the right margin, VT100).
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

    // ---- origin mode + DECALN --------------------------------------

    /// Move the cursor to a CUP/HVP target (0-based row,col). Under origin
    /// mode the row is relative to `scroll_top` and clamped to the region;
    /// the column is always absolute. Clears pending-wrap. # C: O(1).
    pub fn move_to(&mut self, row: u16, col: u16) {
        if self.origin_mode {
            let top = self.scroll_top;
            let bot = self.scroll_bot;
            self.y = (top + row).min(bot);
            self.x = col.min(self.cols - 1);
        } else {
            self.y = row.min(self.rows - 1);
            self.x = col.min(self.cols - 1);
        }
        self.wrap_pending = false;
    }

    /// Home the cursor honoring origin mode (region-top under DECOM).
    /// # C: O(1).
    pub fn home(&mut self) {
        self.move_to(0, 0);
    }

    /// DECALN (`ESC # 8`): fill the whole screen with uppercase `E` using
    /// the DEFAULT attr, home the cursor. Screen-alignment test pattern.
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
            2 => self.fill(0, total),
            // ED 3 (xterm): erase the screen AND the scrollback history.
            3 => {
                self.fill(0, total);
                self.history.clear();
                self.view_offset = 0;
            }
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

    /// Resize the grid to `new_cols`×`new_rows`, preserving overlapping
    /// content + reflowing emulator geometry (Linux `vc_do_resize`).
    ///
    /// Row preservation matches Linux: when rows GROW or stay equal, the
    /// existing rows keep their absolute index (top-anchored). When rows
    /// SHRINK, Linux drops rows from the TOP so the cursor line stays
    /// visible — we mirror that by copying the BOTTOM `new_rows` source
    /// rows up to the new grid (`src_top = old_rows - new_rows`) and
    /// rebasing the cursor's y by the same shift, so content around the
    /// cursor is kept rather than the top of the screen. Columns are
    /// always top-left anchored (col 0..min(old,new)); cells beyond the
    /// old extent blank with the current attr.
    ///
    /// Cursor clamps into the new grid. The scroll region follows Linux:
    /// a full-screen region (`scroll_bot == old_rows-1`) re-expands to
    /// `new_rows-1`; otherwise top/bot clamp into the grid and reset to
    /// full screen if the bounds become invalid. Tab stops rebuild at the
    /// new width; `view_offset` clamps to the (unchanged) history length.
    /// No-op if the dimensions are unchanged. # C: O(cols*rows).
    pub fn resize(&mut self, new_cols: u16, new_rows: u16) {
        let new_cols = new_cols.max(1);
        let new_rows = new_rows.max(1);
        if new_cols == self.cols && new_rows == self.rows {
            return; // no-op on identical dimensions (Linux vc_do_resize early-out)
        }
        let old_rows = self.rows;
        let old_cols = self.cols;
        let was_full_region = self.scroll_bot == old_rows.saturating_sub(1);

        let mut next = vec![Cell::blank(self.attr); new_cols as usize * new_rows as usize];
        let copy_rows = new_rows.min(old_rows);
        let copy_cols = new_cols.min(old_cols);
        // When shrinking rows, source from the BOTTOM `new_rows` rows so the
        // cursor's neighbourhood is kept (Linux drops from the top); when
        // growing/equal, src_top == 0 (top-anchored).
        let src_top = old_rows.saturating_sub(new_rows); // 0 unless shrinking
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
        self.tab_stops = default_tab_stops(new_cols);
        // Cursor x clamps to the new width. y rebases by the same `src_top`
        // shift applied to the content, then clamps to the new grid.
        self.x = self.x.min(new_cols - 1);
        self.y = self.y.saturating_sub(src_top).min(new_rows - 1);
        // Scroll region (Linux vc_do_resize): a previously full-screen region
        // re-expands; otherwise clamp into the grid, resetting to full screen
        // when the bounds become invalid (top >= bot or bot out of range).
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
        // History rows hold the OLD column count, so the renderer must not
        // blit a scrollback row whose width mismatches the new grid: snap the
        // view to the live bottom (Linux drops the scrollback view on resize).
        // This trivially satisfies `view_offset <= history_len`, so the offset
        // is never left stale past the (unchanged) history length.
        self.view_offset = 0;
    }

    /// Save cursor state (DECSC / ESC 7): position, SGR attr, both charset
    /// slots, GL selector, origin mode, pending-wrap — the full VT100 saved
    /// rendition + charset state. # C: O(1).
    pub fn save_cursor(&mut self) {
        self.saved_x = self.x;
        self.saved_y = self.y;
        self.saved_attr = self.attr;
        self.saved_g0 = self.g0;
        self.saved_g1 = self.g1;
        self.saved_gl = self.gl;
        self.saved_origin = self.origin_mode;
        self.saved_wrap_pending = self.wrap_pending;
    }

    /// Restore the full saved cursor state (DECRC / ESC 8). # C: O(1).
    pub fn restore_cursor(&mut self) {
        self.attr = self.saved_attr;
        self.g0 = self.saved_g0;
        self.g1 = self.saved_g1;
        self.gl = self.saved_gl;
        self.origin_mode = self.saved_origin;
        // Position clamps; under origin mode the saved row is already an
        // absolute screen row (DECSC saved it absolute), so restore as-is
        // then clamp to the grid.
        self.y = self.saved_y.min(self.rows - 1);
        self.x = self.saved_x.min(self.cols - 1);
        self.wrap_pending = self.saved_wrap_pending;
        self.cursor_dirty = true;
    }
}
