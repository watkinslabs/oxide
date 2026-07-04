use alloc::collections::VecDeque;
use alloc::vec;

use super::{default_palette, default_tab_stops, AltScreen, Attr, Charset, Cell, Vc};
use super::{DEFAULT_BG_RGB, DEFAULT_FG_RGB};

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
            palette: default_palette(),
            default_fg: DEFAULT_FG_RGB,
            default_bg: DEFAULT_BG_RGB,
        }
    }

    /// Resolve + apply an SGR 16/256-color index to the current fg through
    /// the active palette. A basic 0..7 index brightens to 8..15 when bold
    /// (VGA convention). # C: O(1).
    pub fn set_fg_index(&mut self, idx: u32) {
        let i = if self.attr.bold && idx < 8 { idx + 8 } else { idx };
        self.attr.fg = self.palette[i.min(255) as usize];
    }

    /// Resolve + apply an SGR 16/256-color index to the current bg through
    /// the active palette. # C: O(1).
    pub fn set_bg_index(&mut self, idx: u32) {
        self.attr.bg = self.palette[idx.min(255) as usize];
    }

    /// Default fg (SGR 39 target). # C: O(1).
    pub fn default_fg(&self) -> u32 { self.default_fg }
    /// Default bg (SGR 49 target). # C: O(1).
    pub fn default_bg(&self) -> u32 { self.default_bg }

    /// `OSC 4 ; idx ; spec` — redefine one palette entry. Future glyphs use
    /// it; already-printed cells keep their resolved RGB (set-time model).
    /// # C: O(1).
    pub fn set_palette(&mut self, idx: u8, rgb: u32) {
        self.palette[idx as usize] = rgb;
    }

    /// `OSC 10` — set the default fg. # C: O(1).
    pub fn set_default_fg(&mut self, rgb: u32) { self.default_fg = rgb; }
    /// `OSC 11` — set the default bg. # C: O(1).
    pub fn set_default_bg(&mut self, rgb: u32) { self.default_bg = rgb; }

    /// `OSC 104` — reset one (`Some`) or all (`None`) palette entries to the
    /// xterm/VGA defaults. # C: O(1) or O(256).
    pub fn reset_palette(&mut self, idx: Option<u8>) {
        match idx {
            Some(i) => self.palette[i as usize] = crate::palette::xterm_256_rgb(i as u32),
            None => self.palette = default_palette(),
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
        self.x = 0;
        self.y = 0;
        self.mark_all_dirty();
    }

    /// Leave the alternate screen (`CSI ?47/?1047/?1049l`): restore the saved
    /// main screen + cursor. No-op if not on alt. # C: O(cols*rows).
    pub fn leave_alt(&mut self) {
        if let Some(a) = self.alt_screen.take() {
            self.cells = a.cells;
            self.x = a.x;
            self.y = a.y;
            self.attr = a.attr;
            self.mark_all_dirty();
        }
    }

    /// Active GL charset (G0 when `gl==0`, else G1). # C: O(1).
    #[inline]
    pub fn active_charset(&self) -> Charset {
        if self.gl == 1 { self.g1 } else { self.g0 }
    }

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
        self.y = self.saved_y.min(self.rows - 1);
        self.x = self.saved_x.min(self.cols - 1);
        self.wrap_pending = self.saved_wrap_pending;
        self.cursor_dirty = true;
    }
}
