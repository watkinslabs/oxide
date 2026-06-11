// `consw` renderer abstraction (Linux `struct consw`,
// include/linux/console.h). The VT layer drives a `Consw` to render a
// `Vc` cell grid; concrete renderers (fbcon, vgacon) implement it. No
// `dyn` — `Consw` is a generic trait monomorphized at each call site
// (mirrors the HAL-trait rule, CLAUDE.md §Code style / docs/52).
//
// The emulator does NOT depend on a concrete renderer. Instead `Vc`
// tracks dirty rows + a dirty cursor (set by put_glyph/erase/scroll/
// clear); `render` is the bridge: it blits dirty rows + the cursor via
// the trait and clears the marks. The console driver calls `render`
// after `emulator.feed_bytes(...)`.

use crate::vc::Vc;

/// Scroll direction for the optional fast-path `con_scroll`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ScrollDir {
    /// Region moves up `n` rows (content scrolls toward the top).
    Up,
    /// Region moves down `n` rows.
    Down,
}

/// Renderer ops the VT layer calls to paint a `Vc`. Linux `struct consw`
/// shape: init, clear region, blit cells, cursor, scroll, full repaint.
pub trait Consw {
    /// Bind/resize the renderer to a `cols`×`rows` text grid (Linux
    /// `con_init`). Called once at attach and on resize.
    /// # C: O(cols*rows) — renderer may clear its surface.
    fn con_init(&mut self, cols: u32, rows: u32);

    /// Clear the cell region `(x,y)`..`(x+w, y+h)` to the renderer's
    /// background (Linux `con_clear`). # C: O(w*h).
    fn con_clear(&mut self, vc: &Vc, x: u32, y: u32, w: u32, h: u32);

    /// Blit `n` cells from `vc` starting at `(col,row)` (Linux
    /// `con_putcs`). # C: O(n).
    fn con_putcs(&mut self, vc: &Vc, row: u32, col: u32, n: u32);

    /// Draw (`visible`) or erase the cursor at the `vc` cursor position
    /// (Linux `con_cursor`). # C: O(1).
    fn con_cursor(&mut self, vc: &Vc, visible: bool);

    /// Optional hardware/fast scroll of the `top..=bot` row region by
    /// `n` rows in `dir` (Linux `con_scroll`). Default: full repaint
    /// (the safe path). Returning is enough — `render` repaints. The
    /// `vc` already holds the scrolled cells.
    /// # C: O(cols*rows) default.
    fn con_scroll(&mut self, vc: &Vc, top: u32, bot: u32, dir: ScrollDir, n: u32) {
        let _ = (top, bot, dir, n);
        self.con_switch(vc);
    }

    /// Repaint the entire screen from `vc` (Linux `con_switch`, used on
    /// VT switch). # C: O(cols*rows).
    fn con_switch(&mut self, vc: &Vc) {
        let rows = vc.rows as u32;
        let cols = vc.cols as u32;
        for r in 0..rows {
            self.con_putcs(vc, r, 0, cols);
        }
        // The full repaint above already painted the (normal) cursor cell,
        // so any stale block is gone; draw the cursor honoring visibility.
        self.con_cursor(vc, vc.cursor_visible);
    }
}

/// Erase the cursor block the renderer last drew at `old` by repainting
/// that cell with its normal (non-reverse) attributes, then forget it.
/// No-op when nothing was drawn. Mirrors Linux fbcon erasing the prior
/// cursor cell before moving the block. # C: O(1).
fn erase_old_cursor<C: Consw>(vc: &mut Vc, consw: &mut C) {
    if let Some((ox, oy)) = vc.last_cursor() {
        if oy < vc.rows && ox < vc.cols {
            consw.con_putcs(vc, oy as u32, ox as u32, 1);
        }
        vc.set_last_cursor(None);
    }
}

/// Render a `Vc` to `consw`: blit every dirty row, repaint the cursor if
/// dirty, then clear the dirty marks. This is the bridge the console
/// driver calls after `emulator.feed_bytes(...)`. The emulator never
/// touches `consw`.
/// # C: O(dirty_rows * cols).
pub fn render<C: Consw>(vc: &mut Vc, consw: &mut C) {
    let cols = vc.cols as u32;
    let rows = vc.rows;
    for r in 0..rows {
        if vc.is_row_dirty(r) {
            consw.con_putcs(vc, r as u32, 0, cols);
        }
    }
    if vc.is_cursor_dirty() {
        // Erase the previous cursor block so a moved cursor leaves no
        // reverse-video artifact behind (Linux fbcon erases the prior
        // cell). Skip it when that row was already repainted this pass
        // (a dirty-row putcs above drew the cell with its normal attrs).
        if let Some((_ox, oy)) = vc.last_cursor() {
            if !vc.is_row_dirty(oy) {
                erase_old_cursor(vc, consw);
            } else {
                vc.set_last_cursor(None);
            }
        }
        // Draw the cursor at its new position honoring `cursor_visible`
        // (`?25l` actually hides the block).
        consw.con_cursor(vc, vc.cursor_visible);
        vc.set_last_cursor(if vc.cursor_visible { Some((vc.x, vc.y)) } else { None });
    }
    vc.clear_dirty();
}

/// Repaint the whole screen (VT switch): mark all dirty, full `con_switch`,
/// clear marks.
/// # C: O(cols*rows).
pub fn switch<C: Consw>(vc: &mut Vc, consw: &mut C) {
    consw.con_switch(vc);
    // The full repaint cleared any old block; record the new one (or none
    // when the cursor is hidden).
    vc.set_last_cursor(if vc.cursor_visible { Some((vc.x, vc.y)) } else { None });
    vc.clear_dirty();
}
