// fbcon `consw` renderer (T2): blits a `vtdata::Vc` cell grid to a
// framebuffer. Each cell carries fully-resolved fg/bg 0x00RRGGBB
// (vtdata's SGR emulator resolved index/256/truecolor + bold-brighten at
// set-time), so the blit reads `cell.fg`/`cell.bg` directly — no palette
// lookup here. reverse swaps fg/bg; underline forces the bottom row to
// fg. The legacy `Console` byte path stays.
//
// The per-cell blit math (`blit_cell`) is a pure fn over a `&mut [u32]`
// pixel slice + dims, so it is host-testable against a fake framebuffer
// without any device. `VcRenderer` owns a `Vec<u32>` and impls `Consw`.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use vtdata::{Attr, Consw, Vc, ATTR_REVERSE, ATTR_UNDERLINE};

use crate::damage::{Damage, FlushRect};

/// Default glyph cell width (built-in 8×16 font) — the fallback/initial
/// sizing. The LIVE cell width comes from `font::active().width`.
pub const CELL_W: u32 = 8;
/// Default glyph cell height (built-in 8×16 font) — the fallback/initial
/// sizing. The LIVE cell height comes from `font::active().height`.
pub const CELL_H: u32 = 16;

/// Blit one cell into `px` (a row-major `cols*cell_w` × `rows*cell_h`
/// pixel buffer with stride `stride_px` pixels per scanline) at text
/// position `(col,row)`. `cell_w`/`cell_h` are the font-driven cell
/// dimensions (advance + scanlines). `fg`/`bg` are resolved 0x00RRGGBB;
/// `flags` carries `ATTR_REVERSE` (swap fg/bg) and `ATTR_UNDERLINE` (force
/// the bottom glyph row to fg). Out-of-range pixels are skipped.
/// # C: O(cell_w*cell_h).
#[allow(clippy::too_many_arguments)]
pub fn blit_cell(
    px: &mut [u32],
    stride_px: usize,
    cell_w: u32,
    cell_h: u32,
    col: u32,
    row: u32,
    glyph: u32,
    fg: u32,
    bg: u32,
    flags: u16,
) {
    let underline_flag = flags & ATTR_UNDERLINE != 0;
    let (mut fg_px, mut bg_px) = (fg, bg);
    if flags & ATTR_REVERSE != 0 {
        core::mem::swap(&mut fg_px, &mut bg_px);
    }
    // Map the cell's Unicode codepoint to a glyph index via the active
    // font's unicode table (`conv_uni_to_pc`); unmapped → the font's '?'
    // fallback. This is what renders DEC/box-drawing (U+25xx) + accented
    // Latin the emulator already stores, instead of the old ASCII-only `?`.
    let font = crate::font::active();
    let g = font.glyph_index(glyph);
    let cw = cell_w as usize;
    let ch = cell_h as usize;
    let cell_x = col as usize * cw;
    let cell_y = row as usize * ch;
    for py in 0..ch {
        let underline = underline_flag && py == ch - 1;
        let base = (cell_y + py) * stride_px + cell_x;
        // Read each column width-correctly: glyph_bit handles fonts WIDER
        // than 8px (12/16/24/32). For the default 8px font this matches the
        // old `(glyph_row >> (7-x)) & 1` exactly. Columns past the glyph
        // width are blank (advance ≥ glyph width when cell==font).
        for pxn in 0..cw {
            let on = font.glyph_bit(g, py, pxn) || underline;
            let color = if on { fg_px } else { bg_px };
            let off = base + pxn;
            if off < px.len() {
                px[off] = color;
            }
        }
    }
}

/// Cell-based fbcon renderer: owns a 0x00RRGGBB pixel buffer sized to
/// the bound text grid. Implements `Consw` so the VT layer can blit a
/// `Vc` into it (`vtdata::render`). The kernel driver copies `pixels()`
/// to the live framebuffer.
pub struct VcRenderer {
    cols: u32,
    rows: u32,
    /// Live cell width/height in pixels, cached from `font::active()` at
    /// `con_init`. Default 8×16; font-driven when a wider font is loaded.
    cell_w: u32,
    cell_h: u32,
    px: Vec<u32>,
    /// Pixels written since the last [`VcRenderer::take_damage`]. The flush
    /// sink uploads this box instead of the whole surface.
    dmg: Damage,
}

impl VcRenderer {
    /// New renderer for a `cols`×`rows` text grid (pixel buffer
    /// allocated lazily by `con_init`). Cell dims default to the built-in
    /// 8×16 until `con_init` reads the active font. # C: O(1).
    pub fn new() -> Self {
        VcRenderer { cols: 0, rows: 0, cell_w: CELL_W, cell_h: CELL_H, px: Vec::new(), dmg: Damage::empty() }
    }

    /// Take the damaged region accumulated since the last call, clamped to
    /// the surface. `None` when nothing changed — the caller then skips the
    /// upload entirely. # C: O(1)
    pub fn take_damage(&mut self) -> Option<FlushRect> {
        self.dmg.take(self.width_px(), self.height_px())
    }

    /// Mark the whole surface damaged (mode set, resize, scanout restore —
    /// anything that invalidates what the device already holds). # C: O(1)
    pub fn damage_all(&mut self) {
        self.dmg.add(0, 0, self.width_px(), self.height_px());
    }

    /// Record the cell region `x..x+w` by `y..y+h` as damaged, in pixels.
    /// # C: O(1)
    fn damage_cells(&mut self, x: u32, y: u32, w: u32, h: u32) {
        self.dmg.add(x * self.cell_w, y * self.cell_h, w * self.cell_w, h * self.cell_h);
    }

    /// Live cell width in pixels (font-driven). # C: O(1).
    pub fn cell_w(&self) -> u32 {
        self.cell_w
    }

    /// Live cell height in pixels (font-driven). # C: O(1).
    pub fn cell_h(&self) -> u32 {
        self.cell_h
    }

    /// Width in pixels of the bound grid. # C: O(1).
    pub fn width_px(&self) -> u32 {
        self.cols * self.cell_w
    }

    /// Height in pixels of the bound grid. # C: O(1).
    pub fn height_px(&self) -> u32 {
        self.rows * self.cell_h
    }

    /// The rendered 0x00RRGGBB pixel buffer (row-major, stride =
    /// width_px). # C: O(1).
    pub fn pixels(&self) -> &[u32] {
        &self.px
    }

    #[inline]
    fn stride(&self) -> usize {
        self.width_px() as usize
    }
}

impl Default for VcRenderer {
    fn default() -> Self {
        VcRenderer::new()
    }
}

impl Consw for VcRenderer {
    /// # C: O(cols*rows*cell_w*cell_h) — allocate + clear the surface.
    fn con_init(&mut self, cols: u32, rows: u32) {
        // Latch the live cell dims from the active font (default 8×16).
        let font = crate::font::active();
        self.cell_w = font.width;
        self.cell_h = font.height;
        self.cols = cols;
        self.rows = rows;
        self.px = vec![0u32; (cols * self.cell_w * rows * self.cell_h) as usize];
        // A fresh surface shares nothing with what the device holds.
        self.dmg.clear();
        self.damage_all();
    }

    /// # C: O(w*h*cell_w*cell_h).
    fn con_clear(&mut self, vc: &Vc, x: u32, y: u32, w: u32, h: u32) {
        let stride = self.stride();
        let (cw, ch) = (self.cell_w, self.cell_h);
        let blank = Attr::default();
        let (y_end, x_end) = ((y + h).min(self.rows), (x + w).min(self.cols));
        for r in y..y_end {
            for c in x..x_end {
                blit_cell(&mut self.px, stride, cw, ch, c, r, ' ' as u32, blank.fg, blank.bg, blank.flags());
            }
        }
        if x_end > x && y_end > y {
            self.damage_cells(x, y, x_end - x, y_end - y);
        }
        let _ = vc;
    }

    /// Blit the visible window (honors `Vc::view_offset` — history rows
    /// when scrolled back). # C: O(n*cell_w*cell_h).
    fn con_putcs(&mut self, vc: &Vc, row: u32, col: u32, n: u32) {
        if row >= self.rows {
            return;
        }
        let stride = self.stride();
        let (cw, ch) = (self.cell_w, self.cell_h);
        let mut drawn = 0u32;
        for i in 0..n {
            let c = col + i;
            if c >= self.cols {
                break;
            }
            let glyph = vc.visible_glyph_at(c as u16, row as u16);
            let a = vc.visible_attr_at(c as u16, row as u16).unwrap_or_default();
            blit_cell(&mut self.px, stride, cw, ch, c, row, glyph, a.fg, a.bg, a.flags());
            drawn += 1;
        }
        self.damage_cells(col, row, drawn, 1);
    }

    /// Cursor = reverse-video block at the vc cursor cell. When `visible`
    /// is false (`?25l` hid the cursor) the cell is blitted with its
    /// NORMAL attributes — i.e. the block is erased, so the cursor is
    /// actually hidden (Linux fbcon stops drawing the cursor block). The
    /// bridge (`consw::render`) passes `vc.cursor_visible`. # C: O(CELL).
    fn con_cursor(&mut self, vc: &Vc, visible: bool) {
        let (cx, cy) = (vc.x as u32, vc.y as u32);
        if cx >= self.cols || cy >= self.rows {
            return;
        }
        let stride = self.stride();
        let (cw, ch) = (self.cell_w, self.cell_h);
        let glyph = vc.glyph_at(cx as u16, cy as u16);
        let mut a = vc.attr_at(cx as u16, cy as u16).unwrap_or_default();
        if visible {
            a.reverse = !a.reverse;
        }
        blit_cell(&mut self.px, stride, cw, ch, cx, cy, glyph, a.fg, a.bg, a.flags());
        self.damage_cells(cx, cy, 1, 1);
    }
}

#[cfg(test)]
extern crate std;

#[cfg(test)]
mod tests;
