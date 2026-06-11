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

/// Glyph cell width (built-in font).
pub const CELL_W: u32 = 8;
/// Glyph cell height (built-in font).
pub const CELL_H: u32 = 16;

/// Blit one cell into `px` (a row-major `cols*CELL_W` × `rows*CELL_H`
/// pixel buffer with stride `stride_px` pixels per scanline) at text
/// position `(col,row)`. `fg`/`bg` are resolved 0x00RRGGBB; `flags`
/// carries `ATTR_REVERSE` (swap fg/bg) and `ATTR_UNDERLINE` (force the
/// bottom glyph row to fg). Out-of-range pixels are skipped.
/// # C: O(CELL_W*CELL_H).
pub fn blit_cell(
    px: &mut [u32],
    stride_px: usize,
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
    let cw = CELL_W as usize;
    let ch = CELL_H as usize;
    let cell_x = col as usize * cw;
    let cell_y = row as usize * ch;
    for py in 0..ch {
        let bits = font.glyph_row(g, py);
        let underline = underline_flag && py == ch - 1;
        let base = (cell_y + py) * stride_px + cell_x;
        for pxn in 0..cw {
            let on = ((bits >> (7 - pxn)) & 1) == 1 || underline;
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
    px: Vec<u32>,
}

impl VcRenderer {
    /// New renderer for a `cols`×`rows` text grid (pixel buffer
    /// allocated lazily by `con_init`). # C: O(1).
    pub fn new() -> Self {
        VcRenderer { cols: 0, rows: 0, px: Vec::new() }
    }

    /// Width in pixels of the bound grid. # C: O(1).
    pub fn width_px(&self) -> u32 {
        self.cols * CELL_W
    }

    /// Height in pixels of the bound grid. # C: O(1).
    pub fn height_px(&self) -> u32 {
        self.rows * CELL_H
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
    /// # C: O(cols*rows*CELL_W*CELL_H) — allocate + clear the surface.
    fn con_init(&mut self, cols: u32, rows: u32) {
        self.cols = cols;
        self.rows = rows;
        self.px = vec![0u32; (cols * CELL_W * rows * CELL_H) as usize];
    }

    /// # C: O(w*h*CELL_W*CELL_H).
    fn con_clear(&mut self, vc: &Vc, x: u32, y: u32, w: u32, h: u32) {
        let stride = self.stride();
        let blank = Attr::default();
        for r in y..(y + h).min(self.rows) {
            for c in x..(x + w).min(self.cols) {
                blit_cell(&mut self.px, stride, c, r, ' ' as u32, blank.fg, blank.bg, blank.flags());
            }
        }
        let _ = vc;
    }

    /// Blit the visible window (honors `Vc::view_offset` — history rows
    /// when scrolled back). # C: O(n*CELL_W*CELL_H).
    fn con_putcs(&mut self, vc: &Vc, row: u32, col: u32, n: u32) {
        if row >= self.rows {
            return;
        }
        let stride = self.stride();
        for i in 0..n {
            let c = col + i;
            if c >= self.cols {
                break;
            }
            let glyph = vc.visible_glyph_at(c as u16, row as u16);
            let a = vc.visible_attr_at(c as u16, row as u16).unwrap_or_default();
            blit_cell(&mut self.px, stride, c, row, glyph, a.fg, a.bg, a.flags());
        }
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
        let glyph = vc.glyph_at(cx as u16, cy as u16);
        let mut a = vc.attr_at(cx as u16, cy as u16).unwrap_or_default();
        if visible {
            a.reverse = !a.reverse;
        }
        blit_cell(&mut self.px, stride, cx, cy, glyph, a.fg, a.bg, a.flags());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vtdata::{rgb, xterm_256_rgb, Emulator, Vc, ATTR_UNDERLINE};

    // Resolved RGB shorthands (cells now carry RGB, not indices).
    const WHITE: u32 = 0xffffff;
    const BLACK: u32 = 0x000000;

    #[test]
    fn blit_known_glyph_pixels() {
        // 1 cell wide, 1 row: blit 'X' fg=white bg=black.
        let stride = CELL_W as usize;
        let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
        blit_cell(&mut px, stride, 0, 0, 'X' as u32, WHITE, BLACK, 0);
        let (mut fg, mut bg) = (0, 0);
        for &p in &px {
            if p == WHITE {
                fg += 1;
            } else if p == BLACK {
                bg += 1;
            }
        }
        assert!(fg > 0, "glyph wrote no fg pixels");
        assert!(bg > 0, "glyph wrote no bg pixels (solid block?)");
    }

    #[test]
    fn reverse_swaps_fg_bg() {
        let stride = CELL_W as usize;
        let red = xterm_256_rgb(1);
        let normal = {
            let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
            blit_cell(&mut px, stride, 0, 0, 'A' as u32, WHITE, red, 0);
            px
        };
        let reversed = {
            let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
            blit_cell(&mut px, stride, 0, 0, 'A' as u32, WHITE, red, vtdata::ATTR_REVERSE);
            px
        };
        // Reverse must produce a different pixel pattern (fg/bg swapped).
        assert_ne!(normal, reversed);
        // Where normal has fg(white), reversed must have bg(red=VGA1).
        for i in 0..normal.len() {
            if normal[i] == WHITE {
                assert_eq!(reversed[i], red, "reverse should swap fg→bg at {i}");
            }
        }
    }

    #[test]
    fn underline_lights_bottom_row() {
        let stride = CELL_W as usize;
        let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
        // space glyph (no glyph bits) + underline → only bottom row is fg.
        blit_cell(&mut px, stride, 0, 0, ' ' as u32, WHITE, BLACK, ATTR_UNDERLINE);
        let last = (CELL_H as usize - 1) * stride;
        for c in 0..CELL_W as usize {
            assert_eq!(px[last + c], WHITE, "underline bottom row must be fg");
        }
        // a non-bottom row stays bg for a blank glyph.
        assert_ne!(px[0], WHITE);
        let _ = rgb([0, 0, 0]);
    }

    #[test]
    fn truecolor_cell_blits_exact_rgb() {
        // A cell carrying 38;2 truecolor RGB blits that exact pixel.
        let mut vc = Vc::new(1, 1);
        let mut em = Emulator::new();
        em.feed_bytes(&mut vc, b"\x1b[38;2;10;20;30mZ");
        let a = vc.attr_at(0, 0).unwrap();
        assert_eq!(a.fg, rgb([10, 20, 30]));
        let stride = CELL_W as usize;
        let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
        blit_cell(&mut px, stride, 0, 0, 'Z' as u32, a.fg, a.bg, a.flags());
        assert!(px.iter().any(|&p| p == rgb([10, 20, 30])), "truecolor fg pixel missing");
    }

    #[test]
    fn renderer_blits_vc_via_consw() {
        let mut vc = Vc::new(4, 1);
        let mut em = Emulator::new();
        em.feed_bytes(&mut vc, b"Hi");
        let mut r = VcRenderer::new();
        r.con_init(vc.cols as u32, vc.rows as u32);
        vtdata::render(&mut vc, &mut r);
        assert_eq!(r.width_px(), 4 * CELL_W);
        assert_eq!(r.height_px(), CELL_H);
        // Some non-zero pixels were written for 'H'/'i'.
        assert!(r.pixels().iter().any(|&p| p != 0));
    }

    // T7b Piece 2: the fbcon VT printk console flow — emulator feeds a
    // byte-run into the screen `Vc`, the Vc cells reflect the text, and
    // the consw blit runs. This mirrors `kernel::vt_console_sink` /
    // `vt_write` (kernel-only, cfg-gated) end-to-end on the host.
    #[test]
    fn vt_console_flow_cells_and_blit() {
        let mut vc = Vc::new(10, 2);
        let mut em = Emulator::new();
        let mut r = VcRenderer::new();
        r.con_init(vc.cols as u32, vc.rows as u32);

        // Emit "[INFO]" then a raw \n (emulator linefeed) + "x".
        em.feed_bytes(&mut vc, b"[INFO]");
        em.feed_bytes(&mut vc, b"\n");
        em.feed_bytes(&mut vc, b"x");
        vtdata::render(&mut vc, &mut r);

        // The Vc cells reflect the fed bytes.
        let row0: alloc::string::String = (0..6)
            .map(|c| char::from_u32(vc.glyph_at(c, 0)).unwrap())
            .collect();
        assert_eq!(row0, "[INFO]");
        // raw \n advances the row without column reset → 'x' lands at
        // col 6, row 1.
        assert_eq!(vc.glyph_at(6, 1), 'x' as u32);

        // The consw blit ran: pixels for the glyphs are non-zero.
        assert!(r.pixels().iter().any(|&p| p != 0), "blit produced no pixels");
    }

    // Extract cell (0,0)'s CELL_W×CELL_H pixel block from a renderer.
    fn cell00(r: &VcRenderer) -> alloc::vec::Vec<u32> {
        let stride = (r.cols * CELL_W) as usize;
        let mut out = alloc::vec::Vec::new();
        for py in 0..CELL_H as usize {
            for px in 0..CELL_W as usize {
                out.push(r.pixels()[py * stride + px]);
            }
        }
        out
    }

    // #2 glyphs: DEC special-graphics / box-drawing must render the REAL
    // line-drawing glyph (conv_uni_to_pc(U+2500)=CP437 196), NOT collapse to
    // '?'. Feeding `ESC(0` selects DEC special graphics into G0; `q` then
    // maps to U+2500 (─). The rendered cell must differ from a rendered '?'.
    #[test]
    fn box_drawing_renders_not_question_mark() {
        let mut vc = Vc::new(4, 1);
        let mut em = Emulator::new();
        let mut r = VcRenderer::new();
        r.con_init(vc.cols as u32, vc.rows as u32);
        em.feed_bytes(&mut vc, b"\x1b(0q"); // G0=DEC special, 'q' → U+2500
        assert_eq!(vc.glyph_at(0, 0), 0x2500, "emulator stores U+2500 for ESC(0 q");
        vtdata::render(&mut vc, &mut r);
        let box_px = cell00(&r);

        // Render a literal '?' in the same position for comparison.
        let mut vc2 = Vc::new(4, 1);
        let mut em2 = Emulator::new();
        let mut r2 = VcRenderer::new();
        r2.con_init(vc2.cols as u32, vc2.rows as u32);
        em2.feed_bytes(&mut vc2, b"?");
        vtdata::render(&mut vc2, &mut r2);
        let q_px = cell00(&r2);

        assert!(box_px.iter().any(|&p| p != 0), "box glyph must have lit pixels");
        assert_ne!(box_px, q_px, "U+2500 must NOT render as '?' (the old collapse)");
    }
}
