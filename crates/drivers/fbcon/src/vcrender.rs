// fbcon `consw` renderer (T2): blits a `vtdata::Vc` cell grid to a
// framebuffer, mapping each cell's `Attr` (fg/bg/bold/underline/reverse)
// to pixels via the built-in 8x16 font + the VGA/xterm-256 palette
// (reused from `crate`). This is the cell-based renderer that replaces
// the lossy byte-stream mirror; the legacy `Console` byte path stays.
//
// The per-cell blit math (`blit_cell`) is a pure fn over a `&mut [u32]`
// pixel slice + dims, so it is host-testable against a fake framebuffer
// without any device. `VcRenderer` owns a `Vec<u32>` and impls `Consw`.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use vtdata::{Attr, Consw, Vc};

/// Glyph cell width (built-in font).
pub const CELL_W: u32 = 8;
/// Glyph cell height (built-in font).
pub const CELL_H: u32 = 16;

/// Pack an [r,g,b] palette entry into a 0x00RRGGBB pixel.
/// # C: O(1).
#[inline]
pub fn rgb_pixel(c: [u8; 3]) -> u32 {
    ((c[0] as u32) << 16) | ((c[1] as u32) << 8) | (c[2] as u32)
}

/// Resolve a cell `Attr` to (fg_rgb, bg_rgb) palette colors, applying
/// bold→bright (indices <8 gain +8) and reverse→swap. Underline is a
/// glyph-row effect handled by `blit_cell`, not a color.
/// # C: O(1).
pub fn attr_colors(attr: Attr) -> ([u8; 3], [u8; 3]) {
    let fg_idx = if attr.bold && (attr.fg as u32) < 8 {
        attr.fg as u32 + 8
    } else {
        attr.fg as u32
    };
    let mut fg = crate::xterm_256(fg_idx);
    let mut bg = crate::xterm_256(attr.bg as u32);
    if attr.reverse {
        core::mem::swap(&mut fg, &mut bg);
    }
    (fg, bg)
}

/// Blit one cell into `px` (a row-major `cols*CELL_W` × `rows*CELL_H`
/// pixel buffer with stride `stride_px` pixels per scanline) at text
/// position `(col,row)`. Renders the glyph for `glyph` with `attr`'s
/// colors; underline forces the bottom glyph row to fg. Out-of-range
/// pixels are skipped. # C: O(CELL_W*CELL_H).
pub fn blit_cell(
    px: &mut [u32],
    stride_px: usize,
    col: u32,
    row: u32,
    glyph: u32,
    attr: Attr,
) {
    let (fg, bg) = attr_colors(attr);
    let fg_px = rgb_pixel(fg);
    let bg_px = rgb_pixel(bg);
    // ASCII-only built-in font (0x20..0x7e); others map to '?'.
    let g = if (0x20..0x7f).contains(&glyph) {
        (glyph - 0x20) as usize
    } else {
        ('?' as usize) - 0x20
    };
    let cw = CELL_W as usize;
    let ch = CELL_H as usize;
    let cell_x = col as usize * cw;
    let cell_y = row as usize * ch;
    for py in 0..ch {
        let bits = crate::BUILTIN_FONT[g * ch + py];
        let underline = attr.underline && py == ch - 1;
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
                blit_cell(&mut self.px, stride, c, r, ' ' as u32, blank);
            }
        }
        let _ = vc;
    }

    /// # C: O(n*CELL_W*CELL_H).
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
            let glyph = vc.glyph_at(c as u16, row as u16);
            let attr = vc.attr_at(c as u16, row as u16).unwrap_or_default();
            blit_cell(&mut self.px, stride, c, row, glyph, attr);
        }
    }

    /// Cursor = reverse-video block at the vc cursor cell. # C: O(CELL).
    fn con_cursor(&mut self, vc: &Vc, visible: bool) {
        let (cx, cy) = (vc.x as u32, vc.y as u32);
        if cx >= self.cols || cy >= self.rows {
            return;
        }
        let stride = self.stride();
        let glyph = vc.glyph_at(cx as u16, cy as u16);
        let mut attr = vc.attr_at(cx as u16, cy as u16).unwrap_or_default();
        if visible {
            attr.reverse = !attr.reverse;
        }
        blit_cell(&mut self.px, stride, cx, cy, glyph, attr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vtdata::{Emulator, Vc};

    #[test]
    fn blit_known_glyph_pixels() {
        // 1 cell wide, 1 row: blit 'X' fg=white(15) bg=black(0).
        let stride = CELL_W as usize;
        let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
        let attr = Attr { fg: 15, bg: 0, bold: false, underline: false, reverse: false };
        blit_cell(&mut px, stride, 0, 0, 'X' as u32, attr);
        let white = rgb_pixel([0xff, 0xff, 0xff]);
        let black = rgb_pixel([0x00, 0x00, 0x00]);
        let (mut fg, mut bg) = (0, 0);
        for &p in &px {
            if p == white {
                fg += 1;
            } else if p == black {
                bg += 1;
            }
        }
        assert!(fg > 0, "glyph wrote no fg pixels");
        assert!(bg > 0, "glyph wrote no bg pixels (solid block?)");
    }

    #[test]
    fn reverse_swaps_fg_bg() {
        let stride = CELL_W as usize;
        let normal = {
            let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
            let a = Attr { fg: 15, bg: 1, bold: false, underline: false, reverse: false };
            blit_cell(&mut px, stride, 0, 0, 'A' as u32, a);
            px
        };
        let reversed = {
            let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
            let a = Attr { fg: 15, bg: 1, bold: false, underline: false, reverse: true };
            blit_cell(&mut px, stride, 0, 0, 'A' as u32, a);
            px
        };
        // Reverse must produce a different pixel pattern (fg/bg swapped).
        assert_ne!(normal, reversed);
        // Where normal has fg(white), reversed must have bg(red=VGA1).
        let white = rgb_pixel(crate::xterm_256(15));
        let red = rgb_pixel(crate::xterm_256(1));
        for i in 0..normal.len() {
            if normal[i] == white {
                assert_eq!(reversed[i], red, "reverse should swap fg→bg at {i}");
            }
        }
    }

    #[test]
    fn underline_lights_bottom_row() {
        let stride = CELL_W as usize;
        let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
        // space glyph (no glyph bits) + underline → only bottom row is fg.
        let a = Attr { fg: 15, bg: 0, bold: false, underline: true, reverse: false };
        blit_cell(&mut px, stride, 0, 0, ' ' as u32, a);
        let white = rgb_pixel([0xff, 0xff, 0xff]);
        let last = (CELL_H as usize - 1) * stride;
        for c in 0..CELL_W as usize {
            assert_eq!(px[last + c], white, "underline bottom row must be fg");
        }
        // a non-bottom row stays bg for a blank glyph.
        assert_ne!(px[0], white);
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
}
