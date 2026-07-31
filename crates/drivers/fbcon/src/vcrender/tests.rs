use super::*;
use std::sync::Mutex;
use vtdata::{rgb, xterm_256_rgb, Emulator, Vc, ATTR_UNDERLINE};

// The console font is a process-wide global (`font::active()`); the
// wide-font test swaps it. Every test that reads/swaps the active font
// serializes on this lock so the parallel test harness can't observe a
// half-swapped global. Poison is ignored (a panicking test still releases).
static FONT_LOCK: Mutex<()> = Mutex::new(());
fn font_guard() -> std::sync::MutexGuard<'static, ()> {
    FONT_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

// Resolved RGB shorthands (cells now carry RGB, not indices).
const WHITE: u32 = 0xffffff;
const BLACK: u32 = 0x000000;

#[test]
fn blit_known_glyph_pixels() {
    let _g = font_guard();
    // 1 cell wide, 1 row: blit 'X' fg=white bg=black.
    let stride = CELL_W as usize;
    let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
    blit_cell(&mut px, stride, CELL_W, CELL_H, 0, 0, 'X' as u32, WHITE, BLACK, 0);
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
    let _g = font_guard();
    let stride = CELL_W as usize;
    let red = xterm_256_rgb(1);
    let normal = {
        let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
        blit_cell(&mut px, stride, CELL_W, CELL_H, 0, 0, 'A' as u32, WHITE, red, 0);
        px
    };
    let reversed = {
        let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
        blit_cell(&mut px, stride, CELL_W, CELL_H, 0, 0, 'A' as u32, WHITE, red, vtdata::ATTR_REVERSE);
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
    let _g = font_guard();
    let stride = CELL_W as usize;
    let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
    // space glyph (no glyph bits) + underline → only bottom row is fg.
    blit_cell(&mut px, stride, CELL_W, CELL_H, 0, 0, ' ' as u32, WHITE, BLACK, ATTR_UNDERLINE);
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
    let _g = font_guard();
    // A cell carrying 38;2 truecolor RGB blits that exact pixel.
    let mut vc = Vc::new(1, 1);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, b"\x1b[38;2;10;20;30mZ");
    let a = vc.attr_at(0, 0).unwrap();
    assert_eq!(a.fg, rgb([10, 20, 30]));
    let stride = CELL_W as usize;
    let mut px = vec![0u32; (CELL_W * CELL_H) as usize];
    blit_cell(&mut px, stride, CELL_W, CELL_H, 0, 0, 'Z' as u32, a.fg, a.bg, a.flags());
    assert!(px.iter().any(|&p| p == rgb([10, 20, 30])), "truecolor fg pixel missing");
}

#[test]
fn renderer_blits_vc_via_consw() {
    let _g = font_guard();
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
    let _g = font_guard();
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

// Extract cell (0,0)'s cell_w×cell_h pixel block from a renderer.
fn cell00(r: &VcRenderer) -> alloc::vec::Vec<u32> {
    let stride = (r.cols * r.cell_w()) as usize;
    let mut out = alloc::vec::Vec::new();
    for py in 0..r.cell_h() as usize {
        for px in 0..r.cell_w() as usize {
            out.push(r.pixels()[py * stride + px]);
        }
    }
    out
}

// Default 8×16 font must produce a pixel-identical 'A' to the old
// (glyph_row >> (7-x)) path: build the expected block straight from
// font::glyph_bit and compare against the rendered cell. This is the
// "login unaffected" guarantee — default cell stays 8×16, same pixels.
#[test]
fn default_font_blit_a_unchanged() {
    let _g = font_guard();
    crate::font::set_default(); // ensure built-in 8×16 is active
    // Blit 'A' the new (glyph_bit) way and the OLD way (the byte-per-row
    // `(glyph_row >> (7-x)) & 1` formula this PR replaced). For the
    // default 8px font the two MUST be pixel-identical — the "login
    // unaffected" guarantee. blit_cell (no render → no cursor overlay).
    let stride = CELL_W as usize;
    let mut got = vec![0u32; (CELL_W * CELL_H) as usize];
    blit_cell(&mut got, stride, CELL_W, CELL_H, 0, 0, 'A' as u32, WHITE, BLACK, 0);

    let font = crate::font::active();
    assert_eq!((font.width, font.height), (CELL_W, CELL_H), "default font is 8×16");
    let g = font.glyph_index('A' as u32);
    let mut want = vec![0u32; (CELL_W * CELL_H) as usize];
    for py in 0..CELL_H as usize {
        let bits = font.glyph_row(g, py); // OLD byte-per-row read
        for x in 0..CELL_W as usize {
            want[py * stride + x] = if (bits >> (7 - x)) & 1 == 1 { WHITE } else { BLACK };
        }
    }
    assert_eq!(got, want, "default 8×16 'A' must blit pixel-identical to old path");
}

// A 16px-wide font (synthetic) makes the cell 16 px wide and reads
// columns past pixel 7 — proving the wide-font path renders.
#[test]
fn wide_font_cell_is_font_driven() {
    let _g = font_guard();
    // Install a synthetic 16×16 font: glyph for 'A' has column 12 lit on
    // every row (a column only reachable via the wide path).
    let stride = 64usize;
    let count = 128u32; // 'A'=65 in scope
    let charsize = 2 * 16; // row_bytes(2)*height(16)
    let mut data = alloc::vec![0u8; count as usize * stride];
    let aidx = 65usize;
    for py in 0..16usize {
        // byte1 bit for column 12 = 7-(12%8)=3 → 0b0000_1000.
        data[aidx * stride + py * 2 + 1] = 0b0000_1000;
    }
    // Identity unimap so 'A'(0x41) → glyph 65.
    let uni: alloc::vec::Vec<(u32, u16)> = (0..count).map(|i| (i, i as u16)).collect();
    crate::font::set_font_with_map(16, 16, count, stride, &data, uni, 65);
    let _ = charsize;

    // con_init latches the font dims → 16×16 cell, 16-px-wide buffer.
    let mut r = VcRenderer::new();
    r.con_init(1, 1);
    assert_eq!((r.cell_w(), r.cell_h()), (16, 16));
    assert_eq!(r.width_px(), 16, "grid width is font-driven (16px)");

    // Blit 'A' directly (no cursor overlay). Column 12 is lit in the
    // glyph — only reachable via glyph_bit's byte1 read (x≥8).
    let cw = r.cell_w();
    let ch = r.cell_h();
    let mut px = vec![0u32; (cw * ch) as usize];
    blit_cell(&mut px, cw as usize, cw, ch, 0, 0, 'A' as u32, WHITE, BLACK, 0);
    for py in 0..ch as usize {
        assert_eq!(px[py * cw as usize + 12], WHITE, "wide-font col 12 row {py} must be fg");
        assert_eq!(px[py * cw as usize + 11], BLACK, "col 11 must be bg");
        assert_eq!(px[py * cw as usize + 0], BLACK, "col 0 must be bg");
    }
    // Restore the default font for other tests.
    crate::font::set_default();
}

// #2 glyphs: DEC special-graphics / box-drawing must render the REAL
// line-drawing glyph (conv_uni_to_pc(U+2500)=CP437 196), NOT collapse to
// '?'. Feeding `ESC(0` selects DEC special graphics into G0; `q` then
// maps to U+2500 (─). The rendered cell must differ from a rendered '?'.
#[test]
fn box_drawing_renders_not_question_mark() {
    let _g = font_guard();
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
