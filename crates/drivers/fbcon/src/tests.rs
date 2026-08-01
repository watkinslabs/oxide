use crate::*;
use crate::damage::FlushRect;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use crate::kernel::CONSOLE_TEST_DOMAIN;
static FLUSH_COUNT: AtomicUsize = AtomicUsize::new(0);
/// Rect of the most recent flush, so a test can assert the SCOPE of the
/// upload and not merely that one happened.
static LAST_X: AtomicU32 = AtomicU32::new(0);
static LAST_Y: AtomicU32 = AtomicU32::new(0);
static LAST_W: AtomicU32 = AtomicU32::new(0);
static LAST_H: AtomicU32 = AtomicU32::new(0);
/// Pixel-buffer length the sink was handed, to prove the rect is the small
/// part of a large surface rather than the surface itself.
static LAST_LEN: AtomicUsize = AtomicUsize::new(0);

fn count_flush(pixels: &[u8], rect: FlushRect) {
    FLUSH_COUNT.fetch_add(1, Ordering::Relaxed);
    LAST_X.store(rect.x, Ordering::Relaxed);
    LAST_Y.store(rect.y, Ordering::Relaxed);
    LAST_W.store(rect.w, Ordering::Relaxed);
    LAST_H.store(rect.h, Ordering::Relaxed);
    LAST_LEN.store(pixels.len(), Ordering::Relaxed);
}

fn last_rect() -> (u32, u32, u32, u32) {
    (
        LAST_X.load(Ordering::Relaxed),
        LAST_Y.load(Ordering::Relaxed),
        LAST_W.load(Ordering::Relaxed),
        LAST_H.load(Ordering::Relaxed),
    )
}

fn flushes() -> usize {
    FLUSH_COUNT.load(Ordering::Relaxed)
}

fn arm_flush_probe() {
    FLUSH_COUNT.store(0, Ordering::Relaxed);
    for c in [&LAST_X, &LAST_Y, &LAST_W, &LAST_H] {
        c.store(0, Ordering::Relaxed);
    }
    LAST_LEN.store(0, Ordering::Relaxed);
}

/// Run the pending `FbconFlush` softirq.
fn drain_flush() {
    // SAFETY: hosted unit test owns the fbcon flush slot under CONSOLE_TEST_DOMAIN.
    unsafe { softirq::run_pending(); }
}

// Test console geometry: 640x480 with the built-in 8x16 font is an 80x30
// grid, so one text row is 16 scanlines of a 480-scanline surface.
const TEST_XRES: u32 = 640;
const TEST_YRES: u32 = 480;
const TEST_CELL_H: u32 = 16;

#[test]
fn psf2_header_layout() {
    assert_eq!(core::mem::size_of::<font::Psf2Header>(), 32);
}

#[test]
fn step_emits_putchar_for_ascii() {
    let mut s = ParserState::default();
    assert_eq!(step(&mut s, b'A'), Action::PutChar('A' as u32));
}

#[test]
fn step_csi_cup_decodes_pos() {
    let mut s = ParserState::default();
    for &b in b"\x1b[10;20H" {
        step(&mut s, b);
    }
    let mut s2 = ParserState::default();
    let mut last = Action::None;
    for &b in b"\x1b[10;20H" {
        last = step(&mut s2, b);
    }
    assert_eq!(last, Action::CursorPosition(10, 20));
}

#[test]
fn step_csi_sgr_collects_params() {
    let mut s = ParserState::default();
    let mut last = Action::None;
    for &b in b"\x1b[1;31;47m" {
        last = step(&mut s, b);
    }
    if let Action::SetGraphicRendition(p, n) = last {
        assert_eq!(n, 3);
        assert_eq!(&p[..3], &[1, 31, 47]);
    } else {
        panic!("expected SetGraphicRendition");
    }
}

#[test]
fn step_decset_25_show_cursor() {
    let mut s = ParserState::default();
    let mut last = Action::None;
    for &b in b"\x1b[?25h" {
        last = step(&mut s, b);
    }
    assert_eq!(last, Action::SetMode(25, true));
}

#[test]
fn step_utf8_decode_two_byte() {
    let mut s = ParserState::default();
    step(&mut s, 0xc3);
    let act = step(&mut s, 0xa9);
    assert_eq!(act, Action::PutChar(0xe9));
}

#[test]
fn xterm_256_cube_mid() {
    assert_eq!(xterm_256(124), [175, 0, 0]);
}

#[test]
fn xterm_256_grayscale() {
    assert_eq!(xterm_256(232), [8, 8, 8]);
}

#[test]
fn vga_palette_size() {
    assert_eq!(VGA_PALETTE.len(), 16);
}

#[test]
fn console_new_dims() {
    let c = Console::new(640, 480);
    assert_eq!(c.cols, 80);
    assert_eq!(c.rows, 30);
    assert_eq!(c.fb.len(), 640 * 480 * 4);
}

#[test]
fn put_advances_cursor() {
    let mut c = Console::new(640, 480);
    c.put(b"abc");
    assert_eq!((c.cur_col, c.cur_row), (3, 0));
}

#[test]
fn newline_advances_row_only() {
    let mut c = Console::new(640, 480);
    c.put(b"abc\nx");
    assert_eq!(c.cur_col, 4);
    assert_eq!(c.cur_row, 1);
}

#[test]
fn carriage_return_resets_column() {
    let mut c = Console::new(640, 480);
    c.put(b"abc\rx");
    assert_eq!((c.cur_col, c.cur_row), (1, 0));
}

#[test]
fn ansi_csi_h_positions_cursor() {
    let mut c = Console::new(640, 480);
    c.put(b"\x1b[10;20H");
    assert_eq!((c.cur_row, c.cur_col), (9, 19));
}

#[test]
fn sgr_red_changes_fg() {
    let mut c = Console::new(640, 480);
    c.put(b"\x1b[31m");
    assert_eq!(c.fg, VGA_PALETTE[1]);
}

#[test]
fn kernel_graphics_mode_suppresses_foreground_rendering() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    arm_flush_probe();

    kernel::vt_write(1, b"text");
    drain_flush();
    assert!(flushes() > 0);

    arm_flush_probe();
    kernel::set_vt_graphics_mode(1, true);
    kernel::vt_write(1, b"graphics");
    drain_flush();
    assert_eq!(flushes(), 0);

    kernel::set_vt_graphics_mode(1, false);
    drain_flush();
    assert!(flushes() > 0);
    kernel::kernel_unregister();
}

// Console bring-up hands the sink the whole surface once: the device holds
// nothing yet, so the first upload legitimately damages everything.
#[test]
fn console_bring_up_flushes_the_whole_surface() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    arm_flush_probe();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);

    assert_eq!(flushes(), 1, "bring-up repaints once");
    assert_eq!(last_rect(), (0, 0, TEST_XRES, TEST_YRES));
    assert_eq!(LAST_LEN.load(Ordering::Relaxed), (TEST_XRES * TEST_YRES * 4) as usize);
    kernel::kernel_unregister();
}

// The defect this exists to prevent: one changed console line must upload
// that line's scanlines, not the frame. The sink still receives the whole
// pixel buffer — the rect is what bounds the work.
#[test]
fn one_line_of_output_damages_only_that_text_row() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    arm_flush_probe();

    kernel::vt_write(1, b"hello");
    drain_flush();

    assert_eq!(flushes(), 1);
    let (_x, y, _w, h) = last_rect();
    assert_eq!(y, 0, "text landed on the first row");
    assert_eq!(h, TEST_CELL_H, "one text row is one cell height of scanlines");
    // The surface handed over is still the whole frame; the rect is 1/30th.
    assert_eq!(LAST_LEN.load(Ordering::Relaxed), (TEST_XRES * TEST_YRES * 4) as usize);
    assert!(h * 30 <= TEST_YRES, "a line must not cost the frame");
    kernel::kernel_unregister();
}

// Writing on a later row damages that row, not everything above it.
#[test]
fn a_later_row_damages_that_row_alone() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);

    // Park the cursor on text row 4 and drain, so the move itself is not
    // part of the measured flush.
    kernel::vt_write(1, b"\x1b[5;1H");
    drain_flush();
    arm_flush_probe();

    kernel::vt_write(1, b"x");
    drain_flush();

    assert_eq!(flushes(), 1);
    let (_x, y, _w, h) = last_rect();
    assert_eq!(y, 4 * TEST_CELL_H);
    assert_eq!(h, TEST_CELL_H);
    kernel::kernel_unregister();
}

// Damage between flushes accumulates: two writes on different rows coalesce
// into one upload covering both, and nothing outside them.
#[test]
fn damage_coalesces_across_writes_between_flushes() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    kernel::vt_write(1, b"\x1b[2;1Ha");
    drain_flush();
    arm_flush_probe();

    // Rows 2 and 4 (1-based), no drain in between.
    kernel::vt_write(1, b"\x1b[3;1Hb");
    kernel::vt_write(1, b"\x1b[5;1Hc");
    drain_flush();

    assert_eq!(flushes(), 1, "one coalesced upload, not one per write");
    let (_x, y, _w, h) = last_rect();
    // Row 1 still carries the cursor block left by the previous write; moving
    // the cursor away has to erase it, so that row is damaged too and the box
    // starts there rather than at the first row this pass wrote.
    assert_eq!(y, 1 * TEST_CELL_H, "the erased old cursor cell is inside the box");
    // ...down to the bottom of row 4, the last row written.
    assert_eq!(y + h, 5 * TEST_CELL_H, "ends at the bottom of the last touched row");
    // Still a fraction of the 30-row surface, not the frame.
    assert!(h < TEST_YRES / 2, "coalescing must not degenerate to a full frame");
    kernel::kernel_unregister();
}

// A flush with nothing damaged must issue no upload at all — the device
// already holds the current frame.
#[test]
fn a_flush_with_no_damage_uploads_nothing() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    kernel::vt_write(1, b"text");
    drain_flush();
    arm_flush_probe();

    kernel::force_repaint();
    drain_flush();
    arm_flush_probe();

    // Nothing rendered since; raising the softirq again must be a no-op.
    softirq::raise(softirq::Slot::FbconFlush);
    drain_flush();
    assert_eq!(flushes(), 0);
    kernel::kernel_unregister();
}

// A repaint (VT switch, unblank, scanout restore) legitimately damages
// everything: the device's copy is stale, so the full frame must go up.
#[test]
fn force_repaint_damages_the_whole_surface() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    kernel::vt_write(1, b"text");
    drain_flush();
    arm_flush_probe();

    kernel::force_repaint();
    drain_flush();

    assert_eq!(flushes(), 1);
    assert_eq!(last_rect(), (0, 0, TEST_XRES, TEST_YRES));
    kernel::kernel_unregister();
}

// Switching to another VT repaints from that VT's cell grid, so the whole
// surface is damaged rather than the last line written.
#[test]
fn vt_switch_damages_the_whole_surface() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    kernel::vt_write(1, b"one");
    drain_flush();
    arm_flush_probe();

    kernel::switch_vt(2);
    drain_flush();

    assert_eq!(flushes(), 1);
    assert_eq!(last_rect(), (0, 0, TEST_XRES, TEST_YRES));
    kernel::kernel_unregister();
}

// Leaving graphics mode repaints the text grid from scratch — the DRM client
// owned the scanout meanwhile, so nothing on it can be trusted.
#[test]
fn leaving_graphics_mode_damages_the_whole_surface() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    kernel::set_vt_graphics_mode(1, true);
    drain_flush();
    arm_flush_probe();

    kernel::set_vt_graphics_mode(1, false);
    drain_flush();

    assert_eq!(flushes(), 1);
    assert_eq!(last_rect(), (0, 0, TEST_XRES, TEST_YRES));
    kernel::kernel_unregister();
}

// Scrollback moves every row, so the whole surface is damaged — the damage
// path must not shrink a scroll to the rows the emulator last wrote.
#[test]
fn scrollback_damages_the_whole_surface() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    for _ in 0..64 {
        kernel::vt_write(1, b"line\r\n");
    }
    drain_flush();
    arm_flush_probe();

    kernel::scrolldelta(4);
    drain_flush();

    assert_eq!(flushes(), 1);
    assert_eq!(last_rect(), (0, 0, TEST_XRES, TEST_YRES));
    kernel::kernel_unregister();
}

// Scrolling off the bottom of the screen rewrites every row, so the upload
// must cover the frame and the text must not be left stale on the device.
#[test]
fn scrolling_past_the_last_row_damages_every_row() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    // Fill the 30-row grid, then force it to scroll.
    for _ in 0..30 {
        kernel::vt_write(1, b"filler\r\n");
    }
    drain_flush();
    arm_flush_probe();

    kernel::vt_write(1, b"scrolled\r\n");
    drain_flush();

    assert_eq!(flushes(), 1);
    assert_eq!(last_rect(), (0, 0, TEST_XRES, TEST_YRES), "a scroll moves every row");
    kernel::kernel_unregister();
}

// Damage raised before a sink exists must survive: `kernel_init` installs
// the sink last, and the bring-up repaint has to still see the full frame.
#[test]
fn damage_raised_without_a_sink_is_deferred_not_dropped() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    arm_flush_probe();
    // No sink installed: the raised softirq must not consume the damage.
    softirq::raise(softirq::Slot::FbconFlush);
    drain_flush();
    assert_eq!(flushes(), 0);

    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    assert_eq!(flushes(), 1);
    assert_eq!(last_rect(), (0, 0, TEST_XRES, TEST_YRES));
    kernel::kernel_unregister();
}
