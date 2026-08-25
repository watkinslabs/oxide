use super::*;

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

// Linux suspends console irq-work before CPU teardown: the last visible
// damage is flushed synchronously, writes during the suspended interval stay
// in the retained console image without pinning their current CPU, and resume
// publishes that accumulated damage once.
#[test]
fn console_suspend_blocks_softirq_publication_until_resume() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    drain_flush();

    arm_flush_probe();
    kernel::vt_console_sink(b"before suspend");
    assert!(softirq::local_pending());
    kernel::console_suspend();
    assert_eq!(flushes(), 1, "pre-suspend damage flushed synchronously");
    assert!(!softirq::local_pending(), "stale per-CPU publication cancelled");

    arm_flush_probe();
    kernel::vt_console_sink(b"while suspended");
    assert!(!softirq::local_pending(), "console logging cannot pin a dying CPU");
    drain_flush();
    assert_eq!(flushes(), 0, "no framebuffer device access while suspended");

    kernel::console_resume();
    assert!(softirq::local_pending(), "retained damage queued on resume");
    drain_flush();
    assert_eq!(flushes(), 1, "suspended output becomes visible after resume");
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

