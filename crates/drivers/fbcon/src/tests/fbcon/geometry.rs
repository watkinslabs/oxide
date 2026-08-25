use super::*;

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

#[test]
fn scanout_rebind_resizes_the_live_console_to_the_native_mode() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    kernel::vt_write(1, b"firmware status");
    drain_flush();
    arm_flush_probe();

    assert!(kernel::kernel_rebind(NATIVE_XRES, NATIVE_YRES, count_flush));
    drain_flush();
    assert_eq!(flushes(), 1, "the native scanout receives a full repaint");
    assert_eq!(last_rect(), (0, 0, NATIVE_XRES, NATIVE_YRES));
    assert_eq!(LAST_LEN.load(Ordering::Relaxed), (NATIVE_XRES * NATIVE_YRES * 4) as usize);
    assert_eq!(kernel::console_dims(), Some((48, 128)));
    assert!(kernel::screen_dump(false).starts_with(b"firmware status"));
    kernel::kernel_unregister();
}

#[test]
fn scanout_rebind_notifies_the_numbered_vt_geometry_consumer() {
    let _guard = CONSOLE_TEST_DOMAIN.lock();
    kernel::kernel_unregister();
    arm_geometry_probe();
    kernel::set_geometry_sink(capture_geometry);
    kernel::kernel_init(TEST_XRES, TEST_YRES, count_flush);
    assert_eq!(GEOMETRY_COUNT.load(Ordering::Relaxed), 1);
    assert_eq!(
        (
            GEOMETRY_ROWS.load(Ordering::Relaxed),
            GEOMETRY_COLS.load(Ordering::Relaxed),
            GEOMETRY_YPIXEL.load(Ordering::Relaxed),
        ),
        (30, 80, TEST_YRES),
    );

    assert!(kernel::kernel_rebind(NATIVE_XRES, NATIVE_YRES, count_flush));
    assert_eq!(GEOMETRY_COUNT.load(Ordering::Relaxed), 2);
    assert_eq!(
        (
            GEOMETRY_ROWS.load(Ordering::Relaxed),
            GEOMETRY_COLS.load(Ordering::Relaxed),
            GEOMETRY_YPIXEL.load(Ordering::Relaxed),
        ),
        (48, 128, NATIVE_YRES),
        "the early firmware geometry must not survive the native rebind",
    );
    kernel::kernel_unregister();
}

// The defect this exists to prevent: one changed console line must upload
// that line's scanlines, not the frame. The sink still receives the whole
// pixel buffer — the rect is what bounds the work.

