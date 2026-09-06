use super::*;

fn context() -> NonclientScrollContext {
    NonclientScrollContext { window: WindowRect { left: 50, top: 60, right: 90, bottom: 160 },
        client: Rect { left: 2, top: 3, right: 23, bottom: 80 }, style: WS_HSCROLL | WS_VSCROLL, ex_style: 0,
        metrics: ScrollMetrics { arrow_size: 17, dpi: 96 }, pressed: ScrollPart::None,
        colors: ScrollColors { face: 0xd4d0c8, highlight: 0xffffff, light: 0xd4d0c8, shadow: 0x808080,
            dark_shadow: 0x404040, text: 0, window: 0xffffff, track: 0xd4d0c8 } }
}
fn scroll() -> ScrollState { ScrollState { visible: true, max: 99, page: 20, pos: 40, ..ScrollState::new() } }

#[test]
fn canonical_client_parent_coordinates_translate_once_for_positive_and_negative_origins() {
    let base = context();
    for (x, y) in [(50, 60), (-500, -600), (0, 0)] {
        let window = WindowRect { left: x, top: y, right: x + 40, bottom: y + 100 };
        let client = WindowRect { left: x + 2, top: y + 3, right: x + 23, bottom: y + 80 };
        let c = nonclient_scroll_context(window, client, base.style, base.ex_style, base.metrics, base.colors, base.pressed).unwrap();
        assert_eq!(c.client, base.client);
        assert_eq!(c.window, window);
        assert_eq!(bounds(c, SB_VERT), bounds(base, SB_VERT));
        assert_eq!(bounds(c, SB_HORZ), bounds(base, SB_HORZ));
    }
}

#[test]
fn context_rejects_overflow_reversed_outside_client_but_keeps_zero_client() {
    let c = context();
    let make = |window, client| nonclient_scroll_context(window, client, c.style, c.ex_style, c.metrics, c.colors, c.pressed);
    assert!(make(c.window, WindowRect { left: 52, top: 63, right: 52, bottom: 63 }).is_some());
    for client in [WindowRect { left: 49, top: 60, right: 70, bottom: 80 },
        WindowRect { left: 52, top: 63, right: 51, bottom: 80 },
        WindowRect { left: 52, top: 63, right: 91, bottom: 80 },
        WindowRect { left: i32::MIN, top: 60, right: 70, bottom: 80 }] {
        assert!(make(c.window, client).is_none());
    }
    assert!(make(WindowRect { left: i32::MIN, right: i32::MAX, ..c.window }, c.window).is_none());
}

#[test]
fn window_relative_bar_geometry_handles_left_side_and_crossbar_pixel() {
    let c = context();
    assert_eq!(bounds(c, SB_VERT), Ok(Some(Rect { left: 23, top: 3, right: 40, bottom: 81 })));
    assert_eq!(bounds(c, SB_HORZ), Ok(Some(Rect { left: 2, top: 80, right: 24, bottom: 97 })));
    assert_eq!(bounds(NonclientScrollContext { ex_style: WS_EX_LEFTSCROLLBAR, ..c }, SB_VERT),
        Ok(Some(Rect { left: -15, top: 3, right: 2, bottom: 81 })));
    assert_eq!(bounds(NonclientScrollContext { style: 0, ..c }, SB_VERT), Ok(None));
    assert!(bounds(c, 2).is_err());
}

#[test]
fn actual_existing_backing_preserves_every_client_pixel_and_identity() {
    let mut gdi = GdiManager::new();
    let dc = gdi.acquire_window_dc(7, 40, 100).unwrap();
    gdi.fill_rect(dc, Rect { left: 0, top: 0, right: 40, bottom: 100 }, 0x123456).unwrap();
    let before = gdi.text_state(dc).unwrap();
    let (result_dc, outcome) = render(&mut gdi, 7, SB_VERT, scroll(), context()).unwrap();
    assert_eq!(result_dc, dc);
    assert_eq!(outcome, ScrollDrawOutcome::Painted(Rect { left: 23, top: 3, right: 40, bottom: 81 }));
    assert_eq!(gdi.text_state(dc).unwrap(), before);
    let pixels = gdi.pixels(dc).unwrap();
    for y in 0..100 { for x in 0..40 {
        if x < 23 || y < 3 || y >= 81 { assert_eq!(pixels[y * 40 + x], 0x123456); }
    } }
    assert_eq!(pixels[3 * 40 + 23], context().colors.light);
}

#[test]
fn missing_or_wrong_sized_backing_never_allocates_resizes_or_writes() {
    let mut gdi = GdiManager::new();
    assert_eq!(render(&mut gdi, 7, SB_VERT, scroll(), context()), Err(GdiError::NoSuchObject));
    assert_eq!(gdi.window_dc(7), None);
    let dc = gdi.acquire_window_dc(7, 21, 77).unwrap();
    let before = gdi.text_state(dc).unwrap();
    assert_eq!(render(&mut gdi, 7, SB_VERT, scroll(), context()), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.text_state(dc).unwrap(), before);
    assert!(gdi.pixels(dc).unwrap().iter().all(|pixel| *pixel == 0));
}

#[test]
fn clipping_and_hidden_are_not_presentable_repaint_proofs() {
    let mut gdi = GdiManager::new(); let dc = gdi.acquire_window_dc(7, 40, 100).unwrap();
    gdi.set_paint_clip(dc, Rect { left: 0, top: 0, right: 23, bottom: 80 }).unwrap();
    assert_eq!(render(&mut gdi, 7, SB_VERT, scroll(), context()), Ok((dc, ScrollDrawOutcome::Clipped)));
    assert_eq!(render(&mut gdi, 7, SB_VERT, scroll(), NonclientScrollContext { style: 0, ..context() }), Ok((dc, ScrollDrawOutcome::Hidden)));
    assert!(gdi.pixels(dc).unwrap().iter().all(|pixel| *pixel == 0));
}
