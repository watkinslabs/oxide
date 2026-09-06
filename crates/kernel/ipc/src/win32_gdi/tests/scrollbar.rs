use super::*;

const METRICS: ScrollMetrics = ScrollMetrics { arrow_size: 17, dpi: 96 };
const COLORS: ScrollColors = ScrollColors { face: 0xc0c0c0, highlight: 0xffffff, light: 0xdfdfdf,
    shadow: 0x808080, dark_shadow: 0x404040, text: 0x010101, window: 0xfefefe, track: 0xaabbcc };
const BAR: Rect = Rect { left: 2, top: 2, right: 19, bottom: 202 };
fn state() -> ScrollState { ScrollState { min: 0, max: 99, page: 20, pos: 40, track_pos: 0,
    tracking: false, visible: true, disabled: false } }
fn draw(g: &mut GdiManager, dc: u32, s: ScrollState, part: ScrollPart) -> ScrollDrawOutcome {
    g.draw_nonclient_scrollbar(dc, BAR, true, s, METRICS, COLORS, part).unwrap()
}
fn pixel(g: &GdiManager, dc: u32, x: usize, y: usize) -> u32 { g.pixels(dc).unwrap()[y * 24 + x] }

#[test]
fn proportional_geometry_rounding_dpi_short_and_tracking() {
    assert_eq!(scrollbar_layout(200, state(), METRICS).unwrap(), ScrollLayout { arrow_size: 17, thumb_pos: 84, thumb_size: 33 });
    let mut s = state(); s.page = 1; s.pos = 0;
    assert_eq!(scrollbar_layout(200, s, METRICS).unwrap().thumb_size, 17);
    assert_eq!(scrollbar_layout(200, s, ScrollMetrics { dpi: 192, ..METRICS }).unwrap().thumb_size, 34);
    assert_eq!(scrollbar_layout(38, s, METRICS).unwrap(), ScrollLayout { arrow_size: 17, thumb_pos: 0, thumb_size: 0 });
    assert_eq!(scrollbar_layout(11, s, METRICS).unwrap().arrow_size, 3);
    assert_eq!(scrollbar_layout(4, s, METRICS).unwrap().arrow_size, 0);
    s.tracking = true; s.track_pos = 99;
    assert_eq!(scrollbar_layout(200, s, METRICS).unwrap().thumb_pos, 166);
    s.disabled = true;
    assert_eq!(scrollbar_layout(200, s, METRICS).unwrap().thumb_size, 0);
}

#[test]
fn real_vertical_pixels_contain_arrows_track_thumb_and_position_changes() {
    let mut g = GdiManager::new(); let dc = g.create_dc(24, 208).unwrap();
    assert_eq!(draw(&mut g, dc, state(), ScrollPart::None), ScrollDrawOutcome::Painted(BAR));
    assert_eq!(pixel(&g, dc, 10, 40), COLORS.track);
    assert_eq!(pixel(&g, dc, 10, 95), COLORS.face);
    assert_eq!(pixel(&g, dc, 10, 10), COLORS.text);
    assert_eq!(pixel(&g, dc, 10, 195), COLORS.text);
    assert_eq!(pixel(&g, dc, 1, 95), 0);
    let mut s = state(); s.pos = 0;
    draw(&mut g, dc, s, ScrollPart::None);
    assert_eq!(pixel(&g, dc, 10, 30), COLORS.face);
    assert_eq!(pixel(&g, dc, 10, 95), COLORS.track);
}

#[test]
fn horizontal_raster_has_both_arrows_and_proportional_thumb() {
    let mut g = GdiManager::new(); let dc = g.create_dc(208, 24).unwrap();
    let bounds = Rect { left: 2, top: 2, right: 202, bottom: 19 };
    assert_eq!(g.draw_nonclient_scrollbar(dc, bounds, false, state(), METRICS, COLORS, ScrollPart::None), Ok(ScrollDrawOutcome::Painted(bounds)));
    let p = g.pixels(dc).unwrap();
    assert_eq!(p[10 * 208 + 10], COLORS.text);
    assert_eq!(p[10 * 208 + 195], COLORS.text);
    assert_eq!(p[10 * 208 + 40], COLORS.track);
    assert_eq!(p[10 * 208 + 95], COLORS.face);
}

#[test]
fn disabled_and_pressed_change_actual_pixels_without_owner_mutation() {
    let mut g = GdiManager::new(); let dc = g.create_dc(24, 208).unwrap();
    let mut s = state(); s.disabled = true;
    draw(&mut g, dc, s, ScrollPart::FirstArrow);
    assert_eq!(pixel(&g, dc, 10, 95), COLORS.track);
    assert_eq!(pixel(&g, dc, 10, 10), COLORS.shadow);
    draw(&mut g, dc, state(), ScrollPart::FirstPage);
    assert_eq!(pixel(&g, dc, 10, 40), COLORS.track ^ RGB_MASK);
    assert_eq!(pixel(&g, dc, 10, 150), COLORS.track);
    draw(&mut g, dc, state(), ScrollPart::LastPage);
    assert_eq!(pixel(&g, dc, 10, 150), COLORS.track ^ RGB_MASK);
    draw(&mut g, dc, state(), ScrollPart::FirstArrow);
    assert_eq!(pixel(&g, dc, 2, 2), COLORS.shadow);
    draw(&mut g, dc, state(), ScrollPart::None);
    assert_eq!(pixel(&g, dc, 2, 2), COLORS.light);
    assert!(s.disabled);
}

#[test]
fn application_paint_surface_intersection_and_empty_paint_are_real() {
    let mut g = GdiManager::new(); let dc = g.create_dc(24, 208).unwrap();
    g.intersect_clip_rect(dc, Rect { left: 5, top: 30, right: 16, bottom: 90 }).unwrap();
    g.set_paint_clip(dc, Rect { left: 9, top: 20, right: 30, bottom: 50 }).unwrap();
    assert_eq!(draw(&mut g, dc, state(), ScrollPart::None), ScrollDrawOutcome::Painted(Rect { left: 9, top: 30, right: 16, bottom: 50 }));
    for y in 0..208 { for x in 0..24 {
        assert_eq!(pixel(&g, dc, x, y), if (9..16).contains(&x) && (30..50).contains(&y) { COLORS.track } else { 0 });
    } }
    let before = g.pixels(dc).unwrap().to_vec();
    g.set_paint_clip(dc, Rect { left: 0, top: 0, right: 0, bottom: 0 }).unwrap();
    assert_eq!(draw(&mut g, dc, state(), ScrollPart::None), ScrollDrawOutcome::Clipped);
    assert_eq!(g.pixels(dc).unwrap(), before);
    let small = g.create_dc(10, 10).unwrap();
    assert_eq!(draw(&mut g, small, state(), ScrollPart::None), ScrollDrawOutcome::Painted(Rect { left: 2, top: 2, right: 10, bottom: 10 }));
}

#[test]
fn hidden_offsurface_and_zero_geometry_do_not_claim_erasure() {
    let mut g = GdiManager::new(); let dc = g.create_dc(24, 208).unwrap();
    draw(&mut g, dc, state(), ScrollPart::None);
    let before = g.pixels(dc).unwrap().to_vec();
    let mut s = state(); s.visible = false;
    assert_eq!(draw(&mut g, dc, s, ScrollPart::None), ScrollDrawOutcome::Hidden);
    assert_eq!(g.pixels(dc).unwrap(), before);
    for bounds in [Rect { left: 30, right: 47, ..BAR }, Rect { right: BAR.left, ..BAR }] {
        assert_eq!(g.draw_nonclient_scrollbar(dc, bounds, true, state(), METRICS, COLORS, ScrollPart::None), Ok(ScrollDrawOutcome::Clipped));
    }
    assert_eq!(g.pixels(dc).unwrap(), before);
}

#[test]
fn checker_track_and_short_bar_have_real_pixels() {
    let mut g = GdiManager::new(); let dc = g.create_dc(24, 208).unwrap();
    let colors = ScrollColors { window: COLORS.highlight, ..COLORS };
    let bounds = Rect { bottom: 13, ..BAR };
    g.draw_nonclient_scrollbar(dc, bounds, true, state(), METRICS, colors, ScrollPart::None).unwrap();
    assert_eq!(pixel(&g, dc, 10, 6), COLORS.highlight);
    assert_eq!(pixel(&g, dc, 10, 7), COLORS.face);
}

#[test]
fn invalid_inputs_fail_before_pixel_mutation() {
    let mut g = GdiManager::new(); let dc = g.create_dc(24, 208).unwrap();
    assert_eq!(g.draw_nonclient_scrollbar(0, BAR, true, state(), METRICS, COLORS, ScrollPart::None), Err(GdiError::NoSuchObject));
    for bounds in [Rect { right: -1, ..BAR }, Rect { left: i32::MIN, right: i32::MAX, ..BAR }] {
        assert_eq!(g.draw_nonclient_scrollbar(dc, bounds, true, state(), METRICS, COLORS, ScrollPart::None), Err(GdiError::InvalidDimensions));
    }
    let colors = ScrollColors { face: 0xff000000, ..COLORS };
    assert_eq!(g.draw_nonclient_scrollbar(dc, BAR, true, state(), METRICS, colors, ScrollPart::None), Err(GdiError::InvalidDimensions));
    assert!(g.pixels(dc).unwrap().iter().all(|p| *p == 0));
    assert!(scrollbar_layout(200, state(), ScrollMetrics { dpi: 0, ..METRICS }).is_err());
    assert!(scrollbar_layout(200, ScrollState { min: 100, ..state() }, METRICS).is_err());
}
