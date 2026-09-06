use super::*;
const CLIENT: Rect = Rect { left: 2, top: 3, right: 6, bottom: 7 };
const LAYOUT: PaintBacking = PaintBacking { width: 9, height: 10, client: CLIENT };
const DAMAGE: Rect = Rect { left: 1, top: 1, right: 3, bottom: 3 };

#[test]
fn dirty_client_offset_preserves_all_other_pixels_and_ignores_backing_clips() {
    let mut g = GdiManager::new(); let dc = g.acquire_window_dc(7, 9, 10).unwrap();
    g.fill_rect(dc, Rect { left: 0, top: 0, right: 9, bottom: 10 }, 0x123456).unwrap();
    g.intersect_clip_rect(dc, Rect { left: 0, top: 0, right: 1, bottom: 1 }).unwrap();
    g.set_paint_clip(dc, Rect { left: 0, top: 0, right: 0, bottom: 0 }).unwrap();
    let before = g.dcs.iter().find(|(id, _)| *id == dc).unwrap().1.text;
    let paint = g.create_dc(9, 10).unwrap(); g.fill_rect(paint, DAMAGE, 0xabcdef).unwrap();
    assert_eq!(g.retain_paint(7, paint, DAMAGE, LAYOUT), Ok(dc));
    for y in 0..10 { for x in 0..9 {
        assert_eq!(g.pixels(dc).unwrap()[y * 9 + x], if (3..5).contains(&x) && (4..6).contains(&y) { 0xabcdef } else { 0x123456 });
    } }
    let target = &g.dcs.iter().find(|(id, _)| *id == dc).unwrap().1;
    assert_eq!(target.text, before);
    assert_eq!(target.clip, Some(Rect { left: 0, top: 0, right: 1, bottom: 1 }));
    assert!(target.paint_clip.as_ref().unwrap().is_empty());
    g.delete_object(paint).unwrap();
    assert_eq!(g.window_dc(7), Some(dc));
    assert_eq!(g.pixels(dc).unwrap()[4 * 9 + 3], 0xabcdef);
}

#[test]
fn resize_preserves_overlap_and_supports_source_before_destination() {
    let mut g = GdiManager::new(); let paint = g.create_dc(9, 10).unwrap();
    g.fill_rect(paint, DAMAGE, 0xabcdef).unwrap();
    let dc = g.acquire_window_dc(7, 6, 7).unwrap();
    g.fill_rect(dc, Rect { left: 0, top: 0, right: 6, bottom: 7 }, 0x123456).unwrap();
    assert_eq!(g.retain_paint(7, paint, DAMAGE, LAYOUT), Ok(dc));
    assert_eq!(g.surface(dc).map(|(w,h,_)| (w,h)), Some((9,10)));
    assert_eq!(g.pixels(dc).unwrap()[0], 0x123456);
    assert_eq!(g.pixels(dc).unwrap()[4 * 9 + 3], 0xabcdef);
    assert_eq!(g.pixels(dc).unwrap()[9 * 9 + 8], 0);
}

#[test]
fn rejected_merge_does_not_resize_or_allocate_missing_backing() {
    let mut g = GdiManager::new(); let paint = g.create_dc(9, 10).unwrap();
    assert_eq!(g.retain_paint(7, paint, DAMAGE, LAYOUT), Err(GdiError::NoSuchObject));
    assert_eq!(g.window_dc(7), None);
    let dc = g.acquire_window_dc(7, 6, 7).unwrap(); let before = g.text_state(dc).unwrap();
    for damage in [Rect { right: 5, ..DAMAGE }, Rect { left: -1, ..DAMAGE }, Rect { right: 1, ..DAMAGE }] {
        assert_eq!(g.retain_paint(7, paint, damage, LAYOUT), Err(GdiError::InvalidDimensions));
    }
    assert_eq!(g.retain_paint(7, dc, DAMAGE, LAYOUT), Err(GdiError::InvalidDimensions));
    assert_eq!(g.retain_paint(7, paint, DAMAGE, PaintBacking { width: i32::MAX, ..LAYOUT }), Err(GdiError::InvalidDimensions));
    assert_eq!(g.text_state(dc).unwrap(), before);
    assert!(g.pixels(dc).unwrap().iter().all(|pixel| *pixel == 0));
}

#[test]
fn seed_translates_client_to_origin_preserves_attributes_and_ignores_both_clips() {
    for paint_first in [false, true] {
        let mut g = GdiManager::new();
        let early = if paint_first { Some(g.create_dc(9, 10).unwrap()) } else { None };
        let dc = g.acquire_window_dc(7, 9, 10).unwrap();
        let paint = early.unwrap_or_else(|| g.create_dc(9, 10).unwrap());
        g.fill_rect(dc, CLIENT, 0xabcdef).unwrap();
        g.fill_rect(paint, Rect { left: 0, top: 0, right: 9, bottom: 10 }, 0x123456).unwrap();
        for handle in [dc, paint] {
            g.intersect_clip_rect(handle, Rect { left: 0, top: 0, right: 0, bottom: 0 }).unwrap();
            g.set_paint_clip(handle, Rect { left: 0, top: 0, right: 0, bottom: 0 }).unwrap();
        }
        let before = g.text_state(paint).unwrap();
        assert_eq!(g.seed_paint(7, paint, LAYOUT), Ok(()));
        for y in 0..10 { for x in 0..9 {
            assert_eq!(g.pixels(paint).unwrap()[y * 9 + x], if x < 4 && y < 4 { 0xabcdef } else { 0x123456 });
        } }
        assert_eq!(g.text_state(paint).unwrap(), before);
        assert_eq!(g.get_app_clip_box(paint).unwrap().0, super::super::NULL_REGION);
        assert_eq!(g.get_app_clip_box(dc).unwrap().0, super::super::NULL_REGION);
    }
}

#[test]
fn seed_rejects_missing_alias_wrong_geometry_and_short_destination_atomically() {
    let mut g = GdiManager::new(); let paint = g.create_dc(3, 3).unwrap();
    assert_eq!(g.seed_paint(7, paint, LAYOUT), Err(GdiError::NoSuchObject));
    let dc = g.acquire_window_dc(7, 9, 10).unwrap();
    assert_eq!(g.seed_paint(7, dc, LAYOUT), Err(GdiError::InvalidDimensions));
    assert_eq!(g.seed_paint(7, paint, LAYOUT), Err(GdiError::InvalidDimensions));
    for layout in [PaintBacking { width: 8, ..LAYOUT },
        PaintBacking { client: Rect { left: -1, ..CLIENT }, ..LAYOUT },
        PaintBacking { client: Rect { left: i32::MIN, right: i32::MAX, ..CLIENT }, ..LAYOUT }] {
        assert_eq!(g.seed_paint(7, paint, layout), Err(GdiError::InvalidDimensions));
    }
    assert!(g.pixels(paint).unwrap().iter().all(|pixel| *pixel == 0));
    assert_eq!(g.surface(paint).map(|(w,h,_)| (w,h)), Some((3,3)));
    let empty = PaintBacking { client: Rect { right: CLIENT.left, bottom: CLIENT.top, ..CLIENT }, ..LAYOUT };
    assert_eq!(g.seed_paint(7, paint, empty), Ok(()));
}

#[test]
fn seeded_transparent_and_application_clipped_dirty_pixels_survive_retention() {
    let mut g = GdiManager::new(); let dc = g.acquire_window_dc(7, 9, 10).unwrap();
    g.fill_rect(dc, CLIENT, 0x123456).unwrap();
    let paint = g.create_dc(9, 10).unwrap();
    g.seed_paint(7, paint, LAYOUT).unwrap();
    g.blend_pixels(paint, 2, 2, 1, 1, &[0x00ffffff]).unwrap();
    g.intersect_clip_rect(paint, Rect { left: 0, top: 0, right: 1, bottom: 1 }).unwrap();
    g.fill_rect(paint, Rect { left: 0, top: 0, right: 4, bottom: 4 }, 0xabcdef).unwrap();
    g.retain_paint(7, paint, Rect { left: 0, top: 0, right: 4, bottom: 4 }, LAYOUT).unwrap();
    for y in 0..4 { for x in 0..4 {
        assert_eq!(g.pixels(dc).unwrap()[(y + 3) * 9 + x + 2], if x == 0 && y == 0 { 0xabcdef } else { 0x123456 });
    } }
}

#[test]
fn region_retention_rejects_later_invalid_rectangle_before_resize_or_first_write() {
    let mut g = GdiManager::new(); let dc = g.acquire_window_dc(7, 6, 7).unwrap();
    g.fill_rect(dc, Rect { left: 0, top: 0, right: 6, bottom: 7 }, 0x123456).unwrap();
    let paint = g.create_dc(9, 10).unwrap(); g.fill_rect(paint, Rect { left: 0, top: 0, right: 9, bottom: 10 }, 0xffffff).unwrap();
    let valid = WindowRect { left: 0, top: 0, right: 1, bottom: 1 };
    let invalid = WindowRect { left: 3, top: 3, right: 5, bottom: 5 };
    let coverage = PaintRegion::from_rects(&[valid, invalid]).unwrap();
    assert_eq!(g.retain_paint_region(7, paint, &coverage, LAYOUT), Err(GdiError::InvalidDimensions));
    assert_eq!(g.surface(dc).map(|(w,h,_)| (w,h)), Some((6,7)));
    assert!(g.pixels(dc).unwrap().iter().all(|pixel| *pixel == 0x123456));
}

#[test]
fn exact_retention_preserves_gap_even_when_source_gap_has_different_pixels() {
    let mut g = GdiManager::new(); let dc = g.acquire_window_dc(7, 9, 10).unwrap();
    g.fill_rect(dc, Rect { left: 0, top: 0, right: 9, bottom: 10 }, 0x123456).unwrap();
    let paint = g.create_dc(9, 10).unwrap(); g.fill_rect(paint, Rect { left: 0, top: 0, right: 9, bottom: 10 }, 0xffffff).unwrap();
    let coverage = PaintRegion::from_rects(&[WindowRect { left: 0, top: 0, right: 1, bottom: 4 },
        WindowRect { left: 3, top: 0, right: 4, bottom: 4 }]).unwrap();
    assert_eq!(g.retain_paint_region(7, paint, &coverage, LAYOUT), Ok(dc));
    for y in 0..10 { for x in 0..9 {
        assert_eq!(g.pixels(dc).unwrap()[y * 9 + x], if (3..7).contains(&y) && (x == 2 || x == 5) { 0xffffff } else { 0x123456 });
    } }
}
