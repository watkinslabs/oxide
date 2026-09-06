use super::*;

fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect { Rect { left, top, right, bottom } }

#[test]
fn paint_clip_never_replaces_application_clip_or_its_first_intersection_state() {
    let mut owner = GdiManager::new(); let dc = owner.create_dc(4, 4).unwrap();
    owner.set_paint_clip(dc, rect(1, 1, 3, 3)).unwrap();
    assert_eq!(owner.intersect_clip_rect(dc, rect(0, 0, 4, 4)), Ok(SIMPLE_REGION));
    assert_eq!(owner.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(1, 1, 3, 3))));
    owner.intersect_clip_rect(dc, rect(2, 0, 4, 4)).unwrap();
    owner.set_paint_clip(dc, rect(0, 0, 4, 4)).unwrap();
    assert_eq!(owner.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(2, 0, 4, 4))));
    let fresh = owner.create_dc(2, 2).unwrap();
    owner.set_paint_clip(fresh, EMPTY).unwrap();
    assert_eq!(owner.intersect_clip_rect(fresh, EMPTY), Ok(SIMPLE_REGION));
    assert_eq!(owner.get_app_clip_box(fresh), Ok((NULL_REGION, EMPTY)));
}

#[test]
fn fresh_paint_dcs_do_not_accumulate_previous_paint_clip() {
    let mut owner = GdiManager::new();
    for paint in [rect(0, 0, 1, 1), rect(2, 2, 3, 3)] {
        let dc = owner.create_dc(3, 3).unwrap();
        owner.set_paint_clip(dc, paint).unwrap();
        owner.intersect_clip_rect(dc, rect(0, 0, 3, 3)).unwrap();
        owner.fill_rect(dc, rect(0, 0, 3, 3), 0xffffff).unwrap();
        let mut expected = [0; 9]; expected[(paint.top * 3 + paint.left) as usize] = 0xffffff;
        assert_eq!(owner.pixels(dc).unwrap(), expected);
        owner.delete_object(dc).unwrap();
    }
}

#[test]
fn invalid_paint_bounds_preserve_clip_and_resize_preserves_paint_geometry() {
    let mut owner = GdiManager::new(); let dc = owner.create_dc(2, 2).unwrap();
    owner.set_paint_clip(dc, rect(3, 3, 6, 6)).unwrap();
    assert_eq!(owner.get_app_clip_box(dc), Ok((NULL_REGION, EMPTY)));
    assert_eq!(owner.set_paint_clip(dc, rect(4, 0, 1, 1)), Err(GdiError::InvalidDimensions));
    owner.resize_dc(dc, 5, 5).unwrap();
    assert_eq!(owner.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(3, 3, 5, 5))));
    assert_eq!(owner.set_paint_clip(0, EMPTY), Err(GdiError::NoSuchObject));
}

#[test]
fn repeated_intersection_reports_application_complexity_and_effective_bounds() {
    let mut owner = GdiManager::new(); let dc = owner.create_dc(4, 4).unwrap();
    assert_eq!(owner.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(0, 0, 4, 4))));
    assert_eq!(owner.intersect_clip_rect(dc, rect(5, 5, 1, 1)), Ok(SIMPLE_REGION));
    assert_eq!(owner.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(1, 1, 4, 4))));
    assert_eq!(owner.intersect_clip_rect(dc, rect(2, -1, 3, 3)), Ok(SIMPLE_REGION));
    assert_eq!(owner.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(2, 1, 3, 3))));
    assert_eq!(owner.intersect_clip_rect(dc, rect(3, 3, 4, 4)), Ok(NULL_REGION));
    assert_eq!(owner.get_app_clip_box(dc), Ok((NULL_REGION, EMPTY)));
    assert_eq!(owner.intersect_clip_rect(dc, rect(-100, -100, 100, 100)), Ok(NULL_REGION));
}

#[test]
fn first_empty_clip_returns_simple_but_queries_empty_and_invalid_dc_fails() {
    let mut owner = GdiManager::new(); let dc = owner.create_dc(2, 2).unwrap();
    assert_eq!(owner.intersect_clip_rect(dc, rect(1, 1, 1, 2)), Ok(SIMPLE_REGION));
    assert_eq!(owner.get_app_clip_box(dc), Ok((NULL_REGION, EMPTY)));
    assert_eq!(owner.intersect_clip_rect(0, EMPTY), Err(GdiError::NoSuchObject));
    assert_eq!(owner.get_app_clip_box(0), Err(GdiError::NoSuchObject));
}

#[test]
fn resize_recomputes_visibility_without_truncating_retained_application_clip() {
    let mut owner = GdiManager::new(); let dc = owner.create_dc(2, 2).unwrap();
    owner.intersect_clip_rect(dc, rect(3, 3, 8, 8)).unwrap();
    assert_eq!(owner.get_app_clip_box(dc), Ok((NULL_REGION, EMPTY)));
    owner.resize_dc(dc, 6, 6).unwrap();
    assert_eq!(owner.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(3, 3, 6, 6))));
}

fn assert_draw_is_clipped(operation: u32, paint: bool) {
    let mut owner = GdiManager::new();
        let dc = owner.create_dc(3, 3).unwrap();
        if paint { owner.set_paint_clip(dc, rect(1, 1, 2, 2)).unwrap(); }
        else { owner.intersect_clip_rect(dc, rect(1, 1, 2, 2)).unwrap(); }
        match operation {
            0 => owner.fill_rect(dc, rect(0, 0, 3, 3), 0xffffff).unwrap(),
            1 => owner.pat_blt(dc, 0, 0, 3, 3, 0xf00021).unwrap(),
            2 => owner.blit_pixels(dc, 0, 0, 3, 3, 3, &[0xffffff; 9]).unwrap(),
            _ => owner.blend_pixels(dc, 0, 0, 3, 3, &[0xffffffff; 9]).unwrap(),
        }
        assert_eq!(owner.pixels(dc).unwrap(), &[0, 0, 0, 0, 0xffffff, 0, 0, 0, 0], "operation {operation}");
}

#[test]
fn fill_obeys_clip() { assert_draw_is_clipped(0, false); }
#[test]
fn pattern_blt_obeys_clip() { assert_draw_is_clipped(1, false); }
#[test]
fn raster_upload_obeys_clip() { assert_draw_is_clipped(2, false); }
#[test]
fn glyph_alpha_blend_obeys_clip() { assert_draw_is_clipped(3, false); }

#[test]
fn fill_obeys_paint_clip() { assert_draw_is_clipped(0, true); }
#[test]
fn pattern_blt_obeys_paint_clip() { assert_draw_is_clipped(1, true); }
#[test]
fn raster_upload_obeys_paint_clip() { assert_draw_is_clipped(2, true); }
#[test]
fn glyph_alpha_blend_obeys_paint_clip() { assert_draw_is_clipped(3, true); }

#[test]
fn bitblt_obeys_paint_clip() {
    let mut owner = GdiManager::new(); let src = owner.create_dc(3, 1).unwrap(); let dst = owner.create_dc(3, 1).unwrap();
    owner.blit_pixels(src, 0, 0, 3, 1, 3, &[1, 2, 3]).unwrap();
    owner.set_paint_clip(src, EMPTY).unwrap();
    owner.set_paint_clip(dst, rect(1, 0, 2, 1)).unwrap();
    owner.bitblt(dst, 0, 0, src, 0, 0, 3, 1).unwrap();
    assert_eq!(owner.pixels(dst).unwrap(), &[0, 2, 0]);
}

#[test]
fn bitblt_honors_destination_clip_but_does_not_apply_source_dc_clip() {
    let mut owner = GdiManager::new(); let src = owner.create_dc(3, 1).unwrap(); let dst = owner.create_dc(3, 1).unwrap();
    owner.blit_pixels(src, 0, 0, 3, 1, 3, &[1, 2, 3]).unwrap();
    owner.intersect_clip_rect(src, EMPTY).unwrap();
    owner.intersect_clip_rect(dst, rect(1, 0, 2, 1)).unwrap();
    owner.bitblt(dst, 0, 0, src, 0, 0, 3, 1).unwrap();
    assert_eq!(owner.pixels(dst).unwrap(), &[0, 2, 0]);
}
