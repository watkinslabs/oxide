use super::*;
use crate::win32_gdi::{GdiManager, Rect, NULL_REGION, SIMPLE_REGION, COMPLEX_REGION};
use crate::win32_gdi::region::{RGN_AND, RGN_COPY, RGN_DIFF, RGN_OR, RGN_XOR};
use crate::win32_window::{PaintRegion, WindowRect};

fn dc() -> (GdiManager, u32) { let mut g = GdiManager::new(); let dc = g.create_dc(20, 20).unwrap(); (g, dc) }
fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect { Rect { left, top, right, bottom } }
fn region(left: i32, top: i32, right: i32, bottom: i32) -> PaintRegion {
    PaintRegion::from_rect(WindowRect { left, top, right, bottom }).unwrap()
}

#[test]
fn the_first_intersection_installs_the_rectangle_and_reports_one_rectangle() {
    let (mut g, dc) = dc();
    assert_eq!(g.intersect_clip_rect(dc, rect(2, 2, 6, 6)), Ok(SIMPLE_REGION));
    assert_eq!(g.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(2, 2, 6, 6))));
    assert_eq!(g.intersect_clip_rect(dc, rect(4, 4, 30, 30)), Ok(SIMPLE_REGION));
    assert_eq!(g.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(4, 4, 6, 6))));
}

#[test]
fn a_degenerate_first_intersection_still_reports_one_rectangle_but_clips_everything_away() {
    let (mut g, dc) = dc();
    assert_eq!(g.intersect_clip_rect(dc, rect(5, 5, 5, 9)), Ok(SIMPLE_REGION));
    assert_eq!(g.get_app_clip_box(dc), Ok((NULL_REGION, rect(0, 0, 0, 0))));
}

#[test]
fn excluding_without_a_clip_first_builds_one_from_the_device_surface() {
    let (mut g, dc) = dc();
    assert_eq!(g.exclude_clip_rect(dc, rect(0, 0, 20, 10)), Ok(SIMPLE_REGION));
    assert_eq!(g.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(0, 10, 20, 20))));
    assert_eq!(g.exclude_clip_rect(dc, rect(5, 12, 9, 16)), Ok(COMPLEX_REGION));
    assert!(!g.pt_visible(dc, 6, 13).unwrap());
    assert!(g.pt_visible(dc, 6, 17).unwrap());
    assert!(!g.pt_visible(dc, 6, 3).unwrap());
}

#[test]
fn selecting_no_region_in_copy_mode_clears_application_clipping() {
    let (mut g, dc) = dc();
    g.intersect_clip_rect(dc, rect(1, 1, 2, 2)).unwrap();
    assert_eq!(g.ext_select_clip_rgn(dc, None, RGN_COPY), Ok(SIMPLE_REGION));
    assert_eq!(g.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(0, 0, 20, 20))));
    assert_eq!(g.ext_select_clip_rgn(dc, None, RGN_DIFF), Err(GdiError::InvalidDimensions));
}

#[test]
fn every_combine_mode_reaches_the_application_clip() {
    for (mode, visible, hidden) in [(RGN_AND, (5, 5), (1, 1)), (RGN_OR, (1, 1), (19, 19)),
        (RGN_DIFF, (1, 1), (5, 5)), (RGN_XOR, (1, 1), (5, 5))] {
        let (mut g, dc) = dc();
        g.intersect_clip_rect(dc, rect(0, 0, 10, 10)).unwrap();
        g.ext_select_clip_rgn(dc, Some(&region(4, 4, 8, 8)), mode).unwrap();
        assert!(g.pt_visible(dc, visible.0, visible.1).unwrap(), "mode {mode}");
        assert!(!g.pt_visible(dc, hidden.0, hidden.1).unwrap(), "mode {mode}");
    }
}

#[test]
fn copy_mode_replaces_the_clip_with_the_selected_region() {
    let (mut g, dc) = dc();
    g.intersect_clip_rect(dc, rect(0, 0, 2, 2)).unwrap();
    assert_eq!(g.ext_select_clip_rgn(dc, Some(&region(6, 6, 9, 9)), RGN_COPY), Ok(SIMPLE_REGION));
    assert_eq!(g.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(6, 6, 9, 9))));
}

#[test]
fn offsetting_reports_an_empty_region_when_no_clip_exists_and_moves_one_that_does() {
    let (mut g, dc) = dc();
    assert_eq!(g.offset_clip_rgn(dc, 3, 3), Ok(NULL_REGION));
    assert_eq!(g.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(0, 0, 20, 20))));
    g.intersect_clip_rect(dc, rect(0, 0, 4, 4)).unwrap();
    assert_eq!(g.offset_clip_rgn(dc, 3, 5), Ok(SIMPLE_REGION));
    assert_eq!(g.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(3, 5, 7, 9))));
}

#[test]
fn the_meta_region_absorbs_the_application_clip_without_changing_the_effective_clip() {
    let (mut g, dc) = dc();
    g.intersect_clip_rect(dc, rect(2, 2, 8, 8)).unwrap();
    let before = g.get_app_clip_box(dc);
    assert_eq!(g.set_meta_rgn(dc), Ok(SIMPLE_REGION));
    assert_eq!(g.get_app_clip_box(dc), before);
    assert_eq!(g.get_random_rgn(dc, crate::win32_gdi::clip::RGN_CODE_CLIP).unwrap(), None);
    assert!(g.get_random_rgn(dc, crate::win32_gdi::clip::RGN_CODE_META).unwrap().is_some());
    // A later clip intersects the meta region on the next promotion.
    g.intersect_clip_rect(dc, rect(0, 0, 4, 4)).unwrap();
    assert_eq!(g.set_meta_rgn(dc), Ok(SIMPLE_REGION));
    assert_eq!(g.get_app_clip_box(dc), Ok((SIMPLE_REGION, rect(2, 2, 4, 4))));
}

#[test]
fn promoting_with_no_application_clip_reports_the_absent_meta_region() {
    let (mut g, dc) = dc();
    assert_eq!(g.set_meta_rgn(dc), Ok(crate::win32_gdi::CLIP_ERROR));
}

#[test]
fn each_random_region_code_names_a_different_region() {
    let (mut g, dc) = dc();
    assert_eq!(g.get_random_rgn(dc, crate::win32_gdi::clip::RGN_CODE_CLIP).unwrap(), None);
    assert_eq!(g.get_random_rgn(dc, crate::win32_gdi::clip::RGN_CODE_RAO).unwrap(), None);
    let system = g.get_random_rgn(dc, crate::win32_gdi::clip::RGN_CODE_SYS).unwrap().unwrap();
    assert_eq!(system.rects(), [WindowRect { left: 0, top: 0, right: 20, bottom: 20 }]);
    g.intersect_clip_rect(dc, rect(2, 2, 8, 8)).unwrap();
    g.set_meta_rgn(dc).unwrap();
    g.intersect_clip_rect(dc, rect(0, 0, 4, 4)).unwrap();
    let clip = g.get_random_rgn(dc, crate::win32_gdi::clip::RGN_CODE_CLIP).unwrap().unwrap();
    assert_eq!(clip.rects(), [WindowRect { left: 0, top: 0, right: 4, bottom: 4 }]);
    let rao = g.get_random_rgn(dc, crate::win32_gdi::clip::RGN_CODE_RAO).unwrap().unwrap();
    assert_eq!(rao.rects(), [WindowRect { left: 2, top: 2, right: 4, bottom: 4 }]);
    assert_eq!(g.get_random_rgn(dc, 9), Err(GdiError::InvalidDimensions));
    assert_eq!(g.get_random_rgn(99, crate::win32_gdi::clip::RGN_CODE_CLIP), Err(GdiError::NoSuchObject));
}

#[test]
fn visibility_of_a_point_needs_the_surface_and_every_clip_region() {
    let (mut g, dc) = dc();
    assert!(g.pt_visible(dc, 19, 19).unwrap());
    assert!(!g.pt_visible(dc, 20, 19).unwrap());
    assert!(!g.pt_visible(dc, -1, 0).unwrap());
    g.intersect_clip_rect(dc, rect(4, 4, 8, 8)).unwrap();
    assert!(g.pt_visible(dc, 4, 4).unwrap());
    assert!(!g.pt_visible(dc, 8, 4).unwrap());
    g.set_meta_rgn(dc).unwrap();
    assert!(g.pt_visible(dc, 4, 4).unwrap());
    g.set_paint_clip(dc, rect(0, 0, 5, 5)).unwrap();
    assert!(g.pt_visible(dc, 4, 4).unwrap());
    assert!(!g.pt_visible(dc, 6, 6).unwrap());
}

#[test]
fn rectangle_visibility_tests_overlap_with_the_effective_clip() {
    let (mut g, dc) = dc();
    g.intersect_clip_rect(dc, rect(4, 4, 8, 8)).unwrap();
    assert!(g.rect_visible(dc, rect(6, 6, 30, 30)).unwrap());
    assert!(!g.rect_visible(dc, rect(8, 8, 30, 30)).unwrap());
    assert_eq!(g.rect_visible(99, rect(0, 0, 1, 1)), Err(GdiError::NoSuchObject));
}
