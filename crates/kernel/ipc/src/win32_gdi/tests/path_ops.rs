use super::*;
use crate::win32_gdi::{PT_BEZIERTO, PT_CLOSEFIGURE, PT_LINETO, PT_MOVETO};
use crate::win32_gdi::region::scan::Point;
use crate::win32_gdi::region::query;
use crate::win32_gdi::{GdiManager, Rect};

fn dc() -> (GdiManager, u32) { let mut g = GdiManager::new(); let dc = g.create_dc(40, 40).unwrap(); (g, dc) }

#[test]
fn a_path_is_readable_only_after_it_is_closed() {
    let (mut g, dc) = dc();
    assert_eq!(g.path_points(dc).err(), Some(GdiError::InvalidDimensions));
    g.begin_path(dc).unwrap();
    g.path_line_to(dc, 5, 5).unwrap();
    assert_eq!(g.path_points(dc).err(), Some(GdiError::InvalidDimensions));
    g.end_path(dc).unwrap();
    let (points, flags) = g.path_points(dc).unwrap();
    assert_eq!(points.len(), 2);
    assert_eq!(flags, [PT_MOVETO, PT_LINETO]);
}

#[test]
fn ending_without_an_open_recording_fails() {
    let (mut g, dc) = dc();
    assert_eq!(g.end_path(dc), Err(GdiError::InvalidDimensions));
    assert_eq!(g.close_figure(dc), Err(GdiError::InvalidDimensions));
    assert_eq!(g.begin_path(99), Err(GdiError::NoSuchObject));
}

#[test]
fn aborting_discards_both_the_open_recording_and_a_closed_path() {
    let (mut g, dc) = dc();
    g.begin_path(dc).unwrap(); g.path_line_to(dc, 1, 1).unwrap(); g.end_path(dc).unwrap();
    assert!(g.path_points(dc).is_ok());
    g.abort_path(dc).unwrap();
    assert_eq!(g.path_points(dc).err(), Some(GdiError::InvalidDimensions));
    // Aborting with nothing recorded still succeeds.
    assert_eq!(g.abort_path(dc), Ok(()));
}

#[test]
fn reopening_a_recording_discards_the_previous_closed_path() {
    let (mut g, dc) = dc();
    g.begin_path(dc).unwrap(); g.path_line_to(dc, 1, 1).unwrap(); g.end_path(dc).unwrap();
    g.begin_path(dc).unwrap();
    assert_eq!(g.path_points(dc).err(), Some(GdiError::InvalidDimensions));
    assert_eq!(g.path_recording(dc), Ok(true));
    g.end_path(dc).unwrap();
    assert_eq!(g.path_recording(dc), Ok(false));
    assert_eq!(g.path_points(dc).map(|(points, _)| points.len()), Ok(0));
}

#[test]
fn drawing_calls_record_only_while_a_path_is_open() {
    let (mut g, dc) = dc();
    assert_eq!(g.path_line_to(dc, 1, 1), Ok(false));
    assert_eq!(g.path_move_to(dc, 1, 1), Ok(false));
    assert_eq!(g.path_rectangle(dc, 0, 0, 2, 2), Ok(false));
    g.begin_path(dc).unwrap();
    assert_eq!(g.path_rectangle(dc, 0, 0, 2, 2), Ok(true));
    g.end_path(dc).unwrap();
    assert_eq!(g.path_points(dc).map(|(points, _)| points.len()), Ok(4));
}

#[test]
fn converting_to_a_region_consumes_the_path() {
    let (mut g, dc) = dc();
    g.begin_path(dc).unwrap();
    g.path_rectangle(dc, 1, 1, 9, 9).unwrap();
    g.end_path(dc).unwrap();
    let region = g.path_to_region(dc).unwrap();
    assert!(query::pt_in_region(&region, 5, 5));
    assert!(!query::pt_in_region(&region, 9, 9));
    assert_eq!(g.path_to_region(dc).err(), Some(GdiError::InvalidDimensions));
}

#[test]
fn the_fill_mode_selects_the_coverage_a_conversion_produces() {
    for (mode, filled) in [(crate::win32_gdi::path::ALTERNATE, false), (crate::win32_gdi::path::WINDING, true)] {
        let (mut g, dc) = dc();
        assert_eq!(g.set_poly_fill_mode(dc, mode), Ok(crate::win32_gdi::path::ALTERNATE));
        assert_eq!(g.poly_fill_mode(dc), Ok(mode));
        g.begin_path(dc).unwrap();
        g.path_rectangle(dc, 0, 0, 10, 10).unwrap();
        g.path_rectangle(dc, 3, 3, 7, 7).unwrap();
        g.end_path(dc).unwrap();
        assert_eq!(query::pt_in_region(&g.path_to_region(dc).unwrap(), 5, 5), filled);
    }
}

#[test]
fn an_unknown_fill_mode_is_refused_and_leaves_the_previous_mode() {
    let (mut g, dc) = dc();
    assert_eq!(g.set_poly_fill_mode(dc, 0), Err(GdiError::InvalidDimensions));
    assert_eq!(g.set_poly_fill_mode(dc, 3), Err(GdiError::InvalidDimensions));
    assert_eq!(g.poly_fill_mode(dc), Ok(crate::win32_gdi::path::ALTERNATE));
}

#[test]
fn flattening_needs_a_closed_path_and_leaves_no_bezier_behind() {
    let (mut g, dc) = dc();
    assert_eq!(g.flatten_path(dc), Err(GdiError::InvalidDimensions));
    g.begin_path(dc).unwrap();
    g.path_rectangle(dc, 0, 0, 4, 4).unwrap();
    g.end_path(dc).unwrap();
    assert_eq!(g.flatten_path(dc), Ok(()));
    assert!(g.path_points(dc).unwrap().1.iter().all(|flag| flag & !PT_CLOSEFIGURE != PT_BEZIERTO));
}

#[test]
fn discarding_needs_a_closed_path_exactly_as_a_conversion_does() {
    let (mut g, dc) = dc();
    assert_eq!(g.discard_path(dc), Err(GdiError::InvalidDimensions));
    g.begin_path(dc).unwrap();
    assert_eq!(g.discard_path(dc), Err(GdiError::InvalidDimensions));
    g.end_path(dc).unwrap();
    assert_eq!(g.discard_path(dc), Ok(()));
    assert_eq!(g.discard_path(dc), Err(GdiError::InvalidDimensions));
}

#[test]
fn a_recording_starts_at_the_device_context_current_position() {
    let (mut g, dc) = dc();
    g.set_text_position(dc, (6, 7)).unwrap();
    g.begin_path(dc).unwrap();
    g.path_line_to(dc, 8, 9).unwrap();
    g.end_path(dc).unwrap();
    assert_eq!(g.path_points(dc).unwrap().0[0], Point { x: 6, y: 7 });
    let _ = Rect { left: 0, top: 0, right: 0, bottom: 0 };
}
