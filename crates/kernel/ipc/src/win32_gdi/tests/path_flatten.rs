use super::*;
use crate::win32_gdi::path::record::{GdiPath, PT_BEZIERTO, PT_CLOSEFIGURE, PT_LINETO, PT_MOVETO};
use crate::win32_gdi::region::query;

fn p(x: i32, y: i32) -> Point { Point { x, y } }

fn curved() -> GdiPath {
    let mut path = GdiPath::open(p(0, 0));
    path.push_raw(p(0, 0), PT_MOVETO).unwrap();
    for point in [p(0, 40), p(40, 40), p(40, 0)] { path.push_raw(point, PT_BEZIERTO).unwrap(); }
    path
}

#[test]
fn flattening_replaces_every_bezier_run_with_line_segments() {
    let flat = flatten(&curved()).unwrap();
    assert!(flat.flags().iter().all(|flag| flag & !PT_CLOSEFIGURE != PT_BEZIERTO));
    assert_eq!(flat.flags()[0], PT_MOVETO);
    assert_eq!(flat.points()[0], p(0, 0));
    assert_eq!(flat.points().last(), Some(&p(40, 0)));
    assert!(flat.len() > curved().len());
}

#[test]
fn a_closed_bezier_run_keeps_its_close_flag_on_the_flattened_tail() {
    let mut path = curved();
    path.close_figure();
    let flat = flatten(&path).unwrap();
    assert_eq!(flat.flags().last().copied(), Some(PT_LINETO | PT_CLOSEFIGURE));
}

#[test]
fn flattening_a_line_only_path_is_an_exact_copy() {
    let mut path = GdiPath::open(p(0, 0));
    path.line_to(&[p(4, 4)], PT_LINETO).unwrap();
    path.close_figure();
    let flat = flatten(&path).unwrap();
    assert_eq!((flat.points(), flat.flags()), (path.points(), path.flags()));
}

#[test]
fn a_bezier_run_without_its_three_points_is_refused() {
    let mut path = GdiPath::open(p(0, 0));
    path.push_raw(p(0, 0), PT_MOVETO).unwrap();
    path.push_raw(p(1, 1), PT_BEZIERTO).unwrap();
    assert_eq!(flatten(&path), Err(GdiError::InvalidDimensions));
}

#[test]
fn each_move_starts_a_new_figure_for_region_conversion() {
    let mut path = GdiPath::open(p(0, 0));
    path.line_to(&[p(0, 0), p(10, 0), p(10, 10), p(0, 10)], PT_LINETO).unwrap();
    path.close_figure();
    path.move_to(p(3, 3));
    path.line_to(&[p(3, 3), p(7, 3), p(7, 7), p(3, 7)], PT_LINETO).unwrap();
    path.close_figure();
    let alternate = to_region(&path, crate::win32_gdi::path::ALTERNATE).unwrap();
    let winding = to_region(&path, crate::win32_gdi::path::WINDING).unwrap();
    assert!(!query::pt_in_region(&alternate, 5, 5));
    assert!(query::pt_in_region(&winding, 5, 5));
    assert!(query::pt_in_region(&alternate, 1, 5));
}

#[test]
fn an_empty_path_has_no_region() {
    assert_eq!(to_region(&GdiPath::open(p(0, 0)), crate::win32_gdi::path::ALTERNATE), Err(GdiError::NoSuchObject));
}
