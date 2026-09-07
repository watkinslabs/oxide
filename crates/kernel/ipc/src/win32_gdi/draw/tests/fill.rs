use super::*;
use alloc::vec::Vec;

fn covered(points: &[Point], clip: Rect, mode: u32) -> Vec<(i32, i32)> {
    let mut out = Vec::new();
    fill_polygon(points, clip, mode, |x, y| out.push((x, y))).unwrap();
    out.sort_unstable();
    out
}

const CLIP: Rect = Rect { left: 0, top: 0, right: 8, bottom: 8 };

#[test]
fn a_rectangular_polygon_fills_exactly_its_interior() {
    let square = [Point { x: 1, y: 1 }, Point { x: 4, y: 1 }, Point { x: 4, y: 4 }, Point { x: 1, y: 4 }];
    let mut expected: Vec<(i32, i32)> = Vec::new();
    for y in 1..4 { for x in 1..4 { expected.push((x, y)); } }
    expected.sort_unstable();
    assert_eq!(covered(&square, CLIP, WINDING), expected);
    assert_eq!(covered(&square, CLIP, ALTERNATE), expected);
}

#[test]
fn coverage_is_clipped_and_never_leaves_the_clip_rectangle() {
    let square = [Point { x: -5, y: -5 }, Point { x: 50, y: -5 }, Point { x: 50, y: 50 }, Point { x: -5, y: 50 }];
    let pixels = covered(&square, CLIP, WINDING);
    assert_eq!(pixels.len(), 64);
    assert!(pixels.iter().all(|(x, y)| (0..8).contains(x) && (0..8).contains(y)));
}

#[test]
fn a_degenerate_run_or_an_empty_clip_covers_nothing() {
    assert!(covered(&[Point { x: 0, y: 0 }, Point { x: 4, y: 4 }], CLIP, WINDING).is_empty());
    let square = [Point { x: 0, y: 0 }, Point { x: 4, y: 0 }, Point { x: 4, y: 4 }, Point { x: 0, y: 4 }];
    assert!(covered(&square, Rect { left: 0, top: 0, right: 0, bottom: 8 }, WINDING).is_empty());
}

#[test]
fn the_two_fill_modes_differ_on_a_self_overlapping_run() {
    // Two nested squares wound the same way: winding fills the hole, alternate leaves it.
    let outer = [Point { x: 0, y: 0 }, Point { x: 8, y: 0 }, Point { x: 8, y: 8 }, Point { x: 0, y: 8 }];
    let inner = [Point { x: 2, y: 2 }, Point { x: 6, y: 2 }, Point { x: 6, y: 6 }, Point { x: 2, y: 6 }];
    let mut run: Vec<Point> = Vec::new();
    run.extend_from_slice(&outer);
    run.push(outer[0]);
    run.extend_from_slice(&inner);
    run.push(inner[0]);
    assert_eq!(covered(&run, CLIP, WINDING).len(), 64);
    assert_eq!(covered(&run, CLIP, ALTERNATE).len(), 64 - 16);
}
