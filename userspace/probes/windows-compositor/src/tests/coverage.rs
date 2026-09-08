//! What a surface has actually been given, as an area rather than a bound.
use super::*;

fn r(left: i32, top: i32, right: i32, bottom: i32) -> Rect { Rect { left, top, right, bottom } }

#[test]
fn nothing_is_held_before_a_frame_arrives() {
    let c = Coverage::default();
    assert!(c.is_empty());
    assert!(!c.holds(r(0, 0, 1, 1)));
}

#[test]
fn a_covered_rectangle_is_held_and_so_is_any_part_of_it() {
    let mut c = Coverage::default();
    c.cover(r(0, 0, 10, 10));
    assert!(c.holds(r(0, 0, 10, 10)));
    assert!(c.holds(r(3, 3, 4, 4)));
    assert!(!c.holds(r(0, 0, 11, 10)), "a pixel past the covered area is not held");
}

#[test]
fn the_space_between_two_disjoint_areas_is_not_held() {
    // The defect this replaces: coverage was one bounding box, so these two
    // corners made the whole rectangle read as held.
    let mut c = Coverage::default();
    c.cover(r(0, 0, 2, 2));
    c.cover(r(8, 8, 10, 10));
    assert!(c.holds(r(0, 0, 2, 2)));
    assert!(c.holds(r(8, 8, 10, 10)));
    assert!(!c.holds(r(4, 4, 6, 6)));
    assert!(!c.holds(r(0, 0, 10, 10)));
}

#[test]
fn areas_that_together_cover_a_rectangle_hold_it() {
    let mut c = Coverage::default();
    c.cover(r(0, 0, 10, 5));
    c.cover(r(0, 5, 10, 10));
    assert!(c.holds(r(0, 0, 10, 10)), "two halves cover the whole");
    let mut quarters = Coverage::default();
    for (l, t) in [(0, 0), (5, 0), (0, 5), (5, 5)] { quarters.cover(r(l, t, l + 5, t + 5)); }
    assert!(quarters.holds(r(0, 0, 10, 10)), "four quarters cover the whole");
    assert!(quarters.holds(r(3, 3, 7, 7)), "and a rectangle spanning all four");
}

#[test]
fn a_hole_left_by_surrounding_areas_is_not_held() {
    // Four bars around a gap: every edge is covered and the middle is not.
    let mut c = Coverage::default();
    c.cover(r(0, 0, 10, 3));
    c.cover(r(0, 7, 10, 10));
    c.cover(r(0, 3, 3, 7));
    c.cover(r(7, 3, 10, 7));
    assert!(c.holds(r(0, 0, 10, 3)));
    assert!(!c.holds(r(4, 4, 6, 6)), "the hole in the middle");
    assert!(!c.holds(r(0, 0, 10, 10)));
}

#[test]
fn repainting_the_same_area_does_not_grow_the_set() {
    let mut c = Coverage::default();
    for _ in 0..MAX_AREAS * 2 { c.cover(r(0, 0, 10, 10)); }
    assert!(c.holds(r(0, 0, 10, 10)));
    let mut inner = Coverage::default();
    inner.cover(r(0, 0, 10, 10));
    for _ in 0..MAX_AREAS * 2 { inner.cover(r(2, 2, 3, 3)); }
    assert!(inner.holds(r(0, 0, 10, 10)), "an area already covered is dropped, not retained");
}

#[test]
fn the_bound_drops_the_oldest_area_rather_than_widening_the_claim() {
    // Past the bound the set must lose coverage, never gain it: a repaint
    // costs one frame, an over-claim corrupts the window permanently.
    let mut c = Coverage::default();
    for i in 0..MAX_AREAS as i32 + 4 { c.cover(r(i * 2, 0, i * 2 + 1, 1)); }
    assert!(!c.holds(r(0, 0, 1, 1)), "the oldest area is gone");
    let last = MAX_AREAS as i32 + 3;
    assert!(c.holds(r(last * 2, 0, last * 2 + 1, 1)), "the newest area is kept");
    assert!(!c.holds(r(1, 0, 2, 1)), "the gaps were never claimed");
}

#[test]
fn subtracting_a_disjoint_rectangle_leaves_the_whole() {
    let mut out = Vec::new();
    subtract(r(0, 0, 4, 4), r(10, 10, 12, 12), &mut out);
    assert_eq!(out, vec![r(0, 0, 4, 4)]);
    out.clear();
    subtract(r(0, 0, 4, 4), r(0, 0, 4, 4), &mut out);
    assert!(out.is_empty(), "a rectangle subtracted from itself leaves nothing");
}
