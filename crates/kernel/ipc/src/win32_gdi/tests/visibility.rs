use super::*;
fn rect(left: i32, top: i32, right: i32, bottom: i32) -> Rect { Rect { left, top, right, bottom } }
fn visible(clip: Rect, query: Rect) -> bool {
    rect_visible_in_clip(PaintRegion::from_rect(WindowRect { left: clip.left, top: clip.top,
        right: clip.right, bottom: clip.bottom }).unwrap(), query)
}

#[test]
fn overlap_requires_area_not_just_touching_and_orders_query_endpoints() {
    let clip = rect(2, 3, 8, 9);
    for query in [rect(2,3,8,9), rect(8,9,2,3), rect(-10,-10,3,4), rect(7,8,20,20)] {
        assert!(visible(clip, query));
    }
    for query in [rect(1,3,2,9), rect(8,3,10,9), rect(2,1,8,3), rect(2,9,8,10),
        rect(4,4,4,8), rect(4,4,8,4)] { assert!(!visible(clip, query)); }
    assert!(!visible(rect(0,0,0,0), clip));
}

#[test]
fn signed_extremes_need_no_subtraction_or_overflow() {
    assert!(visible(rect(0,0,4,4), rect(i32::MAX,i32::MAX,i32::MIN,i32::MIN)));
    assert!(!visible(rect(0,0,4,4), rect(i32::MIN,i32::MIN,-1,-1)));
}
