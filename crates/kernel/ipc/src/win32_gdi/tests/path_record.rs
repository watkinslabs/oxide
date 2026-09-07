use super::*;

fn p(x: i32, y: i32) -> Point { Point { x, y } }

#[test]
fn a_line_from_the_open_position_records_an_implicit_move_first() {
    let mut path = GdiPath::open(p(1, 2));
    path.line_to(&[p(5, 6)], PT_LINETO).unwrap();
    assert_eq!(path.points(), [p(1, 2), p(5, 6)]);
    assert_eq!(path.flags(), [PT_MOVETO, PT_LINETO]);
    assert_eq!(path.position(), p(5, 6));
}

#[test]
fn a_continuing_line_does_not_repeat_the_move() {
    let mut path = GdiPath::open(p(0, 0));
    path.line_to(&[p(1, 1)], PT_LINETO).unwrap();
    path.line_to(&[p(2, 2)], PT_LINETO).unwrap();
    assert_eq!(path.flags(), [PT_MOVETO, PT_LINETO, PT_LINETO]);
}

#[test]
fn a_move_starts_a_new_stroke_at_the_next_line() {
    let mut path = GdiPath::open(p(0, 0));
    path.line_to(&[p(1, 1)], PT_LINETO).unwrap();
    path.move_to(p(9, 9));
    path.line_to(&[p(8, 8)], PT_LINETO).unwrap();
    assert_eq!(path.points(), [p(0, 0), p(1, 1), p(9, 9), p(8, 8)]);
    assert_eq!(path.flags(), [PT_MOVETO, PT_LINETO, PT_MOVETO, PT_LINETO]);
}

#[test]
fn a_closed_figure_forces_the_next_line_to_open_a_stroke() {
    let mut path = GdiPath::open(p(0, 0));
    path.line_to(&[p(1, 1)], PT_LINETO).unwrap();
    path.close_figure();
    assert_eq!(path.flags(), [PT_MOVETO, PT_LINETO | PT_CLOSEFIGURE]);
    path.line_to(&[p(2, 2)], PT_LINETO).unwrap();
    assert_eq!(path.flags(), [PT_MOVETO, PT_LINETO | PT_CLOSEFIGURE, PT_MOVETO, PT_LINETO]);
    // The reopened stroke starts at the unchanged current position.
    assert_eq!(path.points()[2], p(1, 1));
}

#[test]
fn closing_an_empty_path_records_nothing() {
    let mut path = GdiPath::open(p(0, 0));
    path.close_figure();
    assert!(path.is_empty());
}

#[test]
fn a_rectangle_is_one_closed_four_point_figure_wound_by_arc_direction() {
    let mut counter = GdiPath::open(p(0, 0));
    counter.rectangle(1, 2, 5, 6, false).unwrap();
    assert_eq!(counter.points(), [p(5, 2), p(1, 2), p(1, 6), p(5, 6)]);
    assert_eq!(counter.flags(), [PT_MOVETO, PT_LINETO, PT_LINETO, PT_LINETO | PT_CLOSEFIGURE]);
    let mut clockwise = GdiPath::open(p(0, 0));
    clockwise.rectangle(1, 2, 5, 6, true).unwrap();
    assert_eq!(clockwise.points(), [p(5, 6), p(1, 6), p(1, 2), p(5, 2)]);
    assert_eq!(clockwise.flags()[0], PT_MOVETO);
}

#[test]
fn a_rectangle_does_not_move_the_current_position() {
    let mut path = GdiPath::open(p(7, 7));
    path.rectangle(0, 0, 2, 2, false).unwrap();
    assert_eq!(path.position(), p(7, 7));
}
