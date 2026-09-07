use super::*;
use crate::win32_gdi::{GdiManager, GM_ADVANCED, Xform, MWT_SET, AD_CLOCKWISE, AD_COUNTERCLOCKWISE};

/// A context whose pen is visible against the cleared surface: the default
/// device-context pen is black, which a zeroed surface already is.
fn context(width: i32, height: i32) -> (GdiManager, u32) {
    let mut gdi = GdiManager::new();
    let dc = gdi.create_dc(width, height).unwrap();
    let pen = gdi.create_pen(0, 1, 0x00ff_0000).unwrap();
    gdi.select_pen(dc, pen).unwrap();
    (gdi, dc)
}

fn painted(gdi: &GdiManager, dc: u32) -> usize {
    gdi.pixels(dc).unwrap().iter().filter(|pixel| **pixel != 0).count()
}

#[test]
fn an_ellipse_paints_inside_its_rectangle_and_nowhere_else() {
    let (mut gdi, dc) = context(20, 20);
    let brush = gdi.create_solid_brush(0x0000_ff00).unwrap();
    gdi.select_brush(dc, brush).unwrap();
    gdi.ellipse(dc, Rect { left: 4, top: 4, right: 16, bottom: 16 }).unwrap();
    let pixels = gdi.pixels(dc).unwrap().to_vec();
    assert!(painted(&gdi, dc) > 0);
    for y in 0..20i32 {
        for x in 0..20i32 {
            if pixels[(y * 20 + x) as usize] == 0 { continue; }
            assert!((4..16).contains(&x) && (4..16).contains(&y), "painted outside at ({x},{y})");
        }
    }
    // The corners of the bounding box stay clear: an ellipse is not a rectangle.
    assert_eq!(pixels[(4 * 20 + 4) as usize], 0);
    assert_eq!(pixels[(15 * 20 + 15) as usize], 0);
}

#[test]
fn an_empty_or_degenerate_rectangle_paints_nothing() {
    let (mut gdi, dc) = context(16, 16);
    gdi.ellipse(dc, Rect { left: 5, top: 5, right: 5, bottom: 12 }).unwrap();
    gdi.round_rect(dc, Rect { left: 3, top: 3, right: 9, bottom: 3 }, 4, 4).unwrap();
    assert_eq!(painted(&gdi, dc), 0);
}

#[test]
fn a_rounded_rectangle_with_a_tiny_corner_degenerates_to_a_plain_rectangle() {
    let (mut gdi, dc) = context(16, 16);
    gdi.round_rect(dc, Rect { left: 2, top: 2, right: 12, bottom: 12 }, 2, 2).unwrap();
    let rounded = gdi.pixels(dc).unwrap().to_vec();
    let (mut plain_gdi, plain_dc) = context(16, 16);
    plain_gdi.rectangle(plain_dc, Rect { left: 2, top: 2, right: 12, bottom: 12 }).unwrap();
    assert_eq!(rounded, plain_gdi.pixels(plain_dc).unwrap());
    assert!(rounded.iter().any(|pixel| *pixel != 0));
}

#[test]
fn a_rounded_rectangle_clears_its_corners_where_a_plain_one_does_not() {
    let (mut gdi, dc) = context(20, 20);
    gdi.round_rect(dc, Rect { left: 2, top: 2, right: 18, bottom: 18 }, 8, 8).unwrap();
    let pixels = gdi.pixels(dc).unwrap();
    assert_eq!(pixels[(2 * 20 + 2) as usize], 0, "the top-left corner is rounded away");
    assert!(pixels.iter().any(|pixel| *pixel != 0));
}

#[test]
fn an_arc_paints_an_open_run_while_a_pie_closes_through_the_centre() {
    let rect = Rect { left: 0, top: 0, right: 20, bottom: 20 };
    let (start, end) = (Point { x: 20, y: 10 }, Point { x: 10, y: 0 });
    let (mut arc_gdi, arc_dc) = context(20, 20);
    arc_gdi.arc_internal(arc_dc, ARC, rect, start, end).unwrap();
    let (mut pie_gdi, pie_dc) = context(20, 20);
    pie_gdi.arc_internal(pie_dc, PIE, rect, start, end).unwrap();
    assert!(painted(&arc_gdi, arc_dc) > 0);
    assert!(painted(&pie_gdi, pie_dc) > painted(&arc_gdi, arc_dc), "a pie adds two radii and an interior");
}

#[test]
fn an_unknown_arc_form_is_refused() {
    let (mut gdi, dc) = context(20, 20);
    assert_eq!(gdi.arc_internal(dc, 9, Rect { left: 0, top: 0, right: 8, bottom: 8 },
        Point { x: 1, y: 0 }, Point { x: 0, y: 1 }), Err(GdiError::InvalidDimensions));
}

#[test]
fn an_arc_to_moves_the_current_position_to_the_arc_end() {
    let (mut gdi, dc) = context(32, 32);
    gdi.set_text_position(dc, (0, 0)).unwrap();
    gdi.arc_internal(dc, ARC_TO, Rect { left: 0, top: 0, right: 20, bottom: 20 },
        Point { x: 20, y: 10 }, Point { x: 10, y: 20 }).unwrap();
    assert_ne!(gdi.text_state(dc).unwrap().attributes.current_position, (0, 0));
}

#[test]
fn an_angle_arc_refuses_a_negative_radius_and_ends_on_the_swept_angle() {
    let (mut gdi, dc) = context(64, 64);
    assert_eq!(gdi.angle_arc(dc, Point { x: 32, y: 32 }, -1, 0.0, 90.0), Err(GdiError::InvalidDimensions));
    gdi.angle_arc(dc, Point { x: 32, y: 32 }, 20, 0.0, 90.0).unwrap();
    // Ninety degrees counterclockwise from the positive x axis is straight up,
    // and screen y grows downwards.
    assert_eq!(gdi.text_state(dc).unwrap().attributes.current_position, (32, 12));
    assert_eq!(gdi.dc_attr(dc).unwrap().arc_direction, AD_COUNTERCLOCKWISE);
}

#[test]
fn an_angle_arc_restores_the_sweep_direction_it_borrowed() {
    let (mut gdi, dc) = context(64, 64);
    gdi.set_arc_direction(dc, AD_CLOCKWISE).unwrap();
    gdi.angle_arc(dc, Point { x: 32, y: 32 }, 10, 0.0, 180.0).unwrap();
    assert_eq!(gdi.dc_attr(dc).unwrap().arc_direction, AD_CLOCKWISE);
}

#[test]
fn poly_draw_rejects_a_type_array_it_cannot_walk() {
    let (mut gdi, dc) = context(16, 16);
    let points = [Point { x: 1, y: 1 }, Point { x: 2, y: 2 }, Point { x: 3, y: 3 }];
    assert_eq!(gdi.poly_draw(dc, &points, &[PT_LINETO, PT_LINETO]), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.poly_draw(dc, &points, &[PT_LINETO, PT_LINETO, 0x77]), Err(GdiError::InvalidDimensions));
    // A curve needs three points, and only its last may close the figure.
    assert_eq!(gdi.poly_draw(dc, &points, &[PT_BEZIERTO, PT_BEZIERTO, PT_LINETO]), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.poly_draw(dc, &points[..2], &[PT_BEZIERTO, PT_BEZIERTO]), Err(GdiError::InvalidDimensions));
}

#[test]
fn poly_draw_paints_its_run_and_leaves_the_position_on_the_last_point() {
    let (mut gdi, dc) = context(24, 24);
    gdi.set_text_position(dc, (2, 2)).unwrap();
    let points = [Point { x: 20, y: 2 }, Point { x: 20, y: 20 }];
    gdi.poly_draw(dc, &points, &[PT_LINETO, PT_LINETO | PT_CLOSEFIGURE]).unwrap();
    assert!(painted(&gdi, dc) > 0);
    assert_eq!(gdi.text_state(dc).unwrap().attributes.current_position, (20, 20));
}

#[test]
fn poly_poly_draw_checks_that_the_counts_account_for_every_point() {
    let (mut gdi, dc) = context(16, 16);
    let points = [Point { x: 1, y: 1 }, Point { x: 8, y: 1 }, Point { x: 8, y: 8 }];
    assert_eq!(gdi.poly_poly_draw(dc, &points, &[2], POLY_POLYGON), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.poly_poly_draw(dc, &points, &[3], 99), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.poly_poly_draw(dc, &points, &[3], POLY_POLYGON), Ok(()));
    assert!(painted(&gdi, dc) > 0);
}

#[test]
fn the_curve_forms_admit_only_the_point_counts_their_shape_allows() {
    let (mut gdi, dc) = context(32, 32);
    let four: [Point; 4] = [Point { x: 1, y: 1 }, Point { x: 8, y: 1 }, Point { x: 8, y: 8 }, Point { x: 16, y: 8 }];
    assert_eq!(gdi.poly_poly_draw(dc, &four, &[4], POLY_BEZIER), Ok(()));
    assert_eq!(gdi.poly_poly_draw(dc, &four[..3], &[3], POLY_BEZIER), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.poly_poly_draw(dc, &four[..3], &[3], POLY_BEZIER_TO), Ok(()));
    assert_eq!(gdi.poly_poly_draw(dc, &four, &[4], POLY_BEZIER_TO), Err(GdiError::InvalidDimensions));
    assert_eq!(gdi.poly_poly_draw(dc, &four, &[2, 2], POLY_BEZIER), Err(GdiError::InvalidDimensions));
}

#[test]
fn a_curve_form_leaves_the_position_on_its_last_control_point() {
    let (mut gdi, dc) = context(32, 32);
    let four = [Point { x: 1, y: 1 }, Point { x: 8, y: 1 }, Point { x: 8, y: 8 }, Point { x: 16, y: 8 }];
    gdi.poly_poly_draw(dc, &four, &[4], POLY_BEZIER).unwrap();
    assert_eq!(gdi.text_state(dc).unwrap().attributes.current_position, (16, 8));
}

#[test]
fn drawing_accumulates_bounds_only_while_tracking_is_enabled() {
    let (mut gdi, dc) = context(32, 32);
    gdi.ellipse(dc, Rect { left: 4, top: 4, right: 12, bottom: 12 }).unwrap();
    assert_eq!(gdi.get_bounds_rect(dc, true, 0).unwrap().0, 0x0001);
    gdi.set_bounds_rect(dc, None, 0x0004).unwrap();
    gdi.ellipse(dc, Rect { left: 4, top: 4, right: 12, bottom: 12 }).unwrap();
    let (state, rect) = gdi.get_bounds_rect(dc, true, 0).unwrap();
    assert_eq!(state, 0x0003);
    let rect = rect.unwrap();
    assert!(rect.left >= 4 && rect.right <= 12, "{rect:?}");
}

#[test]
fn an_advanced_mode_rectangle_follows_the_world_transform_as_a_polygon() {
    let (mut gdi, dc) = context(32, 32);
    gdi.dc_attr_mut_for_test(dc).graphics_mode = GM_ADVANCED;
    // A quarter turn maps the upright rectangle onto a different quadrant.
    gdi.modify_world_transform(dc, Some(Xform { m11: 0.0, m12: 1.0, m21: -1.0, m22: 0.0, dx: 20.0, dy: 2.0 }), MWT_SET).unwrap();
    let brush = gdi.create_solid_brush(0x0000_00ff).unwrap();
    gdi.select_brush(dc, brush).unwrap();
    gdi.rectangle(dc, Rect { left: 2, top: 2, right: 10, bottom: 6 }).unwrap();
    let pixels = gdi.pixels(dc).unwrap();
    assert!(pixels.iter().any(|pixel| *pixel != 0));
    // The rotated rectangle is taller than it is wide, unlike its logical form.
    let painted: alloc::vec::Vec<(i32, i32)> = (0..32i32).flat_map(|y| (0..32i32).map(move |x| (x, y)))
        .filter(|(x, y)| pixels[(y * 32 + x) as usize] != 0).collect();
    let width = painted.iter().map(|(x, _)| *x).max().unwrap() - painted.iter().map(|(x, _)| *x).min().unwrap();
    let height = painted.iter().map(|(_, y)| *y).max().unwrap() - painted.iter().map(|(_, y)| *y).min().unwrap();
    assert!(height > width, "expected a rotated rectangle, got {width} by {height}");
}
