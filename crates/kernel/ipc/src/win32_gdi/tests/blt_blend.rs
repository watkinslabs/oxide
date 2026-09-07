//! Alpha compositing and gradient interpolation.
use super::*;

#[test]
fn the_blend_record_unpacks_from_its_double_word_low_byte_first() {
    let blend = BlendFunction::from_dword(0x0100_8000);
    assert_eq!(blend.op, AC_SRC_OVER);
    assert_eq!(blend.flags, 0x80);
    assert_eq!(blend.source_constant_alpha, 0x00);
    assert_eq!(blend.alpha_format, AC_SRC_ALPHA);
}

#[test]
fn constant_alpha_weights_a_source_without_its_own_alpha() {
    let opaque = BlendFunction { op: AC_SRC_OVER, flags: 0, source_constant_alpha: 255, alpha_format: 0 };
    assert_eq!(opaque.apply(0x0012_3456, 0x00ff_ffff), 0x0012_3456);
    let invisible = BlendFunction { op: AC_SRC_OVER, flags: 0, source_constant_alpha: 0, alpha_format: 0 };
    assert_eq!(invisible.apply(0x0012_3456, 0x00ab_cdef), 0x00ab_cdef);
    let half = BlendFunction { op: AC_SRC_OVER, flags: 0, source_constant_alpha: 128, alpha_format: 0 };
    // Each channel is source*128/255 + destination*(255-128)/255.
    assert_eq!(half.apply(0x0000_0000, 0x00ff_ffff), 0x007f_7f7f);
    assert_eq!(half.apply(0x00ff_ffff, 0x0000_0000), 0x0080_8080);
}

#[test]
fn a_premultiplied_source_uses_its_own_alpha_scaled_by_the_constant_one() {
    let blend = BlendFunction { op: AC_SRC_OVER, flags: 0, source_constant_alpha: 255, alpha_format: AC_SRC_ALPHA };
    // A fully transparent premultiplied pixel contributes nothing.
    assert_eq!(blend.apply(0x0000_0000, 0x0012_3456), 0x0012_3456);
    // A fully opaque one replaces the destination.
    assert_eq!(blend.apply(0xff65_4321, 0x0012_3456), 0x0065_4321);
}

fn vertex(x: i32, y: i32, red: u16, green: u16, blue: u16) -> TriVertex {
    TriVertex { x, y, red, green, blue, alpha: 0 }
}

#[test]
fn a_horizontal_rectangle_interpolates_across_its_width() {
    let vertices = [vertex(0, 0, 0, 0, 0), vertex(4, 2, 0xff00, 0, 0)];
    let shapes = gradient_shapes(&vertices, &[0, 1], GRADIENT_FILL_RECT_H).unwrap();
    assert_eq!(shapes.len(), 1);
    assert_eq!(shapes[0].bounds(), Rect { left: 0, top: 0, right: 4, bottom: 2 });
    assert_eq!(shapes[0].color_at(0, 0), Some(0x0000_0000));
    assert_eq!(shapes[0].color_at(2, 1), Some(0x007f_0000));
    assert_eq!(shapes[0].color_at(3, 1), Some(0x00bf_0000));
    assert_eq!(shapes[0].color_at(4, 0), None);
}

#[test]
fn a_vertical_rectangle_interpolates_across_its_height() {
    let vertices = [vertex(0, 0, 0, 0, 0), vertex(2, 4, 0, 0, 0xff00)];
    let shapes = gradient_shapes(&vertices, &[0, 1], GRADIENT_FILL_RECT_V).unwrap();
    assert_eq!(shapes[0].color_at(1, 0), Some(0));
    assert_eq!(shapes[0].color_at(1, 2), Some(0x0000_007f));
}

#[test]
fn a_triangle_covers_only_its_interior_and_interpolates_by_area() {
    let vertices = [vertex(0, 0, 0xff00, 0, 0), vertex(4, 0, 0, 0xff00, 0), vertex(0, 4, 0, 0, 0xff00)];
    let shapes = gradient_shapes(&vertices, &[0, 1, 2], GRADIENT_FILL_TRIANGLE).unwrap();
    assert_eq!(shapes[0].bounds(), Rect { left: 0, top: 0, right: 4, bottom: 4 });
    assert_eq!(shapes[0].color_at(0, 0), Some(0x00ff_0000));
    assert_eq!(shapes[0].color_at(4, 0), Some(0x0000_ff00));
    assert_eq!(shapes[0].color_at(0, 4), Some(0x0000_00ff));
    // A point past the hypotenuse is outside the shape.
    assert_eq!(shapes[0].color_at(3, 3), None);
}

#[test]
fn a_request_naming_a_vertex_it_did_not_supply_or_an_unknown_mode_builds_nothing() {
    let vertices = [vertex(0, 0, 0, 0, 0), vertex(2, 2, 0, 0, 0)];
    assert!(gradient_shapes(&vertices, &[0, 2], GRADIENT_FILL_RECT_H).is_none());
    assert!(gradient_shapes(&vertices, &[0], GRADIENT_FILL_RECT_H).is_none());
    assert!(gradient_shapes(&vertices, &[0, 1], 3).is_none());
    assert!(gradient_shapes(&[], &[0, 1], GRADIENT_FILL_RECT_H).is_none());
    assert!(gradient_shapes(&vertices, &[], GRADIENT_FILL_RECT_H).is_none());
    assert!(gradient_shapes(&vertices, &[0, 1, 0], GRADIENT_FILL_TRIANGLE).is_some());
}
