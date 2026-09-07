use super::*;

#[test]
fn combination_applies_the_first_matrix_then_the_second() {
    let scale = Xform { m11: 2.0, m12: 0.0, m21: 0.0, m22: 3.0, dx: 0.0, dy: 0.0 };
    let translate = Xform { m11: 1.0, m12: 0.0, m21: 0.0, m22: 1.0, dx: 5.0, dy: 7.0 };
    let combined = Xform::combine(&scale, &translate);
    assert_eq!(combined, Xform { m11: 2.0, m12: 0.0, m21: 0.0, m22: 3.0, dx: 5.0, dy: 7.0 });
    assert_eq!(combined.apply(Point { x: 1, y: 1 }), Point { x: 7, y: 10 });
    // The other order translates before scaling, so the offset is scaled too.
    let other = Xform::combine(&translate, &scale);
    assert_eq!(other.apply(Point { x: 1, y: 1 }), Point { x: 12, y: 24 });
}

#[test]
fn identity_is_its_own_inverse_and_a_singular_matrix_has_none() {
    assert_eq!(Xform::IDENTITY.invert(), Some(Xform::IDENTITY));
    let singular = Xform { m11: 1.0, m12: 2.0, m21: 2.0, m22: 4.0, dx: 3.0, dy: 4.0 };
    assert_eq!(singular.invert(), None);
    let rotate = Xform { m11: 0.0, m12: 1.0, m21: -1.0, m22: 0.0, dx: 10.0, dy: 20.0 };
    let inverse = rotate.invert().expect("a rotation is invertible");
    assert_eq!(inverse.apply(rotate.apply(Point { x: 3, y: -4 })), Point { x: 3, y: -4 });
}

#[test]
fn inversion_undoes_the_translation_as_well_as_the_linear_part() {
    let xform = Xform { m11: 2.0, m12: 0.0, m21: 0.0, m22: 4.0, dx: 6.0, dy: -8.0 };
    let inverse = xform.invert().unwrap();
    assert_eq!(inverse, Xform { m11: 0.5, m12: 0.0, m21: 0.0, m22: 0.25, dx: -3.0, dy: 2.0 });
}

#[test]
fn rounding_is_floor_of_the_half_shifted_value_and_saturates() {
    assert_eq!(gdi_round(0.5), 1);
    assert_eq!(gdi_round(0.49), 0);
    assert_eq!(gdi_round(-0.5), 0);
    assert_eq!(gdi_round(-0.51), -1);
    assert_eq!(gdi_round(-1.5), -1);
    assert_eq!(gdi_round(1e300), i32::MAX);
    assert_eq!(gdi_round(-1e300), i32::MIN);
    assert_eq!(gdi_round(f64::NAN), i32::MIN);
}

#[test]
fn muldiv_rounds_away_from_zero_and_reports_overflow_as_minus_one() {
    assert_eq!(muldiv(3, 3, 2), 5);
    assert_eq!(muldiv(-3, 3, 2), -5);
    assert_eq!(muldiv(1, 1, 0), -1);
    assert_eq!(muldiv(3, -3, -2), 5);
    assert_eq!(muldiv(i32::MAX, i32::MAX, 1), -1);
}

#[test]
fn the_linear_comparison_ignores_translation_only() {
    let a = Xform { m11: 1.0, m12: 0.0, m21: 0.0, m22: 1.0, dx: 4.0, dy: 5.0 };
    assert!(a.linear_eq(&Xform::IDENTITY));
    assert!(!Xform { m11: 2.0, ..a }.linear_eq(&Xform::IDENTITY));
}

#[test]
fn the_client_layout_is_six_little_endian_floats() {
    let xform = Xform { m11: 1.5, m12: 2.5, m21: 3.5, m22: 4.5, dx: 5.5, dy: 6.5 };
    let bytes = xform.to_le_bytes();
    assert_eq!(bytes.len(), XFORM_BYTES);
    assert_eq!(f32::from_le_bytes(bytes[8..12].try_into().unwrap()), 3.5);
    assert_eq!(Xform::from_le_bytes(&bytes), xform);
}
