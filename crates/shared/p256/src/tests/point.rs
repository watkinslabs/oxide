//! The group law against published base-point multiples.

use super::hex;
use crate::params::ELEM_LEN;
use crate::point::{Affine, Point};
use crate::scalar::{Scalar, mul_base};

fn affine_of(p: &Point) -> ([u8; ELEM_LEN], [u8; ELEM_LEN]) {
    let a = p.to_affine().expect("not the identity");
    (a.x_bytes(), a.y_bytes())
}

fn scalar(v: u64) -> Scalar {
    let mut b = [0u8; ELEM_LEN];
    b[ELEM_LEN - 8..].copy_from_slice(&v.to_be_bytes());
    Scalar::from_bytes_be(&b)
}

#[test]
fn base_point_is_on_the_curve() {
    let g = Point::generator().to_affine().unwrap();
    assert!(g.on_curve());
    assert_eq!(g.x_bytes(), hex::<ELEM_LEN>(
        "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"));
    assert_eq!(g.y_bytes(), hex::<ELEM_LEN>(
        "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"));
}

#[test]
fn published_base_point_multiples() {
    let cases: [(u64, &str, &str); 4] = [
        (1, "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
        (2, "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
            "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1"),
        (3, "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
            "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032"),
        (4, "e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852",
            "e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6"),
    ];
    for (k, x, y) in cases {
        let (gx, gy) = affine_of(&mul_base(&scalar(k)));
        assert_eq!(gx, hex::<ELEM_LEN>(x), "x of {}G", k);
        assert_eq!(gy, hex::<ELEM_LEN>(y), "y of {}G", k);
    }
}

#[test]
fn doubling_agrees_with_addition() {
    let g = Point::generator();
    let (dx, dy) = affine_of(&g.double());
    let (ax, ay) = affine_of(&g.add(&g));
    assert_eq!(dx, ax);
    assert_eq!(dy, ay);
    let (mx, my) = affine_of(&mul_base(&scalar(2)));
    assert_eq!(dx, mx);
    assert_eq!(dy, my);
}

#[test]
fn identity_is_absorbing_and_neutral() {
    let g = Point::generator();
    let i = Point::identity();
    assert_eq!(i.is_identity(), 1);
    assert_eq!(g.is_identity(), 0);
    let (x, y) = affine_of(&g.add(&i));
    let (gx, gy) = affine_of(&g);
    assert_eq!(x, gx);
    assert_eq!(y, gy);
    assert_eq!(i.add(&i).is_identity(), 1);
    assert!(i.to_affine().is_none());
}

#[test]
fn a_point_and_its_negation_sum_to_the_identity() {
    let g = Point::generator();
    assert_eq!(g.add(&g.neg()).is_identity(), 1);
}

#[test]
fn scalar_multiples_are_additive() {
    // 3G + 4G must be 7G, which exercises the ladder against the group law.
    let a = mul_base(&scalar(3));
    let b = mul_base(&scalar(4));
    let (sx, sy) = affine_of(&a.add(&b));
    let (mx, my) = affine_of(&mul_base(&scalar(7)));
    assert_eq!(sx, mx);
    assert_eq!(sy, my);
}

#[test]
fn a_point_off_the_curve_is_rejected() {
    let g = Point::generator().to_affine().unwrap();
    let bad = Affine { x: g.x, y: g.x };
    assert!(!bad.on_curve());
}

#[test]
fn the_order_times_the_base_point_is_the_identity() {
    let n = hex::<ELEM_LEN>(
        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
    assert_eq!(mul_base(&Scalar::from_bytes_be(&n)).is_identity(), 1);
}
