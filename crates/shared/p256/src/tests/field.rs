//! Field arithmetic. The identities here are independent of the Montgomery
//! representation, so a wrong constant or a wrong reduction shows up.

use super::hex;
use crate::field::Fp;
use crate::params::{ELEM_LEN, P};

fn p_bytes() -> [u8; ELEM_LEN] {
    let mut out = [0u8; ELEM_LEN];
    for i in 0..4 {
        out[ELEM_LEN - 8 * (i + 1)..ELEM_LEN - 8 * i].copy_from_slice(&P[i].to_be_bytes());
    }
    out
}

fn fp(s: &str) -> Fp { Fp::from_bytes_be(&hex::<ELEM_LEN>(s)).unwrap() }

#[test]
fn round_trip_through_bytes() {
    let v = "0123456789abcdeffedcba987654321011223344556677889900aabbccddeeff";
    assert_eq!(fp(v).to_bytes_be(), hex::<ELEM_LEN>(v));
}

#[test]
fn identities() {
    let one = Fp::one();
    assert_eq!(one.to_bytes_be(), hex::<ELEM_LEN>(
        "0000000000000000000000000000000000000000000000000000000000000001"));
    assert_eq!(Fp::zero().to_bytes_be(), [0u8; ELEM_LEN]);
    assert_eq!(one.mul(&one).to_bytes_be(), one.to_bytes_be());
    assert_eq!(one.add(&one).to_bytes_be(), hex::<ELEM_LEN>(
        "0000000000000000000000000000000000000000000000000000000000000002"));
}

#[test]
fn the_prime_and_anything_above_it_is_not_a_residue() {
    assert!(Fp::from_bytes_be(&p_bytes()).is_none());
    assert!(Fp::from_bytes_be(&hex::<ELEM_LEN>(
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")).is_none());
    // One below the prime is a residue.
    let mut below = p_bytes();
    below[ELEM_LEN - 1] -= 1;
    assert!(Fp::from_bytes_be(&below).is_some());
}

#[test]
fn subtraction_wraps_through_the_prime() {
    let one = Fp::one();
    let mut expect = p_bytes();
    expect[ELEM_LEN - 1] -= 1;
    assert_eq!(Fp::zero().sub(&one).to_bytes_be(), expect);
    assert_eq!(one.neg().to_bytes_be(), expect);
}

#[test]
fn addition_reduces_above_the_prime() {
    let mut below = p_bytes();
    below[ELEM_LEN - 1] -= 1;
    let pm1 = Fp::from_bytes_be(&below).unwrap();
    assert_eq!(pm1.add(&Fp::one()).to_bytes_be(), [0u8; ELEM_LEN]);
    assert_eq!(pm1.add(&pm1).to_bytes_be(), {
        let mut e = p_bytes();
        e[ELEM_LEN - 1] -= 2;
        e
    });
}

#[test]
fn inverse_returns_the_identity() {
    for v in [
        "0000000000000000000000000000000000000000000000000000000000000002",
        "0123456789abcdeffedcba987654321011223344556677889900aabbccddeeff",
        "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
    ] {
        let a = fp(v);
        assert_eq!(a.mul(&a.inv()).to_bytes_be(), Fp::one().to_bytes_be(), "{}", v);
    }
}

#[test]
fn square_matches_self_multiplication() {
    let a = fp("0123456789abcdeffedcba987654321011223344556677889900aabbccddeeff");
    assert_eq!(a.sqr().to_bytes_be(), a.mul(&a).to_bytes_be());
}

#[test]
fn equality_and_zero_flags() {
    let a = fp("0000000000000000000000000000000000000000000000000000000000000007");
    assert_eq!(a.ct_eq(&a), 1);
    assert_eq!(a.ct_eq(&Fp::one()), 0);
    assert_eq!(Fp::zero().is_zero(), 1);
    assert_eq!(a.is_zero(), 0);
}
