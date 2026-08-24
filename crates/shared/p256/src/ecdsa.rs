//! ECDSA verification over NIST P-256.

use crate::field::Fp;
use crate::params::ELEM_LEN;
use crate::point::Point;
use crate::scalar::{self, Scalar};

/// Verify an ECDSA signature whose `r` and `s` values are fixed-width bytes.
/// The digest is reduced to the group order as required by ECDSA. # C: O(256^2)
pub fn verify(public: &[u8], digest: &[u8], r: &[u8; ELEM_LEN], s: &[u8; ELEM_LEN]) -> bool {
    let q = match Point::from_bytes(public) { Some(p) => p, None => return false };
    let r = Scalar::from_bytes_be(r);
    let s = Scalar::from_bytes_be(s);
    if !r.in_range() || !s.in_range() { return false; }
    let mut h = [0u8; ELEM_LEN];
    if digest.len() >= ELEM_LEN { h.copy_from_slice(&digest[..ELEM_LEN]); }
    else { h[ELEM_LEN - digest.len()..].copy_from_slice(digest); }
    let z = Scalar::from_bytes_reduced(&h);
    let w = s.inv_mod();
    let u1 = z.mul_mod(&w);
    let u2 = r.mul_mod(&w);
    let sum = scalar::mul_base(&u1).add(&scalar::mul(&u2, &q));
    let a = match sum.to_affine() { Some(a) => a, None => return false };
    let x = Scalar::from_bytes_reduced(&a.x.to_bytes_be());
    x.to_bytes_be() == r.to_bytes_be()
}

/// Parse a fixed-width P-256 ECDSA signature. # C: O(1)
pub fn parse_p1363(sig: &[u8]) -> Option<([u8; ELEM_LEN], [u8; ELEM_LEN])> {
    if sig.len() != 2 * ELEM_LEN { return None; }
    let mut r = [0; ELEM_LEN];
    let mut s = [0; ELEM_LEN];
    r.copy_from_slice(&sig[..ELEM_LEN]);
    s.copy_from_slice(&sig[ELEM_LEN..]);
    Some((r, s))
}

/// Convert an affine coordinate into the field representation used here. # C: O(1)
pub fn valid_coordinate(bytes: &[u8; ELEM_LEN]) -> bool { Fp::from_bytes_be(bytes).is_some() }
