//! Test manifest.
//!
//! - `field`: modular arithmetic against hand-checkable identities.
//! - `point`: the group law against published base-point multiples.
//! - `ecdh`: the published key-agreement vector, validation refusals, and the
//!   debug key pair the pairing specification publishes.

#[path = "field.rs"] mod field;
#[path = "point.rs"] mod point;
#[path = "ecdh.rs"] mod ecdh;

const fn hexval(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// Parse a hex string into a fixed-width byte array.
pub(crate) const fn hex<const N: usize>(s: &str) -> [u8; N] {
    let b = s.as_bytes();
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (hexval(b[2 * i]) << 4) | hexval(b[2 * i + 1]);
        i += 1;
    }
    out
}

/// Reverse a byte array, which is how a least-significant-first protocol
/// encoding maps onto this crate's big-endian boundary.
pub(crate) fn rev<const N: usize>(mut b: [u8; N]) -> [u8; N] { b.reverse(); b }
