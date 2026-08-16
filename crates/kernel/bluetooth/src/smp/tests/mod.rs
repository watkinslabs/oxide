//! Test manifest.
//!
//! - `crypto`: the published crypto-function vectors, which are the only
//!   evidence the byte-order reversals are right.
//! - `method`: every cell of both method tables and every override.
//! - `level`: requirement and key-level mappings, key-size bounds, sufficiency.
//! - `pdu`: codec round trips and refusals.
//! - `keys`: the store, key roles, and address resolution.
//! - `xtransport`: both derivation directions in both generations.
//! - `pairing`: two sessions driven against each other end to end.

#[path = "crypto.rs"] mod crypto;
#[path = "method.rs"] mod method;
#[path = "level.rs"] mod level;
#[path = "pdu.rs"] mod pdu;
#[path = "keys.rs"] mod keys;
#[path = "xtransport.rs"] mod xtransport;
#[path = "pairing.rs"] mod pairing;

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
