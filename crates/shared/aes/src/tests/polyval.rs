// POLYVAL known-answer tests.
//
// Provenance: RFC 8452 ("AES-GCM-SIV"), which defines POLYVAL. §3 gives the
// two-block example under a bare hash key; the worked example in §4 hashes the
// three-block encoded input and is reproduced here as its 48-byte message.
//
// A round trip cannot check a hash, and byte order is exactly what a
// hand-written POLYVAL gets wrong — drop the reversal at either boundary and
// the function is still a perfectly good keyed hash, just not this one. These
// vectors are the only thing that pins it.
//
// The zero-padding of a trailing partial block is not exercised here: both
// published messages are whole blocks. The HCTR2 vectors over non-block-
// multiple messages cover it, since the mode's one-byte padding leaves a
// partial block for `finish` to pad.

use crate::polyval::{Polyval, polyval};
use super::vec_util::{assert_hex, hex};

struct Vector { h: &'static str, data: &'static str, out: &'static str }

const VECTORS: &[Vector] = &[
    // §3, POLYVAL(H, X_1, X_2)
    Vector { h: "25629347589242761d31f826ba4b757b",
             data: "4f4f95668c83dfb6401762bb2d01a262d1a24ddd2721d006bbe45f20d3c9f362",
             out: "f7a3b47b846119fae5b7866cf5e5b77e" },
    // §4, the hash over associated data, plaintext and the length block
    Vector { h: "310728d9911f1f3837b24316c3fab9a0",
             data: concat!("6578616d706c65000000000000000000",
                           "48656c6c6f20776f726c640000000000",
                           "38000000000000005800000000000000"),
             out: "ad7fcf0b5169851662672f3c5f95138f" },
];

fn key16(s: &str) -> [u8; 16] { let mut b = [0u8; 16]; b.copy_from_slice(&hex(s)); b }

#[test]
fn matches_vectors() {
    for v in VECTORS {
        assert_hex(&polyval(&key16(v.h), &hex(v.data)), v.out);
    }
}

/// The same published digest must come out however the caller splits the
/// message across `update` calls — the partial-block buffer carries bytes over
/// rather than hashing a short block of its own.
#[test]
fn chunked_updates_match_vectors() {
    for v in VECTORS {
        let data = hex(v.data);
        for split in 0..=data.len() {
            let mut p = Polyval::new(&key16(v.h));
            p.update(&data[..split]);
            p.update(&data[split..]);
            assert_hex(&p.finish(), v.out);
        }
        // Byte at a time: every update lands mid-block.
        let mut p = Polyval::new(&key16(v.h));
        for b in data.iter() { p.update(&[*b]); }
        assert_hex(&p.finish(), v.out);
    }
}

/// An all-zero message hashes to zero whatever the key: every absorbed block
/// is zero, so the accumulator never leaves it. A dropped byte reversal is
/// invisible here, which is why this is a guard against a broken absorb loop
/// and not a substitute for the vectors above.
#[test]
fn zero_message_hashes_to_zero() {
    assert_hex(&polyval(&key16(VECTORS[0].h), &[0u8; 64]), "00000000000000000000000000000000");
}
