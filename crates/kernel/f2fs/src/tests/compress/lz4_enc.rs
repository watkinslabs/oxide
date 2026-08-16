//! LZ4 encoding, proved by the decoder that has to read it back.
//!
//! A round trip is the whole contract: the format has no end marker, so a
//! stream that breaks the encoder's parsing restrictions is not rejected by
//! the decoder — it is read as a different, shorter block. Every case here
//! therefore checks the DECODED BYTES, never just that encoding succeeded.

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::lz4;
use crate::compress::lz4_enc;

use super::build::lz4_compress as oracle;

/// Encode, decode, and hand back what came out. # C: O(len)
fn round(src: &[u8]) -> Vec<u8> {
    let mut packed = vec![0u8; src.len() * 2 + 64];
    let n = lz4_enc::compress(src, &mut packed).expect("budget");
    let mut out = vec![0u8; src.len()];
    let produced = lz4::decompress(&packed[..n], &mut out).expect("decode");
    assert_eq!(produced, src.len(), "produced length");
    out
}

/// A deterministic byte stream with no structure to find. # C: O(n)
fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut s = seed | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            (s >> 11) as u8
        })
        .collect()
}

#[test]
fn every_length_up_to_a_block_round_trips() {
    for n in 0..300usize {
        let src: Vec<u8> = (0..n).map(|i| (i % 7) as u8).collect();
        assert_eq!(round(&src), src, "length {n}");
    }
}

#[test]
fn incompressible_bytes_round_trip_and_do_not_shrink() {
    let src = noise(16384, 0x1234_5678);
    assert_eq!(round(&src), src);
    let mut packed = vec![0u8; src.len() * 2];
    let n = lz4_enc::compress(&src, &mut packed).unwrap();
    assert!(n >= src.len(), "noise compressed to {n} from {}", src.len());
}

#[test]
fn a_long_run_of_one_byte_round_trips() {
    for n in [4usize, 12, 13, 16, 19, 32, 271, 4096, 65536] {
        let src = vec![0xa5u8; n];
        assert_eq!(round(&src), src, "run of {n}");
    }
}

#[test]
fn a_match_at_every_distance_round_trips() {
    // A distance is only reachable once the output holds that many bytes, so
    // each case is a prefix of noise followed by a copy of its own tail.
    for dist in 1..=600usize {
        let head = noise(dist, dist as u32 + 1);
        let mut src = head.clone();
        src.extend_from_slice(&head);
        src.extend_from_slice(&noise(32, 9));
        assert_eq!(round(&src), src, "distance {dist}");
    }
}

#[test]
fn a_match_of_every_length_round_trips() {
    // The nibble saturates at fifteen and spills; the spill rolls over at
    // 255. Both boundaries and their neighbours are covered.
    for extra in 0..300usize {
        let mlen = 4 + extra;
        let unit = noise(64, 3);
        let mut src = unit.clone();
        src.extend_from_slice(&unit[..mlen.min(unit.len())]);
        while src.len() < 64 + mlen { src.push(src[src.len() - 64]); }
        src.extend_from_slice(&noise(24, 5));
        assert_eq!(round(&src), src, "match length {mlen}");
    }
}

#[test]
fn a_literal_run_of_every_length_round_trips() {
    // The literal nibble saturates at fifteen too, and a run past 270 needs a
    // second spill byte.
    for n in 0..300usize {
        let mut src = noise(n, n as u32 + 17);
        let tail = vec![7u8; 64];
        src.extend_from_slice(&tail);
        src.extend_from_slice(&tail);
        assert_eq!(round(&src), src, "literal run {n}");
    }
}

#[test]
fn every_cluster_width_round_trips() {
    for log in 2u8..=8 {
        let bytes = (1usize << log) * crate::uapi::BLKSIZE;
        let mut src: Vec<u8> = (0..bytes).map(|i| ((i / 97) % 251) as u8).collect();
        src[..64].copy_from_slice(&noise(64, log as u32));
        assert_eq!(round(&src), src, "log {log}");
    }
}

#[test]
fn a_budget_too_small_is_refused_rather_than_truncated() {
    let src = noise(4096, 42);
    for budget in [0usize, 1, 16, 1024, 4000] {
        let mut packed = vec![0u8; budget];
        assert_eq!(lz4_enc::compress(&src, &mut packed), None, "budget {budget}");
    }
}

#[test]
fn the_encoder_and_the_independent_one_both_decode_to_the_same_bytes() {
    // Two encoders written from the format description, one in the test
    // fixtures and one in the kernel: agreement on the decoded bytes is
    // evidence about the format rather than about either implementation.
    for n in [64usize, 1000, 4096, 20000] {
        let mut src: Vec<u8> = (0..n).map(|i| ((i * i) % 13) as u8).collect();
        src.extend_from_slice(&noise(64, n as u32));
        let mine = round(&src);
        let theirs = oracle(&src);
        let mut out = vec![0u8; src.len()];
        let produced = lz4::decompress(&theirs, &mut out).expect("oracle decode");
        assert_eq!(produced, src.len());
        assert_eq!(mine, out, "length {n}");
        assert_eq!(mine, src);
    }
}

#[test]
fn the_last_five_bytes_are_always_literals() {
    // The decoder ends a block on the encoder's promise that no match
    // finishes inside the tail. A stream that broke it would still decode,
    // just to the wrong length, so the check is on the length.
    for n in 13..200usize {
        let src = vec![3u8; n];
        let mut packed = vec![0u8; n * 2 + 64];
        let k = lz4_enc::compress(&src, &mut packed).unwrap();
        let mut out = vec![0u8; n];
        assert_eq!(lz4::decompress(&packed[..k], &mut out), Ok(n), "length {n}");
        // The block must be consumed exactly: trailing bytes would mean the
        // decoder stopped early and the rest is unread.
        let mut short = vec![0u8; n];
        assert!(lz4::decompress(&packed[..k - 1], &mut short).is_err(), "length {n}");
    }
}
