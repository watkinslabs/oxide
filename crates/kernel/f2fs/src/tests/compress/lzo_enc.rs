//! LZO1X encoding, both variants, proved by the decoder that reads it back.
//!
//! The stream's awkward part is the literals that ride in the spare bits of a
//! byte an earlier instruction wrote: an encoder that loses track of which
//! byte that was writes a stream the decoder reads as a match, and the result
//! is plausible bytes rather than an error. Every case here checks the DECODED
//! BYTES for both variants, because the run-length writer and the plain one
//! take different paths through the same instruction set.

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::lzo;
use crate::compress::lzo_enc;

/// Encode with one variant, decode, and hand back what came out. # C: O(len)
fn round_as(src: &[u8], rle: bool) -> Vec<u8> {
    let mut packed = vec![0u8; src.len() * 2 + 256];
    let n = lzo_enc::compress(src, &mut packed, rle).expect("budget");
    let mut out = vec![0u8; src.len()];
    let produced = lzo::decompress(&packed[..n], &mut out).expect("decode");
    assert_eq!(produced, src.len(), "produced length, rle={rle}");
    out
}

/// Both variants must give the input back. # C: O(len)
fn round(src: &[u8]) {
    assert_eq!(round_as(src, false), src, "plain");
    assert_eq!(round_as(src, true), src, "run-length");
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
        round(&src);
    }
}

#[test]
fn every_short_length_of_noise_round_trips() {
    // Short inputs never reach the match finder and are spelled out; the
    // opening byte has a shape only a stream's first literal run can use.
    for n in 0..64usize {
        round(&noise(n, n as u32 + 1));
    }
}

#[test]
fn incompressible_bytes_round_trip() {
    round(&noise(16384, 0xfeed_face));
}

#[test]
fn a_long_run_of_one_byte_round_trips() {
    for n in [4usize, 20, 21, 33, 34, 264, 300, 4096, 65536] {
        round(&vec![0x5au8; n]);
    }
}

#[test]
fn a_run_of_zeroes_of_every_length_round_trips() {
    // The run-length variant spells these as one instruction and the plain
    // one as a match; both must give the same bytes back.
    for n in 0..300usize {
        let mut src = noise(24, 11);
        src.extend_from_slice(&vec![0u8; n]);
        src.extend_from_slice(&noise(24, 12));
        round(&src);
    }
}

#[test]
fn a_zero_run_at_the_extensions_boundaries_round_trips() {
    for n in [3usize, 4, 5, 2049, 2050, 2051, 2052, 2053, 4102, 6000] {
        let mut src = noise(32, 13);
        src.extend_from_slice(&vec![0u8; n]);
        src.extend_from_slice(&noise(32, 14));
        round(&src);
    }
}

#[test]
fn the_run_length_variant_spends_fewer_bytes_on_zeroes() {
    // If it did not, the extension would be a header that buys nothing and
    // the two writers would be the same writer.
    let mut src = noise(32, 15);
    src.extend_from_slice(&vec![0u8; 40000]);
    src.extend_from_slice(&noise(32, 16));
    let mut a = vec![0u8; src.len() * 2 + 256];
    let mut b = vec![0u8; src.len() * 2 + 256];
    let plain = lzo_enc::compress(&src, &mut a, false).unwrap();
    let rle = lzo_enc::compress(&src, &mut b, true).unwrap();
    assert!(rle < plain, "run-length {rle} not shorter than plain {plain}");
}

#[test]
fn a_match_at_every_distance_round_trips() {
    for dist in 1..=600usize {
        let head = noise(dist, dist as u32 + 21);
        let mut src = head.clone();
        src.extend_from_slice(&head);
        src.extend_from_slice(&noise(40, 22));
        round(&src);
    }
}

#[test]
fn a_match_at_every_encoding_boundary_round_trips() {
    // The distance chooses the encoding: two bytes below 0x800, three below
    // 0x4000, four above it. Each boundary and its neighbours are covered.
    for dist in [0x7feusize, 0x7ff, 0x800, 0x801, 0x3fff, 0x4000, 0x4001, 0xbffd, 0xbffe] {
        let head = noise(dist, dist as u32);
        let mut src = head.clone();
        src.extend_from_slice(&head[..dist.min(4096)]);
        src.extend_from_slice(&noise(40, 23));
        round(&src);
    }
}

#[test]
fn a_match_of_every_length_round_trips() {
    // The length field is two, five or six bits depending on the encoding and
    // spills past that; the long-match band the run-length variant refuses to
    // write is inside this range.
    for mlen in 4..320usize {
        let unit = noise(1024, 31);
        let mut src = unit.clone();
        src.extend_from_slice(&unit[..mlen]);
        src.extend_from_slice(&noise(40, 32));
        round(&src);
    }
}

#[test]
fn every_cluster_width_round_trips() {
    for log in 2u8..=8 {
        let bytes = (1usize << log) * crate::uapi::BLKSIZE;
        let mut src: Vec<u8> = (0..bytes).map(|i| ((i / 89) % 241) as u8).collect();
        src[..64].copy_from_slice(&noise(64, log as u32));
        round(&src);
    }
}

#[test]
fn a_budget_too_small_is_refused_rather_than_truncated() {
    let src = noise(4096, 77);
    for budget in [0usize, 1, 2, 5, 16, 1024, 4000] {
        let mut packed = vec![0u8; budget];
        assert_eq!(lzo_enc::compress(&src, &mut packed, false), None, "plain, budget {budget}");
        assert_eq!(lzo_enc::compress(&src, &mut packed, true), None, "rle, budget {budget}");
    }
}

#[test]
fn the_plain_variant_never_opens_with_the_version_byte() {
    // A stream whose first byte is the version marker is read as a versioned
    // one, and its first two bytes are then not data at all.
    for n in [0usize, 1, 2, 3, 17, 18, 21, 64, 300, 4096] {
        for seed in 1..6u32 {
            let src = noise(n, seed);
            let mut packed = vec![0u8; n * 2 + 256];
            let k = lzo_enc::compress(&src, &mut packed, false).unwrap();
            if k >= 5 {
                assert_ne!(packed[0], lzo::VERSION_MARKER, "length {n} seed {seed}");
            }
        }
    }
}

#[test]
fn the_run_length_variant_declares_its_version() {
    let src = noise(1000, 5);
    let mut packed = vec![0u8; 4096];
    let k = lzo_enc::compress(&src, &mut packed, true).unwrap();
    assert!(k >= 5);
    assert_eq!(packed[0], lzo::VERSION_MARKER);
    assert_eq!(packed[1], lzo_enc::LZO_VERSION);
}

#[test]
fn a_stream_is_consumed_exactly() {
    // The decoder refuses a stream with bytes after its marker, so an encoder
    // that padded or over-ran would be caught here rather than in a file.
    for n in [0usize, 30, 500, 5000] {
        let src = noise(n, n as u32 + 3);
        for rle in [false, true] {
            let mut packed = vec![0u8; n * 2 + 256];
            let k = lzo_enc::compress(&src, &mut packed, rle).unwrap();
            let mut out = vec![0u8; n];
            assert_eq!(lzo::decompress(&packed[..k], &mut out), Ok(n));
            assert_eq!(
                lzo::decompress(&packed[..k + 1], &mut out),
                Err(lzo::LzoError::InputNotConsumed),
                "length {n} rle {rle}"
            );
        }
    }
}
