//! The LZO1X command decoder, its four match encodings, and the run-length
//! extension that only exists when the stream declares it.

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::lzo::{decompress, LzoError};

use super::build::{
    lzo_literals, lzo_long_literals, lzo_m1, lzo_m2, lzo_m3, lzo_m4, lzo_uniform, lzo_zero_run,
    patterned, LZO_END, LZO_RLE_HEADER,
};

fn decode(src: &[u8], out: usize) -> Result<Vec<u8>, LzoError> {
    let mut dst = vec![0u8; out];
    let n = decompress(src, &mut dst)?;
    dst.truncate(n);
    Ok(dst)
}

fn stream(body: &[u8]) -> Vec<u8> {
    let mut v = body.to_vec();
    v.extend_from_slice(&LZO_END);
    v
}

#[test]
fn the_end_marker_alone_is_an_empty_stream() {
    assert_eq!(decompress(&LZO_END, &mut []), Ok(0));
}

#[test]
fn a_stream_shorter_than_the_marker_is_refused() {
    assert_eq!(decompress(&[17, 0], &mut [0u8; 8]), Err(LzoError::InputOverrun));
}

#[test]
fn a_stream_with_no_marker_is_refused() {
    let mut b = Vec::new();
    lzo_literals(&mut b, b"abcdefgh");
    assert!(decode(&b, 8).is_err());
}

#[test]
fn bytes_after_the_marker_are_refused() {
    let mut b = Vec::new();
    lzo_literals(&mut b, b"abcdefgh");
    let mut s = stream(&b);
    s.push(0);
    assert_eq!(decode(&s, 8), Err(LzoError::InputNotConsumed));
}

#[test]
fn a_short_literal_run_round_trips() {
    let mut b = Vec::new();
    lzo_literals(&mut b, b"abcdefgh");
    assert_eq!(decode(&stream(&b), 8).unwrap(), b"abcdefgh".to_vec());
}

#[test]
fn the_shortest_and_longest_command_byte_runs_round_trip() {
    for len in [4usize, 5, 17, 18] {
        let data = patterned(len);
        let mut b = Vec::new();
        lzo_literals(&mut b, &data);
        assert_eq!(decode(&stream(&b), len).unwrap(), data, "len {len}");
    }
}

#[test]
fn a_literal_run_spelled_past_the_command_byte_round_trips() {
    for len in [19usize, 273, 274, 300, 1000] {
        let data = patterned(len);
        let mut b = Vec::new();
        lzo_long_literals(&mut b, &data);
        assert_eq!(decode(&stream(&b), len).unwrap(), data, "len {len}");
    }
}

#[test]
fn a_literal_run_that_does_not_fit_the_output_is_refused() {
    let mut b = Vec::new();
    lzo_literals(&mut b, b"abcdefgh");
    assert_eq!(decode(&stream(&b), 4), Err(LzoError::OutputOverrun));
}

#[test]
fn a_two_byte_match_encoding_copies_from_behind() {
    let mut b = Vec::new();
    lzo_literals(&mut b, b"abcd");
    lzo_m2(&mut b, 2, 3, &[]);
    assert_eq!(decode(&stream(&b), 7).unwrap(), b"abcdcdc".to_vec());
}

#[test]
fn every_two_byte_match_length_round_trips() {
    for mlen in 3..=8usize {
        let mut b = Vec::new();
        lzo_literals(&mut b, b"abcd");
        lzo_m2(&mut b, 4, mlen, &[]);
        let out = decode(&stream(&b), 4 + mlen).unwrap();
        assert_eq!(&out[..4], b"abcd", "mlen {mlen}");
        assert_eq!(out.len(), 4 + mlen);
    }
}

#[test]
fn a_three_byte_match_encoding_copies_from_behind() {
    let mut b = Vec::new();
    lzo_literals(&mut b, b"abcd");
    lzo_m3(&mut b, 4, 4, &[]);
    assert_eq!(decode(&stream(&b), 8).unwrap(), b"abcdabcd".to_vec());
}

#[test]
fn every_three_byte_match_length_round_trips() {
    let seed = patterned(64);
    for mlen in 3..=33usize {
        let mut b = Vec::new();
        lzo_long_literals(&mut b, &seed);
        lzo_m3(&mut b, 64, mlen, &[]);
        let out = decode(&stream(&b), 64 + mlen).unwrap();
        assert_eq!(&out[64..], &seed[..mlen], "mlen {mlen}");
    }
}

#[test]
fn a_three_byte_match_length_spelled_out_round_trips() {
    let seed = patterned(300);
    let mut b = Vec::new();
    lzo_long_literals(&mut b, &seed);
    // A length of 34 saturates the command byte and spills into the bytes
    // after it.
    b.push(32);
    b.push(3);
    let word = ((300usize - 1) << 2) as u16;
    b.extend_from_slice(&word.to_le_bytes());
    let out = decode(&stream(&b), 300 + 36).unwrap();
    assert_eq!(out.len(), 336);
    assert_eq!(&out[300..], &seed[..36]);
}

#[test]
fn a_four_byte_match_encoding_reaches_past_sixteen_kilobytes() {
    let seed = patterned(16_400);
    let mut b = Vec::new();
    lzo_long_literals(&mut b, &seed);
    lzo_m4(&mut b, 16_385, 5, &[]);
    let out = decode(&stream(&b), 16_405).unwrap();
    assert_eq!(&out[16_400..], &seed[15..20]);
}

#[test]
fn every_four_byte_match_length_round_trips() {
    let seed = patterned(20_000);
    for mlen in 3..=9usize {
        let mut b = Vec::new();
        lzo_long_literals(&mut b, &seed);
        lzo_m4(&mut b, 16_385, mlen, &[]);
        let out = decode(&stream(&b), 20_000 + mlen).unwrap();
        let at = 20_000 - 16_385;
        assert_eq!(&out[20_000..], &seed[at..at + mlen], "mlen {mlen}");
    }
}

#[test]
fn a_one_byte_match_encoding_follows_a_carried_literal() {
    let mut b = Vec::new();
    lzo_literals(&mut b, b"abcd");
    lzo_m3(&mut b, 4, 3, b"X");
    lzo_m1(&mut b, 2, &[]);
    assert_eq!(decode(&stream(&b), 10).unwrap(), b"abcdabcXcX".to_vec());
}

#[test]
fn literals_carried_by_a_match_land_after_it() {
    for trail in [&b"X"[..], &b"XY"[..], &b"XYZ"[..]] {
        let mut b = Vec::new();
        lzo_literals(&mut b, b"abcd");
        lzo_m3(&mut b, 4, 3, trail);
        let out = decode(&stream(&b), 7 + trail.len()).unwrap();
        assert_eq!(&out[..7], b"abcdabc");
        assert_eq!(&out[7..], trail);
    }
}

#[test]
fn a_distance_reaching_before_the_start_is_refused() {
    let mut b = Vec::new();
    lzo_literals(&mut b, b"abcd");
    lzo_m3(&mut b, 0x4000, 3, &[]);
    assert_eq!(decode(&stream(&b), 64), Err(LzoError::LookbehindOverrun));
}

#[test]
fn a_match_that_does_not_fit_the_output_is_refused() {
    let mut b = Vec::new();
    lzo_literals(&mut b, b"abcd");
    lzo_m3(&mut b, 4, 33, &[]);
    assert_eq!(decode(&stream(&b), 20), Err(LzoError::OutputOverrun));
}

#[test]
fn a_zero_run_needs_the_declared_bitstream() {
    let mut b = LZO_RLE_HEADER.to_vec();
    lzo_literals(&mut b, b"abcd");
    lzo_zero_run(&mut b, 100, &[]);
    let out = decode(&stream(&b), 104).unwrap();
    assert_eq!(&out[..4], b"abcd");
    assert_eq!(&out[4..], [0u8; 100]);
}

#[test]
fn the_same_bytes_without_the_header_are_not_a_zero_run() {
    // The command decodes as a distant match instead, and reaches before the
    // start of the output — which is why the header is not decoration.
    let mut b = Vec::new();
    lzo_literals(&mut b, b"abcd");
    lzo_zero_run(&mut b, 100, &[]);
    assert!(decode(&stream(&b), 104).is_err());
}

#[test]
fn every_zero_run_boundary_round_trips() {
    for len in [4usize, 11, 12, 2047, 2051] {
        let mut b = LZO_RLE_HEADER.to_vec();
        lzo_literals(&mut b, b"abcd");
        lzo_zero_run(&mut b, len, &[]);
        let out = decode(&stream(&b), 4 + len).unwrap();
        assert_eq!(out.len(), 4 + len, "len {len}");
        assert!(out[4..].iter().all(|&b| b == 0), "len {len}");
    }
}

#[test]
fn a_zero_run_that_does_not_fit_the_output_is_refused() {
    let mut b = LZO_RLE_HEADER.to_vec();
    lzo_literals(&mut b, b"abcd");
    lzo_zero_run(&mut b, 100, &[]);
    assert_eq!(decode(&stream(&b), 50), Err(LzoError::OutputOverrun));
}

#[test]
fn a_uniform_cluster_round_trips() {
    for &len in &[16_384usize, 32_768] {
        let s = lzo_uniform(len, 0x5a);
        assert_eq!(decode(&s, len).unwrap(), vec![0x5au8; len], "len {len}");
    }
}

#[test]
fn a_truncated_stream_is_refused_at_every_cut() {
    let s = lzo_uniform(4096, 0x11);
    for cut in [1usize, 2, 3, 7, s.len() / 2, s.len() - 1] {
        assert!(decode(&s[..cut], 4096).is_err(), "cut {cut}");
    }
}

#[test]
fn a_flipped_byte_never_escapes_its_buffers() {
    let s = lzo_uniform(2048, 0x33);
    for i in 0..s.len().min(400) {
        let mut bad = s.clone();
        bad[i] ^= 0xff;
        let mut dst = vec![0u8; 2048];
        let _ = decompress(&bad, &mut dst);
    }
}

#[test]
fn a_stream_opening_with_a_folded_literal_run_round_trips() {
    // A first byte above the marker's value is a literal run in its own right,
    // which is how a stream with no compressible head begins.
    let data = patterned(6);
    let mut b = vec![17 + 6];
    b.extend_from_slice(&data);
    assert_eq!(decode(&stream(&b), 6).unwrap(), data);
}

#[test]
fn a_folded_run_of_three_or_fewer_is_carried_literals() {
    let mut b = vec![17 + 3];
    b.extend_from_slice(b"xyz");
    assert_eq!(decode(&stream(&b), 3).unwrap(), b"xyz".to_vec());
}
