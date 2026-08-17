//! The LZ4 sequence decoder, at every boundary the format has.

use alloc::vec;
use alloc::vec::Vec;

use crate::compress::lz4::{decompress, Lz4Error};

use super::build::{lz4_compress, lz4_literals, lz4_seq, patterned};

fn decode(src: &[u8], out: usize) -> Result<Vec<u8>, Lz4Error> {
    let mut dst = vec![0u8; out];
    let n = decompress(src, &mut dst)?;
    dst.truncate(n);
    Ok(dst)
}

#[test]
fn literal_only_block_round_trips() {
    let data = b"hello compressed world";
    assert_eq!(decode(&lz4_literals(data), data.len()).unwrap(), data.to_vec());
}

#[test]
fn literal_run_of_fourteen_needs_no_extension() {
    let data = [7u8; 14];
    let block = lz4_literals(&data);
    assert_eq!(block[0], 14 << 4);
    assert_eq!(block.len(), 15);
    assert_eq!(decode(&block, 14).unwrap(), data.to_vec());
}

#[test]
fn literal_run_of_fifteen_spills_a_zero_byte() {
    let data = [8u8; 15];
    let block = lz4_literals(&data);
    assert_eq!(&block[..2], &[15 << 4, 0]);
    assert_eq!(decode(&block, 15).unwrap(), data.to_vec());
}

#[test]
fn literal_run_of_two_hundred_sixty_nine_ends_the_spill() {
    let data = [9u8; 269];
    let block = lz4_literals(&data);
    assert_eq!(&block[..2], &[15 << 4, 254]);
    assert_eq!(decode(&block, 269).unwrap(), data.to_vec());
}

#[test]
fn literal_run_of_two_hundred_seventy_takes_two_spill_bytes() {
    let data = [10u8; 270];
    let block = lz4_literals(&data);
    assert_eq!(&block[..3], &[15 << 4, 255, 0]);
    assert_eq!(decode(&block, 270).unwrap(), data.to_vec());
}

#[test]
fn literal_run_of_five_hundred_twenty_five_takes_three_spill_bytes() {
    let data = patterned(525);
    let block = lz4_literals(&data);
    assert_eq!(&block[..4], &[15 << 4, 255, 255, 0]);
    assert_eq!(decode(&block, 525).unwrap(), data);
}

#[test]
fn empty_input_is_refused() {
    assert_eq!(decompress(&[], &mut [0u8; 16]), Err(Lz4Error::Empty));
}

#[test]
fn empty_output_takes_only_the_empty_block() {
    assert_eq!(decompress(&[0], &mut []), Ok(0));
    assert_eq!(decompress(&[0x10, 1], &mut []), Err(Lz4Error::Overrun));
}

#[test]
fn literals_past_the_end_of_input_are_refused() {
    // The token claims eight literals and only three follow.
    assert_eq!(decode(&[0x80, 1, 2, 3], 8), Err(Lz4Error::Truncated));
}

#[test]
fn input_left_over_after_the_last_sequence_is_refused() {
    let mut block = lz4_literals(b"abcdef");
    block.push(0xff);
    assert_eq!(decode(&block, 6), Err(Lz4Error::Truncated));
}

#[test]
fn literals_that_do_not_fit_the_output_are_refused() {
    let block = lz4_literals(&[3u8; 40]);
    assert_eq!(decode(&block, 39), Err(Lz4Error::Truncated));
}

#[test]
fn a_short_output_leaves_the_block_undecoded() {
    // Twenty bytes of literals into sixteen: the last-sequence check sees the
    // overrun before a single byte is copied.
    let block = lz4_literals(&[1u8; 20]);
    let mut dst = [0u8; 16];
    assert!(decompress(&block, &mut dst).is_err());
    assert_eq!(dst, [0u8; 16]);
}

#[test]
fn literal_length_spill_that_runs_out_of_input_is_refused() {
    assert_eq!(decode(&[0xf0, 255, 255], 300), Err(Lz4Error::Truncated));
}

/// Literals, one match, then the tail literals every block ends with.
fn one_match(lits: &[u8], dist: u16, mlen: usize, tail: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    lz4_seq(&mut b, lits, dist, mlen);
    b.extend_from_slice(&lz4_literals(tail));
    b
}

#[test]
fn a_match_copies_from_what_was_already_produced() {
    let block = one_match(b"abcdefgh", 8, 4, b"ZZZZZZZZ");
    assert_eq!(decode(&block, 20).unwrap(), b"abcdefghabcdZZZZZZZZ".to_vec());
}

#[test]
fn a_distance_of_one_repeats_the_last_byte() {
    let block = one_match(b"abcdefgQ", 1, 4, b"ZZZZZZZZ");
    assert_eq!(decode(&block, 20).unwrap(), b"abcdefgQQQQQZZZZZZZZ".to_vec());
}

#[test]
fn a_match_longer_than_its_distance_is_a_run() {
    let block = one_match(b"abcdefgh", 2, 9, b"ZZZZZZZZZZZ");
    assert_eq!(decode(&block, 28).unwrap(), b"abcdefghghghghghgZZZZZZZZZZZ".to_vec());
}

#[test]
fn a_zero_distance_is_refused() {
    let block = one_match(b"abcdefgh", 0, 4, b"ZZZZZZZZ");
    assert_eq!(decode(&block, 20), Err(Lz4Error::BadOffset));
}

#[test]
fn a_distance_reaching_before_the_start_is_refused() {
    let block = one_match(b"abcdefgh", 9, 4, b"ZZZZZZZZ");
    assert_eq!(decode(&block, 20), Err(Lz4Error::BadOffset));
}

#[test]
fn a_distance_of_exactly_the_output_so_far_is_accepted() {
    let block = one_match(b"abcdefgh", 8, 4, b"ZZZZZZZZ");
    assert_eq!(&decode(&block, 20).unwrap()[8..12], b"abcd");
}

#[test]
fn a_match_length_at_the_nibble_boundary_needs_no_spill() {
    // Eighteen is the longest match the nibble alone encodes.
    let mut b = Vec::new();
    lz4_seq(&mut b, b"abcdefgh", 8, 18);
    assert_eq!(b[0] & 0x0f, 14);
    b.extend_from_slice(&lz4_literals(b"ZZZZZZZZZZZZ"));
    let out = decode(&b, 38).unwrap();
    assert_eq!(&out[8..26], b"abcdefghabcdefghab");
}

#[test]
fn a_match_length_past_the_nibble_spills() {
    let mut b = Vec::new();
    lz4_seq(&mut b, b"abcdefgh", 8, 19);
    assert_eq!(b[0] & 0x0f, 15);
    b.extend_from_slice(&lz4_literals(b"ZZZZZZZZZZZZ"));
    let out = decode(&b, 39).unwrap();
    assert_eq!(&out[8..27], b"abcdefghabcdefghabc");
}

#[test]
fn a_match_length_spill_of_two_hundred_seventy_decodes() {
    let mut b = Vec::new();
    lz4_seq(&mut b, b"abcdefgh", 8, 274);
    b.extend_from_slice(&lz4_literals(b"ZZZZZZZZZZZZ"));
    let out = decode(&b, 294).unwrap();
    assert_eq!(out.len(), 294);
    assert_eq!(&out[282..], b"ZZZZZZZZZZZZ");
}

#[test]
fn a_match_finishing_inside_the_last_five_bytes_is_refused() {
    // The block is otherwise well formed — the input is exactly consumed and
    // the output exactly filled — and is still refused, because the match ends
    // four bytes from the end and the format reserves those for literals.
    let mut b = Vec::new();
    lz4_seq(&mut b, b"abcdefgh", 8, 19);
    b.extend_from_slice(&lz4_literals(b"ZZZZ"));
    assert_eq!(b.len(), 17);
    assert_eq!(decode(&b, 31), Err(Lz4Error::Overrun));
}

#[test]
fn a_block_that_ends_with_a_match_rather_than_literals_is_refused() {
    // No tail: the last sequence must be literals that consume the input.
    let mut b = Vec::new();
    lz4_seq(&mut b, b"abcdefgh", 8, 4);
    assert_eq!(decode(&b, 12), Err(Lz4Error::Truncated));
}

#[test]
fn a_match_running_past_the_output_is_refused() {
    let mut b = Vec::new();
    lz4_seq(&mut b, b"abcdefgh", 8, 400);
    b.extend_from_slice(&lz4_literals(b"ZZZZZZZZZZZZ"));
    assert_eq!(decode(&b, 40), Err(Lz4Error::Overrun));
}

#[test]
fn a_match_length_spill_that_eats_the_tail_is_refused() {
    // The spill bytes run to within five of the end, which no encoder emits.
    let block = [0x8f, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', 8, 0, 255, 255];
    assert_eq!(decode(&block, 400), Err(Lz4Error::Truncated));
}

#[test]
fn a_sequence_cut_off_inside_its_distance_is_refused() {
    // One byte of the two-byte distance, and nothing after it.
    let block = [0x80, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h', 8];
    assert_eq!(decode(&block, 40), Err(Lz4Error::Truncated));
}

#[test]
fn a_literal_only_block_is_complete_without_a_match() {
    // The mirror of the case above: the same literals with nothing after them
    // are a whole block, which is why "input consumed" is the end condition.
    let block = [0x80, b'a', b'b', b'c', b'd', b'e', b'f', b'g', b'h'];
    assert_eq!(decode(&block, 40).unwrap(), b"abcdefgh".to_vec());
}

#[test]
fn a_distance_of_sixty_five_thousand_reaches_back() {
    let src = {
        let mut v = patterned(70_000);
        let head: Vec<u8> = v[..40].to_vec();
        let n = v.len();
        v[n - 40..].copy_from_slice(&head);
        v
    };
    let block = lz4_compress(&src);
    assert_eq!(decode(&block, src.len()).unwrap(), src);
}

#[test]
fn a_whole_uniform_cluster_round_trips() {
    let src = vec![0xa5u8; 16_384];
    let block = lz4_compress(&src);
    assert!(block.len() < 200, "a uniform cluster should compress hard, got {}", block.len());
    assert_eq!(decode(&block, src.len()).unwrap(), src);
}

#[test]
fn a_patterned_cluster_round_trips_and_shrinks() {
    let src = patterned(16_384);
    let block = lz4_compress(&src);
    assert!(block.len() < src.len());
    assert_eq!(decode(&block, src.len()).unwrap(), src);
}

#[test]
fn every_prefix_of_a_patterned_cluster_round_trips() {
    let src = patterned(4096);
    for len in [1usize, 2, 5, 11, 12, 13, 17, 64, 255, 256, 1023, 4096] {
        let block = lz4_compress(&src[..len]);
        assert_eq!(decode(&block, len).unwrap(), src[..len].to_vec(), "len {len}");
    }
}

#[test]
fn an_output_larger_than_the_block_decodes_short() {
    // The decoder reports what it produced; the caller is what insists a
    // cluster be whole.
    let block = lz4_compress(&patterned(100));
    let mut dst = vec![0u8; 4096];
    assert_eq!(decompress(&block, &mut dst).unwrap(), 100);
}

#[test]
fn a_truncated_compressed_block_is_refused() {
    let src = patterned(16_384);
    let block = lz4_compress(&src);
    for cut in [1usize, 4, block.len() / 2, block.len() - 1] {
        assert!(decode(&block[..cut], src.len()).is_err(), "cut {cut}");
    }
}

#[test]
fn a_block_with_a_flipped_token_never_escapes_its_buffers() {
    // Not a claim that the result is meaningful: a claim that no input, valid
    // or not, reads or writes outside what it was given.
    let src = patterned(2048);
    let block = lz4_compress(&src);
    for i in 0..block.len().min(300) {
        let mut bad = block.clone();
        bad[i] ^= 0xff;
        let mut dst = vec![0u8; 2048];
        let _ = decompress(&bad, &mut dst);
    }
}
