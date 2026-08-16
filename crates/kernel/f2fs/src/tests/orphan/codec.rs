//! The orphan block's layout and the pack arithmetic that depends on it.
//!
//! Every number here is a wire contract: a block written with the array one
//! entry too long, or read with a count one too large, reaches the trailer —
//! and the trailer's words then become inode numbers a mount frees. The
//! boundary cases are therefore the point of this file, not decoration.

use alloc::vec;
use alloc::vec::Vec;

use crate::flags::CP_ORPHAN_PRESENT_FLAG;
use crate::uapi::{le32, BLKSIZE, CP_PACKS, NR_CURSEG_DATA_TYPE, NR_CURSEG_PERSIST_TYPE};
use crate::volume::orphan::block::*;

/// Summary blocks a pack that keeps every log carries, and one that parks its
/// node logs in the summary area instead.
const LOGS: usize = NR_CURSEG_PERSIST_TYPE;
const SHORT_LOGS: usize = NR_CURSEG_DATA_TYPE;

/// Head, tail and every summary of the longest pack.
const FIXED_PACK_BLOCKS: u32 = CP_PACKS + LOGS as u32;

// ------------------------------------------------------------------- layout

#[test]
fn the_array_fills_all_but_the_trailer() {
    assert_eq!(ORPHANS_PER_BLOCK, 1020);
    assert_eq!(ORPHANS_PER_BLOCK * 4 + 4 * 4, BLKSIZE);
}

#[test]
fn the_trailer_words_sit_where_the_format_puts_them() {
    assert_eq!(AT_INO, 0);
    assert_eq!(AT_RESERVED, 4080);
    assert_eq!(AT_BLK_ADDR, 4084);
    assert_eq!(AT_BLK_COUNT, 4086);
    assert_eq!(AT_ENTRY_COUNT, 4088);
    assert_eq!(AT_CHECK_SUM, 4092);
    assert_eq!(AT_CHECK_SUM + 4, BLKSIZE);
}

// -------------------------------------------------------------- round trips

#[test]
fn a_short_list_round_trips() {
    let inos = [5u32, 9, 4000, 0x0011_2233];
    let raw = encode(&inos, 1, 1).unwrap();
    assert_eq!(raw.len(), BLKSIZE);
    let back = decode(&raw).unwrap();
    assert_eq!(back.inos, inos.to_vec());
    assert_eq!(back.index, 1);
    assert_eq!(back.count, 1);
}

#[test]
fn the_encoded_counters_are_in_the_bytes_themselves() {
    let raw = encode(&[7u32, 8, 9], 2, 5).unwrap();
    assert_eq!(le32(&raw, AT_ENTRY_COUNT).unwrap(), 3);
    assert_eq!(u16::from_le_bytes([raw[AT_BLK_ADDR], raw[AT_BLK_ADDR + 1]]), 2);
    assert_eq!(u16::from_le_bytes([raw[AT_BLK_COUNT], raw[AT_BLK_COUNT + 1]]), 5);
    assert_eq!(le32(&raw, AT_RESERVED).unwrap(), 0);
}

#[test]
fn slots_past_the_entry_count_stay_zero() {
    let raw = encode(&[1u32, 2], 1, 1).unwrap();
    for i in 2..ORPHANS_PER_BLOCK {
        assert_eq!(le32(&raw, AT_INO + i * 4).unwrap(), 0, "slot {i}");
    }
}

#[test]
fn a_full_block_round_trips_without_touching_the_trailer() {
    let inos: Vec<u32> = (1..=ORPHANS_PER_BLOCK as u32).collect();
    let raw = encode(&inos, 3, 3).unwrap();
    // The last entry must stop one word short of the reserved field.
    assert_eq!(le32(&raw, AT_RESERVED - 4).unwrap(), ORPHANS_PER_BLOCK as u32);
    assert_eq!(le32(&raw, AT_RESERVED).unwrap(), 0);
    let back = decode(&raw).unwrap();
    assert_eq!(back.inos.len(), ORPHANS_PER_BLOCK);
    assert_eq!(back.inos[0], 1);
    assert_eq!(*back.inos.last().unwrap(), ORPHANS_PER_BLOCK as u32);
    assert_eq!(back.index, 3);
    assert_eq!(back.count, 3);
}

#[test]
fn one_entry_too_many_is_refused_rather_than_truncated() {
    let inos: Vec<u32> = (1..=ORPHANS_PER_BLOCK as u32 + 1).collect();
    assert!(encode(&inos, 1, 1).is_none());
    assert!(encode(&inos[..ORPHANS_PER_BLOCK], 1, 1).is_some());
}

#[test]
fn an_empty_block_decodes_to_nothing() {
    let raw = vec![0u8; BLKSIZE];
    let back = decode(&raw).unwrap();
    assert!(back.inos.is_empty());
    assert_eq!(back.index, 0);
    assert_eq!(back.count, 0);
}

// ------------------------------------------------------------- refusals

#[test]
fn an_entry_count_past_the_array_is_refused() {
    let mut raw = encode(&[1u32, 2, 3], 1, 1).unwrap();
    // One past what the array holds: still inside the block, so nothing
    // bounds-checks it away — the entry would be the reserved word.
    raw[AT_ENTRY_COUNT..AT_ENTRY_COUNT + 4]
        .copy_from_slice(&(ORPHANS_PER_BLOCK as u32 + 1).to_le_bytes());
    assert!(decode(&raw).is_none());
}

#[test]
fn the_largest_count_the_array_holds_is_still_accepted() {
    let mut raw = encode(&[1u32, 2, 3], 1, 1).unwrap();
    raw[AT_ENTRY_COUNT..AT_ENTRY_COUNT + 4]
        .copy_from_slice(&(ORPHANS_PER_BLOCK as u32).to_le_bytes());
    assert_eq!(decode(&raw).unwrap().inos.len(), ORPHANS_PER_BLOCK);
}

#[test]
fn an_absurd_entry_count_is_refused() {
    let mut raw = encode(&[1u32], 1, 1).unwrap();
    for bogus in [u32::MAX, 0x8000_0000, 1_000_000] {
        raw[AT_ENTRY_COUNT..AT_ENTRY_COUNT + 4].copy_from_slice(&bogus.to_le_bytes());
        assert!(decode(&raw).is_none(), "{bogus} accepted");
    }
}

#[test]
fn a_short_buffer_is_refused() {
    let raw = encode(&[1u32], 1, 1).unwrap();
    assert!(decode(&raw[..BLKSIZE - 1]).is_none());
    assert!(decode(&[]).is_none());
}

// ------------------------------------------------------------- the checksum

#[test]
fn the_checksum_word_is_written_zero() {
    let raw = encode(&[1u32, 2, 3], 1, 1).unwrap();
    assert_eq!(le32(&raw, AT_CHECK_SUM).unwrap(), 0);
    assert_eq!(decode(&raw).unwrap().check_sum, 0);
}

#[test]
fn a_stored_checksum_is_carried_through_and_never_verified() {
    // The format leaves this word alone: no writer computes it, so a reader
    // that verified it would refuse every volume in existence. It is decoded
    // so a checker can see it, and nothing more.
    let mut raw = encode(&[42u32], 1, 1).unwrap();
    raw[AT_CHECK_SUM..AT_CHECK_SUM + 4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
    let back = decode(&raw).unwrap();
    assert_eq!(back.check_sum, 0xDEAD_BEEF);
    assert_eq!(back.inos, vec![42u32]);
}

// ------------------------------------------------------------- block counts

#[test]
fn the_block_count_is_the_exact_boundary() {
    assert_eq!(blocks_for(0), 0);
    assert_eq!(blocks_for(1), 1);
    assert_eq!(blocks_for(ORPHANS_PER_BLOCK - 1), 1);
    assert_eq!(blocks_for(ORPHANS_PER_BLOCK), 1);
    assert_eq!(blocks_for(ORPHANS_PER_BLOCK + 1), 2);
    assert_eq!(blocks_for(2 * ORPHANS_PER_BLOCK), 2);
    assert_eq!(blocks_for(2 * ORPHANS_PER_BLOCK + 1), 3);
}

#[test]
fn a_list_is_split_at_the_same_boundary() {
    assert!(encode_all(&[]).is_empty());
    let one: Vec<u32> = (1..=1).collect();
    assert_eq!(encode_all(&one).len(), 1);
    let exact: Vec<u32> = (1..=ORPHANS_PER_BLOCK as u32).collect();
    let blocks = encode_all(&exact);
    assert_eq!(blocks.len(), 1);
    assert_eq!(decode(&blocks[0]).unwrap().inos.len(), ORPHANS_PER_BLOCK);
    let over: Vec<u32> = (1..=ORPHANS_PER_BLOCK as u32 + 1).collect();
    let blocks = encode_all(&over);
    assert_eq!(blocks.len(), 2);
    assert_eq!(decode(&blocks[0]).unwrap().inos.len(), ORPHANS_PER_BLOCK);
    assert_eq!(decode(&blocks[1]).unwrap().inos, vec![ORPHANS_PER_BLOCK as u32 + 1]);
}

#[test]
fn every_split_block_names_its_place_in_the_whole_list() {
    let inos: Vec<u32> = (1..=2 * ORPHANS_PER_BLOCK as u32 + 5).collect();
    let blocks = encode_all(&inos);
    assert_eq!(blocks.len(), 3);
    let mut seen: Vec<u32> = Vec::new();
    for (i, raw) in blocks.iter().enumerate() {
        let back = decode(raw).unwrap();
        assert_eq!(back.index, i as u16 + 1, "index of block {i}");
        assert_eq!(back.count, 3, "count in block {i}");
        seen.extend_from_slice(&back.inos);
    }
    assert_eq!(seen, inos);
}

// -------------------------------------------------------- pack arithmetic

#[test]
fn an_empty_list_leaves_the_pack_the_length_it_had() {
    assert_eq!(pack_start_sum(0, 0), 1);
    assert_eq!(pack_total(0, 0, LOGS), FIXED_PACK_BLOCKS);
    assert_eq!(pack_total(0, 0, LOGS), 8);
    assert_eq!(pack_total(0, 0, SHORT_LOGS), 5);
}

#[test]
fn orphan_blocks_push_both_pack_numbers_out_together() {
    for ob in 0..4u32 {
        assert_eq!(pack_start_sum(0, ob), 1 + ob);
        assert_eq!(pack_total(0, ob, LOGS), FIXED_PACK_BLOCKS + ob);
        // The gap between the head plus payload and the summaries IS the
        // orphan region; the two numbers must move by the same amount or a
        // reader takes a summary for an orphan block.
        assert_eq!(pack_total(0, ob, LOGS) - pack_start_sum(0, ob), LOGS as u32 + 1);
    }
}

#[test]
fn the_orphan_region_is_the_same_size_whatever_the_pack_keeps() {
    // A pack that parks its node logs elsewhere is shorter, but the orphan
    // blocks sit before the summaries either way, so where the summaries
    // START must not depend on how many of them there are.
    for ob in 0..4u32 {
        assert_eq!(pack_start_sum(2, ob), pack_start_sum(2, ob));
        let long = pack_total(2, ob, LOGS);
        let short = pack_total(2, ob, SHORT_LOGS);
        assert_eq!(long - short, (LOGS - SHORT_LOGS) as u32);
        assert_eq!(long - pack_start_sum(2, ob), LOGS as u32 + 1);
        assert_eq!(short - pack_start_sum(2, ob), SHORT_LOGS as u32 + 1);
    }
}

#[test]
fn the_payload_shifts_the_orphan_region_too() {
    assert_eq!(pack_start_sum(3, 2), 6);
    assert_eq!(pack_total(3, 2, LOGS), FIXED_PACK_BLOCKS + 5);
    assert_eq!(pack_start_sum(3, 0), 4);
}

#[test]
fn the_block_count_is_recovered_from_where_the_summaries_start() {
    for payload in 0..4u32 {
        for ob in 0..4u32 {
            let start_sum = pack_start_sum(payload, ob);
            assert_eq!(blocks_in_pack(start_sum, payload), Some(ob));
        }
    }
}

#[test]
fn summaries_before_the_payload_ends_are_refused_rather_than_underflowed() {
    assert_eq!(blocks_in_pack(0, 0), None);
    assert_eq!(blocks_in_pack(2, 3), None);
    assert_eq!(blocks_in_pack(4, 3), Some(0));
}

#[test]
fn the_flag_is_set_and_cleared_by_the_same_rule() {
    assert_eq!(flag_word(0, 0) & CP_ORPHAN_PRESENT_FLAG, 0);
    assert_ne!(flag_word(0, 1) & CP_ORPHAN_PRESENT_FLAG, 0);
    // A word that already carries it must lose it when the list empties.
    assert_eq!(flag_word(CP_ORPHAN_PRESENT_FLAG, 0) & CP_ORPHAN_PRESENT_FLAG, 0);
    assert_eq!(flag_word(CP_ORPHAN_PRESENT_FLAG, 4), CP_ORPHAN_PRESENT_FLAG);
    // Nothing else in the word moves.
    let other = 0xFFFF_FFFFu32 & !CP_ORPHAN_PRESENT_FLAG;
    assert_eq!(flag_word(other, 0), other);
    assert_eq!(flag_word(other, 1), other | CP_ORPHAN_PRESENT_FLAG);
}

#[test]
fn the_cap_is_what_is_left_of_a_segment() {
    assert_eq!(max_orphans(512, 0), (512 - 8) as u64 * ORPHANS_PER_BLOCK as u64);
    assert_eq!(max_orphans(512, 3), (512 - 11) as u64 * ORPHANS_PER_BLOCK as u64);
    // A geometry with no room left parks nothing rather than wrapping.
    assert_eq!(max_orphans(8, 0), 0);
    assert_eq!(max_orphans(4, 0), 0);
    assert_eq!(max_orphans(9, 0), ORPHANS_PER_BLOCK as u64);
    // The cap must be exactly the blocks the LONGEST pack could still spend:
    // a list sized against a short pack would not fit the unmount that has to
    // write it out.
    let ob = blocks_for(max_orphans(512, 0) as usize);
    assert_eq!(pack_total(0, ob, LOGS), 512);
    assert!(pack_total(0, ob, SHORT_LOGS) < 512);
}
