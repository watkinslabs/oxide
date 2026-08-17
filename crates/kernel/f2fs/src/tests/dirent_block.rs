//! Reading entries out of a dentry area.

use super::*;
use crate::dirent::Layout;
use crate::flags::*;
use crate::hash;
use crate::test_image::meta::{put16, put32};
use crate::test_image::nodes::dir::{dentry_area, ent, Ent};
use alloc::vec;
use alloc::vec::Vec;

/// A block-sized area holding `entries`.
fn area(entries: &[Ent]) -> Vec<u8> { dentry_area(&Layout::block(), entries) }

#[test]
fn an_empty_area_holds_nothing() {
    let a = vec![0u8; BLKSIZE];
    assert!(entries(&a, &Layout::block()).unwrap().is_empty());
}

#[test]
fn one_short_name_reads_back_whole() {
    let a = area(&[ent("f", 9, FT_REG_FILE)]);
    let list = entries(&a, &Layout::block()).unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].name, b"f");
    assert_eq!(list[0].ino, 9);
    assert_eq!(list[0].file_type, FT_REG_FILE);
    assert_eq!(list[0].hash, hash::name_hash(b"f"));
    assert_eq!(list[0].slot, 0);
}

#[test]
fn a_name_of_exactly_one_slot_occupies_one_slot() {
    let a = area(&[ent("12345678", 9, FT_REG_FILE), ent("next", 10, FT_REG_FILE)]);
    let list = entries(&a, &Layout::block()).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[1].slot, 1);
}

#[test]
fn a_name_one_byte_longer_takes_a_second_slot() {
    // This is the off-by-one that matters: the second slot's record holds none
    // of the name, and a walker that steps one slot reads it as an entry.
    let a = area(&[ent("123456789", 9, FT_REG_FILE), ent("next", 10, FT_REG_FILE)]);
    let list = entries(&a, &Layout::block()).unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].name, b"123456789");
    assert_eq!(list[1].slot, 2);
    assert_eq!(list[1].name, b"next");
}

#[test]
fn the_slot_count_rounds_up() {
    assert_eq!(dentry_slots(0), 0);
    assert_eq!(dentry_slots(1), 1);
    assert_eq!(dentry_slots(8), 1);
    assert_eq!(dentry_slots(9), 2);
    assert_eq!(dentry_slots(16), 2);
    assert_eq!(dentry_slots(255), 32);
}

#[test]
fn the_continuation_slots_of_a_long_name_are_marked_used_too() {
    let a = area(&[ent("123456789", 9, FT_REG_FILE)]);
    assert!(crate::dirent::layout::is_used(&a, 0));
    assert!(crate::dirent::layout::is_used(&a, 1));
    assert!(!crate::dirent::layout::is_used(&a, 2));
}

/// A long name whose CONTINUATION slot carries a stale record.
///
/// The record array and the name array are separate, so the record sitting at
/// a continuation slot holds whatever a previous, shorter entry left there.
/// The format's own walker never reads it, because it advances by the slot
/// COUNT; a walker that advances one slot at a time does.
fn area_with_stale_continuation() -> Vec<u8> {
    let mut a = area(&[ent("123456789", 9, FT_REG_FILE), ent("real", 2, FT_REG_FILE)]);
    let l = Layout::block();
    let at = l.dentry_off(1);
    // The name slot itself is the long name's own tail, so the phantom the
    // stale record describes is the single byte "9".
    put32(&mut a, at + DE_HASH_CODE, crate::hash::name_hash(b"9"));
    put32(&mut a, at + DE_INO, 777);
    put16(&mut a, at + DE_NAME_LEN, 1);
    a[at + DE_FILE_TYPE] = FT_DIR;
    a
}

#[test]
fn a_stale_record_under_a_continuation_slot_is_not_listed() {
    let out = entries(&area_with_stale_continuation(), &Layout::block()).unwrap();
    assert_eq!(out.len(), 2);
    assert_eq!(out[0].name, b"123456789");
    assert_eq!(out[1].name, b"real");
    assert!(out.iter().all(|e| e.ino != 777));
}

#[test]
fn a_stale_record_under_a_continuation_slot_is_not_found_by_name() {
    let a = area_with_stale_continuation();
    let hit = find(&a, &Layout::block(), crate::hash::name_hash(b"9"), b"9").unwrap();
    assert_eq!(hit, None);
}

#[test]
fn the_entry_after_a_long_name_is_still_reached() {
    // The walk must skip the continuation slot without skipping the next real
    // entry with it.
    let out = entries(&area_with_stale_continuation(), &Layout::block()).unwrap();
    assert_eq!(out[1].slot, 2);
}

#[test]
fn a_longest_name_reads_back_whole() {
    let long = "x".repeat(NAME_LEN);
    let a = area(&[ent(&long, 9, FT_REG_FILE)]);
    let list = entries(&a, &Layout::block()).unwrap();
    assert_eq!(list[0].name.len(), NAME_LEN);
    assert_eq!(list[0].name_str(), long);
}

#[test]
fn several_entries_read_back_in_slot_order() {
    let names = ["a", "bb", "ccc", "dddddddddd", "e"];
    let list_in: Vec<Ent> =
        names.iter().enumerate().map(|(i, n)| ent(n, 10 + i as u32, FT_REG_FILE)).collect();
    let a = area(&list_in);
    let out = entries(&a, &Layout::block()).unwrap();
    assert_eq!(out.len(), names.len());
    for (i, n) in names.iter().enumerate() {
        assert_eq!(out[i].name, n.as_bytes());
        assert_eq!(out[i].ino, 10 + i as u32);
    }
}

#[test]
fn a_free_slot_between_entries_is_skipped() {
    let mut a = area(&[ent("a", 1, FT_REG_FILE), ent("b", 2, FT_REG_FILE)]);
    a[0] &= !0b0000_0001;
    let out = entries(&a, &Layout::block()).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, b"b");
}

#[test]
fn a_used_slot_with_a_zero_length_is_skipped_by_one_slot() {
    // Advancing by the slot count would not terminate; the format leaves such
    // records behind.
    let mut a = area(&[ent("a", 1, FT_REG_FILE), ent("b", 2, FT_REG_FILE)]);
    let l = Layout::block();
    a[l.dentry_off(0) + DE_NAME_LEN] = 0;
    a[l.dentry_off(0) + DE_NAME_LEN + 1] = 0;
    let out = entries(&a, &l).unwrap();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, b"b");
}

#[test]
fn a_name_longer_than_the_format_allows_is_an_error() {
    let mut a = area(&[ent("a", 1, FT_REG_FILE)]);
    let l = Layout::block();
    a[l.dentry_off(0) + DE_NAME_LEN..l.dentry_off(0) + DE_NAME_LEN + 2]
        .copy_from_slice(&((NAME_LEN + 1) as u16).to_le_bytes());
    assert!(matches!(entries(&a, &l), Err(DirError::BadNameLen { .. })));
}

#[test]
fn a_name_whose_slots_run_past_the_area_is_an_error() {
    let l = Layout::block();
    let mut a = vec![0u8; BLKSIZE];
    let slot = l.max - 1;
    a[slot / 8] |= 1 << (slot % 8);
    a[l.dentry_off(slot) + DE_NAME_LEN..l.dentry_off(slot) + DE_NAME_LEN + 2]
        .copy_from_slice(&64u16.to_le_bytes());
    assert!(matches!(entries(&a, &l), Err(DirError::BadNameLen { slot: s, .. }) if s == slot));
}

#[test]
fn an_area_shorter_than_its_layout_is_an_error() {
    assert_eq!(entries(&[0u8; 100], &Layout::block()), Err(DirError::Truncated));
}

#[test]
fn a_layout_that_does_not_fit_is_an_error() {
    let bad = Layout::inline(8);
    assert_eq!(entries(&[0u8; 4096], &bad), Err(DirError::Truncated));
}

#[test]
fn find_matches_on_hash_and_name_together() {
    let a = area(&[ent("alpha", 1, FT_REG_FILE), ent("beta", 2, FT_DIR)]);
    let l = Layout::block();
    let hit = find(&a, &l, hash::name_hash(b"beta"), b"beta").unwrap().unwrap();
    assert_eq!(hit.ino, 2);
    assert_eq!(hit.file_type, FT_DIR);
}

#[test]
fn find_reports_nothing_for_an_absent_name() {
    let a = area(&[ent("alpha", 1, FT_REG_FILE)]);
    assert_eq!(find(&a, &Layout::block(), hash::name_hash(b"beta"), b"beta").unwrap(), None);
}

#[test]
fn find_does_not_match_a_name_whose_hash_was_computed_wrong() {
    // The hash is compared first, so a wrong hash misses a name that is there.
    let a = area(&[ent("alpha", 1, FT_REG_FILE)]);
    assert_eq!(find(&a, &Layout::block(), 0, b"alpha").unwrap(), None);
}

#[test]
fn find_does_not_match_a_prefix() {
    let a = area(&[ent("alphabet", 1, FT_REG_FILE)]);
    assert_eq!(find(&a, &Layout::block(), hash::name_hash(b"alpha"), b"alpha").unwrap(), None);
}

#[test]
fn an_inline_area_reads_with_its_own_layout() {
    let l = Layout::inline(3488);
    let a = dentry_area(&l, &[ent(".", 3, FT_DIR), ent("..", 3, FT_DIR), ent("f", 4, FT_REG_FILE)]);
    let out = entries(&a, &l).unwrap();
    assert_eq!(out.len(), 3);
    assert_eq!(out[2].name, b"f");
}

#[test]
fn an_inline_area_read_with_a_blocks_layout_does_not_agree() {
    // The two layouts differ in padding and record count; using one for the
    // other reads the wrong bytes as records.
    let inline = Layout::inline(3488);
    let a = dentry_area(&inline, &[ent("target", 42, FT_REG_FILE)]);
    let mut padded = a.clone();
    padded.resize(BLKSIZE, 0);
    let wrong = entries(&padded, &Layout::block()).unwrap_or_default();
    assert!(wrong.iter().all(|e| e.name != b"target"));
}

#[test]
fn the_type_predicates_read_the_stored_byte() {
    assert!(crate::dirent::is_dir(FT_DIR));
    assert!(!crate::dirent::is_dir(FT_REG_FILE));
    assert!(crate::dirent::known_type(FT_SYMLINK));
    assert!(!crate::dirent::known_type(FT_MAX));
}

#[test]
fn a_walk_can_stop_early() {
    let a = area(&[ent("a", 1, FT_REG_FILE), ent("b", 2, FT_REG_FILE)]);
    let mut seen = 0;
    walk(&a, &Layout::block(), |_| { seen += 1; false }).unwrap();
    assert_eq!(seen, 1);
}

#[test]
fn a_full_area_reads_every_entry() {
    let l = Layout::block();
    let all: Vec<Ent> = (0..l.max).map(|i| ent("n", i as u32 + 1, FT_REG_FILE)).collect();
    let a = dentry_area(&l, &all);
    assert_eq!(entries(&a, &l).unwrap().len(), l.max);
}
