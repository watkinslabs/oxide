use super::*;
use alloc::vec;

fn short_record(name: &[u8; 11], attr: u8, cluster: u32, size: u32) -> Vec<u8> {
    let mut r = vec![0u8; ENTRY_BYTES];
    r[..11].copy_from_slice(name);
    r[short::ATTR] = attr;
    r[short::CLUSTER_HI..short::CLUSTER_HI + 2].copy_from_slice(&((cluster >> 16) as u16).to_le_bytes());
    r[short::CLUSTER_LO..short::CLUSTER_LO + 2].copy_from_slice(&(cluster as u16).to_le_bytes());
    r[short::SIZE..short::SIZE + 4].copy_from_slice(&size.to_le_bytes());
    r
}

fn long_record(ordinal: u8, last: bool, checksum: u8, chars: &[u16]) -> Vec<u8> {
    let mut r = vec![0u8; ENTRY_BYTES];
    r[long::ORDINAL] = ordinal | if last { LAST_LONG_ENTRY } else { 0 };
    r[long::ATTR] = ATTR_EXT;
    r[long::CHECKSUM] = checksum;
    let mut padded = [0xFFFFu16; CHARS_PER_SLOT];
    for (i, c) in chars.iter().enumerate() { padded[i] = *c; }
    if chars.len() < CHARS_PER_SLOT { padded[chars.len()] = 0; }
    let mut at = 0;
    for (start, len) in [(long::CHARS_0, long::CHARS_0_LEN),
                         (long::CHARS_1, long::CHARS_1_LEN),
                         (long::CHARS_2, long::CHARS_2_LEN)] {
        for i in (0..len).step_by(2) {
            r[start + i..start + i + 2].copy_from_slice(&padded[at].to_le_bytes());
            at += 1;
        }
    }
    r
}

/// Slots for `name`, in ON-DISK order: reversed, the first one marked LAST.
fn slots_for(name: &str, checksum: u8) -> Vec<Vec<u8>> {
    let units: Vec<u16> = name.encode_utf16().collect();
    let count = units.len().div_ceil(CHARS_PER_SLOT);
    let mut out = Vec::new();
    for slot in (0..count).rev() {
        let start = slot * CHARS_PER_SLOT;
        let end = core::cmp::min(start + CHARS_PER_SLOT, units.len());
        out.push(long_record((slot + 1) as u8, slot + 1 == count, checksum, &units[start..end]));
    }
    out
}

const README: [u8; 11] = *b"README  TXT";

#[test]
fn a_short_entry_decodes_its_fields() {
    let r = short_record(&README, ATTR_ARCH, 0x1234_5678, 4096);
    let Some(Entry::Short(e)) = parse(&r) else { panic!("short entry") };
    assert_eq!(short_name(&e), "README.TXT");
    assert_eq!(e.cluster, 0x1234_5678, "the cluster is split across two fields");
    assert_eq!(e.size, 4096);
    assert!(!e.is_dir());
}

/// The high half of the cluster number lives in a field far from the low
/// half. Reading only the low one silently opens the wrong data on any FAT32
/// volume with more than 65535 clusters.
#[test]
fn the_cluster_number_is_assembled_from_both_halves() {
    let r = short_record(&README, 0, 0xABCD_0001, 0);
    let Some(Entry::Short(e)) = parse(&r) else { panic!() };
    assert_eq!(e.cluster, 0xABCD_0001);
    assert_ne!(e.cluster, 0x0001, "the high half is not dropped");
}

/// The two markers a scan depends on: one says stop, the other says skip.
/// Confusing them either truncates a directory or shows deleted files.
#[test]
fn the_end_and_deleted_markers_are_distinct() {
    let mut end = short_record(&README, 0, 2, 0);
    end[0] = 0x00;
    assert_eq!(parse(&end), Some(Entry::EndOfDirectory));
    let mut deleted = short_record(&README, 0, 2, 0);
    deleted[0] = DELETED_FLAG;
    assert_eq!(parse(&deleted), Some(Entry::Deleted));
}

/// A name legitimately beginning with the deleted marker's byte is stored
/// escaped. Without the escape it reads back as a different file.
#[test]
fn the_escaped_first_byte_decodes_back_to_its_real_value() {
    let mut name = *b"?ILE    TXT";
    name[0] = 0x05;
    let r = short_record(&name, 0, 2, 0);
    let Some(Entry::Short(e)) = parse(&r) else { panic!() };
    // The escape restores the BYTE; the mount's code page then says what that
    // byte means, which on the default page is a small sigma — not the
    // character of the same value, and not a UTF-8 decode of it.
    assert_eq!(short_name(&e).chars().next(), Some('\u{3c3}'),
               "the byte {DELETED_FLAG:#04x} under the default code page");
    assert!(short_name(&e).ends_with("ILE.TXT"), "and the rest of the name survives");
}

/// A name with no extension gets no trailing dot, and padding is dropped.
#[test]
fn short_names_drop_padding_and_add_a_dot_only_when_needed() {
    let bare = short_record(b"MAKEFILE   ", 0, 2, 0);
    let Some(Entry::Short(e)) = parse(&bare) else { panic!() };
    assert_eq!(short_name(&e), "MAKEFILE");
    let dir = short_record(b"SUBDIR     ", ATTR_DIR, 2, 0);
    let Some(Entry::Short(e)) = parse(&dir) else { panic!() };
    assert_eq!(short_name(&e), "SUBDIR");
    assert!(e.is_dir());
}

/// The checksum is taken over the RAW 11 bytes, padding included — not over
/// the formatted name. Taking it over the formatted name makes every long
/// name in the volume fail to match.
#[test]
fn the_checksum_is_over_the_raw_padded_name() {
    let a = checksum(&README);
    let b = checksum(b"README  TX ");
    assert_ne!(a, b, "padding participates");
    // Stable value, so a rewrite of the rotate-and-add cannot drift.
    assert_eq!(checksum(b"           "), 0x20u8.rotate_right(1).wrapping_add(0x20)
        .rotate_right(1).wrapping_add(0x20).rotate_right(1).wrapping_add(0x20)
        .rotate_right(1).wrapping_add(0x20).rotate_right(1).wrapping_add(0x20)
        .rotate_right(1).wrapping_add(0x20).rotate_right(1).wrapping_add(0x20)
        .rotate_right(1).wrapping_add(0x20).rotate_right(1).wrapping_add(0x20)
        .rotate_right(1).wrapping_add(0x20));
}

/// A long name spanning several slots assembles in the right order. The slots
/// are stored REVERSED on disk; reading them forward yields the name in
/// pieces, transposed.
#[test]
fn a_multi_slot_long_name_assembles_in_order() {
    let name = "a-rather-long-file-name-indeed.txt";
    let sum = checksum(&README);
    let mut asm = LongName::new();
    for record in slots_for(name, sum) {
        let Some(Entry::LongSlot { ordinal, last, checksum, chars }) = parse(&record) else { panic!() };
        asm.push(ordinal, last, checksum, &chars);
    }
    let Some(Entry::Short(e)) = parse(&short_record(&README, 0, 2, 0)) else { panic!() };
    assert_eq!(asm.take(&e).as_deref(), Some(name));
}

/// A name that exactly fills its slots has no terminator, and must not be
/// truncated by one character.
#[test]
fn a_name_that_exactly_fills_its_slots_keeps_every_character() {
    let name = "0123456789abc"; // exactly 13
    let sum = checksum(&README);
    let mut asm = LongName::new();
    for record in slots_for(name, sum) {
        let Some(Entry::LongSlot { ordinal, last, checksum, chars }) = parse(&record) else { panic!() };
        asm.push(ordinal, last, checksum, &chars);
    }
    let Some(Entry::Short(e)) = parse(&short_record(&README, 0, 2, 0)) else { panic!() };
    assert_eq!(asm.take(&e).as_deref(), Some(name));
}

/// THE rule a reader most often gets wrong: a short entry whose checksum does
/// not match the run is not an error. The long name is dropped and the short
/// name stands, because the run belongs to some other entry.
#[test]
fn a_checksum_mismatch_falls_back_to_the_short_name() {
    let mut asm = LongName::new();
    for record in slots_for("orphaned-long-name.txt", 0x42) {
        let Some(Entry::LongSlot { ordinal, last, checksum, chars }) = parse(&record) else { panic!() };
        asm.push(ordinal, last, checksum, &chars);
    }
    let Some(Entry::Short(e)) = parse(&short_record(&README, 0, 2, 0)) else { panic!() };
    assert_eq!(asm.take(&e), None, "the run names something else");
    assert_eq!(short_name(&e), "README.TXT", "and the short name is still readable");
}

/// A run must begin with the slot marked LAST. A directory whose tail was
/// overwritten can leave a headless run; trusting it yields a name with a
/// hole in it.
#[test]
fn a_run_without_its_last_marker_is_not_trusted() {
    let sum = checksum(&README);
    let mut asm = LongName::new();
    // Feed only the second slot of a two-slot name, which is not marked LAST.
    let records = slots_for("a-name-long-enough-to-span.txt", sum);
    let Some(Entry::LongSlot { ordinal, last, checksum, chars }) = parse(&records[1]) else { panic!() };
    assert!(!last);
    asm.push(ordinal, last, checksum, &chars);
    let Some(Entry::Short(e)) = parse(&short_record(&README, 0, 2, 0)) else { panic!() };
    assert_eq!(asm.take(&e), None);
}

/// An ordinal out of sequence restarts the assembly rather than being
/// dropped: the offending slot may itself begin a valid run, and the next
/// short entry must still get its name.
#[test]
fn an_out_of_sequence_slot_restarts_rather_than_poisons() {
    let sum = checksum(&README);
    let mut asm = LongName::new();
    // A stale slot from an abandoned name...
    let stale = slots_for("stale.txt", 0x11);
    let Some(Entry::LongSlot { ordinal, last, checksum, chars }) = parse(&stale[0]) else { panic!() };
    asm.push(ordinal, last, checksum, &chars);
    // ...followed by a complete, correct run.
    for record in slots_for("good.txt", sum) {
        let Some(Entry::LongSlot { ordinal, last, checksum, chars }) = parse(&record) else { panic!() };
        asm.push(ordinal, last, checksum, &chars);
    }
    let Some(Entry::Short(e)) = parse(&short_record(&README, 0, 2, 0)) else { panic!() };
    assert_eq!(asm.take(&e).as_deref(), Some("good.txt"), "the good run still lands");
}

/// A run claiming more slots than a name can span is refused: the ordinal
/// scales the buffer, so an absurd one would size it from untrusted bytes.
#[test]
fn an_impossible_slot_count_is_refused() {
    let mut asm = LongName::new();
    let chars = [0x41u16; CHARS_PER_SLOT];
    asm.push(MAX_LONG_SLOTS + 1, true, 0x42, &chars);
    let Some(Entry::Short(e)) = parse(&short_record(&README, 0, 2, 0)) else { panic!() };
    assert_eq!(asm.take(&e), None);
    // ...and a zero ordinal, which would name a zero-length run.
    asm.push(0, true, 0x42, &chars);
    assert_eq!(asm.take(&e), None);
}

/// Characters beyond a name's end are padded, and must not appear in it.
#[test]
fn padding_after_the_terminator_is_not_part_of_the_name() {
    let sum = checksum(&README);
    let mut asm = LongName::new();
    for record in slots_for("ab", sum) {
        let Some(Entry::LongSlot { ordinal, last, checksum, chars }) = parse(&record) else { panic!() };
        asm.push(ordinal, last, checksum, &chars);
    }
    let Some(Entry::Short(e)) = parse(&short_record(&README, 0, 2, 0)) else { panic!() };
    assert_eq!(asm.take(&e).as_deref(), Some("ab"));
}

/// Non-ASCII survives the round trip: the slots hold UTF-16 code units, and a
/// name outside the basic plane spans a surrogate pair.
#[test]
fn a_non_ascii_name_survives_the_round_trip() {
    for name in ["café-notes.txt", "日本語.txt", "emoji-🌍.txt"] {
        let sum = checksum(&README);
        let mut asm = LongName::new();
        for record in slots_for(name, sum) {
            let Some(Entry::LongSlot { ordinal, last, checksum, chars }) = parse(&record) else { panic!() };
            asm.push(ordinal, last, checksum, &chars);
        }
        let Some(Entry::Short(e)) = parse(&short_record(&README, 0, 2, 0)) else { panic!() };
        assert_eq!(asm.take(&e).as_deref(), Some(name), "{name}");
    }
}

/// A long slot is recognised by its attribute, not by its position. Reading
/// one as a short entry would show a file named from its own character bytes.
#[test]
fn a_long_slot_is_never_mistaken_for_a_file() {
    let record = long_record(1, true, 0x42, &[0x41, 0x42]);
    assert!(matches!(parse(&record), Some(Entry::LongSlot { .. })));
    // A volume label shares three of the four attribute bits but is a file.
    let label = short_record(b"MY VOLUME  ", ATTR_VOLUME, 0, 0);
    let Some(Entry::Short(e)) = parse(&label) else { panic!("a label is a short entry") };
    assert!(e.is_volume_label());
}

/// A record shorter than one entry is refused rather than read past.
#[test]
fn a_short_record_is_refused() {
    assert_eq!(parse(&[]), None);
    assert_eq!(parse(&vec![0u8; ENTRY_BYTES - 1]), None);
}

#[path = "tests/record.rs"] mod record;
