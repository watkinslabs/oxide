//! Long-name slots: built here, read back by the decoder that already
//! existed. A round trip through both is the only check that cannot pass with
//! both sides wrong in the same direction, so the ordering, the ordinals, the
//! padding and the checksum are all pinned against the reader.

use alloc::string::String;
use alloc::vec::Vec;

use crate::dirent::{checksum, parse, Entry, LongName, ShortEntry, CHARS_PER_SLOT,
                    LAST_LONG_ENTRY, MAX_LONG_SLOTS};
use crate::name::lfn::{build_slots, encode};

use syscall::errno::Errno;

const ALIAS: [u8; 11] = *b"LONGNA~1TXT";

fn short_entry() -> ShortEntry {
    ShortEntry { raw_name: ALIAS, attr: 0x20, cluster: 3, size: 0 }
}

/// Build the slots for `name` and read them straight back.
fn round_trip(name: &str) -> Option<String> {
    let encoded = encode(name).expect("encodable");
    let sum = checksum(&ALIAS);
    let mut assembler = LongName::new();
    for record in build_slots(&encoded, sum) {
        let Some(Entry::LongSlot { ordinal, last, checksum: c, chars }) = parse(&record)
            else { panic!("built record is not a long slot") };
        assembler.push(ordinal, last, c, &chars);
    }
    assembler.take(&short_entry())
}

#[test]
fn a_name_survives_the_round_trip() {
    for name in ["a", "readme", "A Long File Name.txt",
                 "exactly-thirteen", "0123456789012"] {
        assert_eq!(round_trip(name).as_deref(), Some(name), "{name}");
    }
}

/// Characters outside the basic plane are two code units, and the slots store
/// code units. A name split across a slot boundary MID-PAIR must still come
/// back whole.
#[test]
fn a_surrogate_pair_survives_being_split_across_slots() {
    // Twelve characters, then one that takes two units: the pair straddles
    // the boundary between the first slot and the second.
    let name = "123456789012\u{1F600}rest";
    assert_eq!(round_trip(name).as_deref(), Some(name));
    assert_eq!(encode(name).unwrap().len, 18, "twelve plus a pair plus four");
}

/// A name that fills its last slot exactly gets no terminator and no padding;
/// one that does not gets a single NUL and then 0xFFFF. Storing padding after
/// an exact fit makes the name one character longer on every reader.
#[test]
fn the_padding_convention_depends_on_an_exact_fit() {
    let exact = encode("0123456789012").unwrap();
    assert_eq!(exact.len, CHARS_PER_SLOT);
    assert_eq!(exact.units.len(), CHARS_PER_SLOT, "no terminator on an exact fit");

    let short = encode("012345678901").unwrap();
    assert_eq!(short.units.len(), CHARS_PER_SLOT);
    assert_eq!(short.units[12], 0x0000, "one terminator");

    let spilling = encode("01234567890123").unwrap();
    assert_eq!(spilling.units.len(), 2 * CHARS_PER_SLOT);
    assert_eq!(spilling.units[14], 0x0000);
    assert!(spilling.units[15..].iter().all(|u| *u == 0xffff), "then filler");
}

/// The run is stored backwards: the FIRST record on disk carries the LAST
/// thirteen characters and the highest ordinal, marked as the run's end.
/// A reader that meets them in order and trusts the order gets the name in
/// two halves, swapped.
#[test]
fn the_slots_are_written_in_reverse_with_the_last_one_first() {
    let encoded = encode("0123456789012ABCDEFGHIJKLM").unwrap();
    let slots = build_slots(&encoded, 0x5a);
    assert_eq!(slots.len(), 2);

    let Some(Entry::LongSlot { ordinal, last, chars, .. }) = parse(&slots[0]) else { panic!() };
    assert_eq!(ordinal, 2);
    assert!(last, "the first record on disk closes the name");
    assert_eq!(char::from_u32(u32::from(chars[0])), Some('A'));

    let Some(Entry::LongSlot { ordinal, last, chars, .. }) = parse(&slots[1]) else { panic!() };
    assert_eq!(ordinal, 1);
    assert!(!last);
    assert_eq!(char::from_u32(u32::from(chars[0])), Some('0'));
}

/// The raw ordinal byte carries the end marker in its top bit, and only on
/// the record that ends the run.
#[test]
fn only_the_first_record_carries_the_end_marker() {
    let slots = build_slots(&encode("0123456789012ABC").unwrap(), 0);
    assert_eq!(slots[0][0] & LAST_LONG_ENTRY, LAST_LONG_ENTRY);
    assert_eq!(slots[1][0] & LAST_LONG_ENTRY, 0);
}

/// Every slot repeats the checksum of the short name it belongs to. It is the
/// only thing tying the run to its entry, and a run whose checksum does not
/// match is discarded in favour of the short name.
#[test]
fn every_slot_carries_the_short_names_checksum() {
    let sum = checksum(&ALIAS);
    let slots = build_slots(&encode("0123456789012ABC").unwrap(), sum);
    assert!(slots.iter().all(|s| s[13] == sum));

    // A run built for a different short name is not this entry's name.
    let mut assembler = LongName::new();
    for record in build_slots(&encode("wrong").unwrap(), sum.wrapping_add(1)) {
        let Some(Entry::LongSlot { ordinal, last, checksum: c, chars }) = parse(&record)
            else { panic!() };
        assembler.push(ordinal, last, c, &chars);
    }
    assert_eq!(assembler.take(&short_entry()), None);
}

/// A long slot must not look like a file to a reader that does not know about
/// long names: the attribute makes it a read-only hidden system volume label,
/// and the cluster field is zero so nothing points at data.
#[test]
fn a_slot_points_at_no_data() {
    let slots = build_slots(&encode("name").unwrap(), 0);
    assert_eq!(slots[0][26], 0);
    assert_eq!(slots[0][27], 0);
    assert_eq!(slots[0][12], 0, "and the reserved byte is zero");
}

/// The ordinal is five bits and each slot holds thirteen characters, so
/// nothing longer than the two together can address is storable — accepting
/// it would write a name no reader could find again.
#[test]
fn a_name_too_long_for_the_slots_is_refused() {
    let longest: String = core::iter::repeat('x').take(255).collect();
    let encoded = encode(&longest).expect("255 is the limit, not past it");
    assert!(encoded.slots() <= usize::from(MAX_LONG_SLOTS));

    let over: String = core::iter::repeat('x').take(256).collect();
    assert_eq!(encode(&over).err(), Some(Errno::Enametoolong));

    // Counted in code units, so a name of pairs reaches the limit at half the
    // characters. That is what the format constrains, not the character count.
    let pairs: String = core::iter::repeat('\u{1F600}').take(128).collect();
    assert_eq!(encode(&pairs).err(), Some(Errno::Enametoolong));

    assert_eq!(encode("").err(), Some(Errno::Enoent));
}

/// The characters land in three runs that are NOT contiguous — the attribute,
/// the checksum and the cluster field sit between them. Writing them as one
/// block puts five of every thirteen characters over the fields a reader
/// needs to recognise the slot at all.
#[test]
fn the_characters_are_written_around_the_fields_between_them() {
    let slots = build_slots(&encode("0123456789012").unwrap(), 0);
    let r = &slots[0];
    let units: Vec<u16> = (0..5).map(|i| u16::from_le_bytes([r[1 + 2 * i], r[2 + 2 * i]]))
        .chain((0..6).map(|i| u16::from_le_bytes([r[14 + 2 * i], r[15 + 2 * i]])))
        .chain((0..2).map(|i| u16::from_le_bytes([r[28 + 2 * i], r[29 + 2 * i]])))
        .collect();
    let want: Vec<u16> = "0123456789012".encode_utf16().collect();
    assert_eq!(units, want);
}
