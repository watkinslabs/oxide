//! The whole 32-byte record: the fields a [`ShortEntry`] does not carry, and
//! what happens to them when an encoder does not carry them either.

use crate::dirent::{encode_short, parse, Entry, Record, RecordTimes, ENTRY_BYTES};
use crate::name::flags::{CASE_LOWER_BASE, CASE_LOWER_EXT};
use crate::time::FatTime;

/// A record with every field distinct, so a swapped pair of offsets shows up.
fn filled() -> [u8; ENTRY_BYTES] {
    let mut r = [0u8; ENTRY_BYTES];
    r[..11].copy_from_slice(b"README  TXT");
    r[11] = 0x20;
    r[12] = CASE_LOWER_BASE | CASE_LOWER_EXT;
    r[13] = 137;
    r[14..16].copy_from_slice(&0x1234u16.to_le_bytes());
    r[16..18].copy_from_slice(&0x2345u16.to_le_bytes());
    r[18..20].copy_from_slice(&0x3456u16.to_le_bytes());
    r[20..22].copy_from_slice(&0x0001u16.to_le_bytes());
    r[22..24].copy_from_slice(&0x4567u16.to_le_bytes());
    r[24..26].copy_from_slice(&0x5678u16.to_le_bytes());
    r[26..28].copy_from_slice(&0x0002u16.to_le_bytes());
    r[28..32].copy_from_slice(&4096u32.to_le_bytes());
    r
}

#[test]
fn every_field_decodes_from_the_offset_that_holds_it() {
    let rec = Record::parse(&filled()).expect("a short entry");
    assert_eq!(rec.short.raw_name, *b"README  TXT");
    assert_eq!(rec.short.attr, 0x20);
    assert_eq!(rec.short.cluster, 0x0001_0002, "and the two halves are not swapped");
    assert_eq!(rec.short.size, 4096);
    assert_eq!(rec.lcase, CASE_LOWER_BASE | CASE_LOWER_EXT);
    assert!(rec.base_is_lower() && rec.ext_is_lower());
    assert_eq!(rec.times.create, FatTime { time: 0x1234, date: 0x2345, cs: 137 });
    assert_eq!(rec.times.access_date, 0x3456);
    assert_eq!(rec.times.modify, FatTime { time: 0x4567, date: 0x5678, cs: 0 });
}

/// Every byte of the record comes back, which is what makes it safe to write
/// over an entry that already exists.
#[test]
fn a_record_round_trips_byte_for_byte() {
    let bytes = filled();
    assert_eq!(Record::parse(&bytes).expect("a short entry").encode(), bytes);
}

/// The smaller encoder does NOT: it writes four fields and zeroes the rest,
/// which on an existing entry destroys both timestamps and the case bits.
/// This is why an update path has to use the record.
#[test]
fn the_short_encoder_zeroes_what_it_does_not_carry() {
    let bytes = filled();
    let Some(Entry::Short(short)) = parse(&bytes) else { panic!("a short entry") };
    let written = encode_short(&short);
    assert_eq!(&written[..12], &bytes[..12], "name, attribute and case byte survive");
    assert_eq!(written[12], 0, "no: the case byte does not");
    assert!(written[13..20].iter().all(|b| *b == 0), "and neither do the timestamps");
    assert_ne!(written, bytes);
}

/// A record is only a record. Reading timestamps out of a long-name slot
/// would take thirteen characters of somebody's filename for a date.
#[test]
fn nothing_but_a_short_entry_parses_as_one() {
    let mut long = filled();
    long[11] = 0x0f;
    assert!(Record::parse(&long).is_none(), "a long-name slot");

    let mut deleted = filled();
    deleted[0] = 0xe5;
    assert!(Record::parse(&deleted).is_none());

    let mut end = filled();
    end[0] = 0;
    assert!(Record::parse(&end).is_none());

    assert!(Record::parse(&[0u8; 8]).is_none(), "and a record too short to be one");
}

/// A record another system wrote with no timestamps at all reads as zeros
/// rather than failing, and writing it back leaves them zero.
#[test]
fn an_entry_with_no_timestamps_keeps_none() {
    let mut bytes = [0u8; ENTRY_BYTES];
    bytes[..11].copy_from_slice(b"NOTIMES TXT");
    let rec = Record::parse(&bytes).expect("a short entry");
    assert_eq!(rec.times, RecordTimes::default());
    assert_eq!(rec.encode(), bytes);
}
