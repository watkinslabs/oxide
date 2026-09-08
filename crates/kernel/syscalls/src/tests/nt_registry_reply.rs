//! Reply layouts and buffer ladders of the NT registry query services.

use super::*;

const STATUS_SUCCESS: u64 = 0;
const STATUS_BUFFER_OVERFLOW: u64 = 0x8000_0005;
const STATUS_BUFFER_TOO_SMALL: u64 = 0xc000_0023;
const NAME: [u16; 2] = [0x0041, 0x0042];

#[test]
fn every_documented_information_class_is_admitted_and_no_other() {
    for (raw, class) in [(0, ValueClass::Basic), (1, ValueClass::Full), (2, ValueClass::Partial), (3, ValueClass::PartialAlign64)] {
        assert_eq!(ValueClass::from_raw(raw), Some(class));
    }
    assert_eq!(ValueClass::from_raw(4), None);
    for (raw, class) in [(0, KeyClass::Basic), (1, KeyClass::Node), (2, KeyClass::Full), (3, KeyClass::Name), (4, KeyClass::Cached)] {
        assert_eq!(KeyClass::from_raw(raw), Some(class));
    }
    assert_eq!(KeyClass::from_raw(5), None);
}

#[test]
fn value_headers_are_the_windows_field_offsets() {
    assert_eq!(ValueClass::Basic.header_bytes(), 12);
    assert_eq!(ValueClass::Full.header_bytes(), 20);
    assert_eq!(ValueClass::Partial.header_bytes(), 12);
    // This class drops the title index, so its data starts two words in.
    assert_eq!(ValueClass::PartialAlign64.header_bytes(), 8);
}

#[test]
fn key_headers_are_the_windows_field_offsets() {
    assert_eq!(KeyClass::Basic.header_bytes(), 16);
    assert_eq!(KeyClass::Node.header_bytes(), 24);
    // Nine counters after the write time - a record claiming 48 would place
    // the class text past its own start and over-report every query.
    assert_eq!(KeyClass::Full.header_bytes(), 44);
    assert_eq!(KeyClass::Name.header_bytes(), 4);
    assert_eq!(KeyClass::Cached.header_bytes(), 40);
}

#[test]
fn a_basic_value_query_reports_the_name_and_never_the_data() {
    let record = value_query_record(ValueClass::Basic, &NAME, 4, &[7, 8, 9]);
    assert_eq!(record.result_len(), 16);
    assert_eq!(&record.bytes()[0..4], &[0, 0, 0, 0]);
    assert_eq!(&record.bytes()[4..8], &4u32.to_le_bytes());
    assert_eq!(&record.bytes()[8..12], &4u32.to_le_bytes());
    assert_eq!(&record.bytes()[12..], &[0x41, 0, 0x42, 0]);
}

#[test]
fn a_full_value_query_places_the_data_directly_after_the_name() {
    let record = value_query_record(ValueClass::Full, &NAME, 1, b"xy");
    assert_eq!(&record.bytes()[8..12], &24u32.to_le_bytes());
    assert_eq!(&record.bytes()[12..16], &2u32.to_le_bytes());
    assert_eq!(&record.bytes()[16..20], &4u32.to_le_bytes());
    assert_eq!(&record.bytes()[24..], b"xy");
    assert_eq!(record.result_len(), 26);
}

#[test]
fn the_partial_classes_carry_the_data_alone() {
    let partial = value_query_record(ValueClass::Partial, &NAME, 3, b"abcd");
    assert_eq!(partial.bytes(), &[0, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, b'a', b'b', b'c', b'd']);
    let aligned = value_query_record(ValueClass::PartialAlign64, &NAME, 3, b"abcd");
    assert_eq!(aligned.bytes(), &[3, 0, 0, 0, 4, 0, 0, 0, b'a', b'b', b'c', b'd']);
}

#[test]
fn value_enumeration_has_no_sixty_four_bit_aligned_class() {
    assert_eq!(value_enum_record(ValueClass::PartialAlign64, &NAME, 1, b"z"), None);
    assert!(value_enum_record(ValueClass::Basic, &NAME, 1, b"z").is_some());
}

#[test]
fn a_short_buffer_still_receives_what_fits_and_a_length_below_the_header_is_refused() {
    let record = value_query_record(ValueClass::Partial, &NAME, 3, b"abcd");
    assert_eq!(deliver(&record, 16, Ladder::HeaderIsMandatory), Delivery { prefix: 16, status: STATUS_SUCCESS });
    assert_eq!(deliver(&record, 14, Ladder::HeaderIsMandatory), Delivery { prefix: 14, status: STATUS_BUFFER_OVERFLOW });
    assert_eq!(deliver(&record, 8, Ladder::HeaderIsMandatory), Delivery { prefix: 8, status: STATUS_BUFFER_TOO_SMALL });
    assert_eq!(deliver(&record, 20, Ladder::HeaderIsMandatory), Delivery { prefix: 16, status: STATUS_SUCCESS });
}

#[test]
fn value_enumeration_never_refuses_a_buffer_below_the_header() {
    let record = value_enum_record(ValueClass::Partial, &NAME, 3, b"abcd").unwrap();
    // The enumeration service has one short-buffer status only; answering a
    // four-byte buffer as too small would fail a caller that sizes its buffer
    // from the reported length after a first, deliberately tiny, attempt.
    assert_eq!(deliver(&record, 4, Ladder::OverflowOnly), Delivery { prefix: 4, status: STATUS_BUFFER_OVERFLOW });
    assert_eq!(deliver(&record, 0, Ladder::OverflowOnly), Delivery { prefix: 0, status: STATUS_BUFFER_OVERFLOW });
}

#[test]
fn the_counting_key_classes_report_the_name_length_without_the_name() {
    let facts = KeyFacts { subkeys: 2, max_subkey: 10, values: 3, max_value_name: 12, max_value_data: 40 };
    let full = key_record(KeyClass::Full, &NAME, facts);
    assert_eq!(full.result_len(), 44);
    assert_eq!(&full.bytes()[12..16], &u32::MAX.to_le_bytes());
    assert_eq!(&full.bytes()[16..20], &0u32.to_le_bytes());
    assert_eq!(&full.bytes()[20..24], &2u32.to_le_bytes());
    assert_eq!(&full.bytes()[24..28], &10u32.to_le_bytes());
    assert_eq!(&full.bytes()[32..36], &3u32.to_le_bytes());
    assert_eq!(&full.bytes()[36..40], &12u32.to_le_bytes());
    assert_eq!(&full.bytes()[40..44], &40u32.to_le_bytes());
    let cached = key_record(KeyClass::Cached, &NAME, facts);
    assert_eq!(cached.result_len(), 40);
    assert_eq!(&cached.bytes()[32..36], &4u32.to_le_bytes());
}

#[test]
fn the_name_carrying_key_classes_append_the_name_after_their_header() {
    for class in [KeyClass::Basic, KeyClass::Node, KeyClass::Name] {
        let record = key_record(class, &NAME, KeyFacts::default());
        assert!(class.carries_name());
        assert_eq!(record.result_len(), class.header_bytes() + 4);
        assert_eq!(&record.bytes()[class.header_bytes()..], &[0x41, 0, 0x42, 0]);
    }
    assert!(!KeyClass::Full.carries_name());
    assert!(!KeyClass::Cached.carries_name());
}

#[test]
fn a_key_without_class_text_reports_an_absent_class_offset() {
    let node = key_record(KeyClass::Node, &NAME, KeyFacts::default());
    assert_eq!(&node.bytes()[12..16], &u32::MAX.to_le_bytes());
    assert_eq!(&node.bytes()[16..20], &0u32.to_le_bytes());
    assert_eq!(&node.bytes()[20..24], &4u32.to_le_bytes());
}

#[test]
fn the_longest_admitted_value_name_matches_the_registry_limit() {
    assert_eq!(MAX_VALUE_NAME_BYTES, 32766);
}
