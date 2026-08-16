//! The three controller enumerations.

use super::*;

#[test]
fn an_index_list_is_a_count_then_the_indices() {
    let v = alloc::vec![0u16, 1, 0x1234];
    let buf = encode_index_list(&v);
    assert_eq!(buf, alloc::vec![3, 0, 0, 0, 1, 0, 0x34, 0x12]);
    assert_eq!(decode_index_list(&buf), Some(v));
}

#[test]
fn an_empty_index_list_is_two_bytes() {
    let buf = encode_index_list(&[]);
    assert_eq!(buf, alloc::vec![0, 0]);
    assert_eq!(decode_index_list(&buf), Some(alloc::vec![]));
}

#[test]
fn a_count_that_disagrees_with_the_bytes_is_refused() {
    // Claims two, carries one.
    assert_eq!(decode_index_list(&[2, 0, 1, 0]), None);
    // Claims one, carries two.
    assert_eq!(decode_index_list(&[1, 0, 1, 0, 2, 0]), None);
    // No count at all.
    assert_eq!(decode_index_list(&[0]), None);
}

#[test]
fn an_extended_row_is_four_bytes() {
    let e = [ExtIndexEntry::new(0, true, 1), ExtIndexEntry::new(5, false, 3)];
    let buf = encode_ext_index_list(&e);
    assert_eq!(buf.len(), 2 + 4 * 2);
    assert_eq!(&buf[2..6], &[0, 0, MGMT_EXT_INDEX_TYPE_CONFIGURED, 1]);
    assert_eq!(&buf[6..10], &[5, 0, MGMT_EXT_INDEX_TYPE_UNCONFIGURED, 3]);
    let back = decode_ext_index_list(&buf).expect("well formed");
    assert_eq!(back, e.to_vec());
    assert!(back[0].is_configured());
    assert!(!back[1].is_configured());
}

#[test]
fn a_truncated_extended_row_is_refused() {
    // Claims one row, carries three of its four bytes.
    assert_eq!(decode_ext_index_list(&[1, 0, 0, 0, 1]), None);
    // Claims one row, carries five bytes.
    assert_eq!(decode_ext_index_list(&[1, 0, 0, 0, 1, 2, 3]), None);
}

#[test]
fn the_extended_index_event_reports_type_then_bus() {
    assert_eq!(encode_ext_index_event(true, 5),
               alloc::vec![MGMT_EXT_INDEX_TYPE_CONFIGURED, 5]);
    assert_eq!(encode_ext_index_event(false, 1),
               alloc::vec![MGMT_EXT_INDEX_TYPE_UNCONFIGURED, 1]);
}
