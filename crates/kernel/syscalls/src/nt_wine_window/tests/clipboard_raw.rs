//! Clipboard ordinal admission and the two parameter-record layouts.
use super::*;

#[test]
fn the_family_claims_exactly_its_own_ordinals() {
    for ordinal in [ADD_FORMAT_LISTENER, REMOVE_FORMAT_LISTENER, CHANGE_CLIPBOARD_CHAIN, COUNT_FORMATS,
        EMPTY_CLIPBOARD, ENUM_FORMATS, GET_DATA, SET_DATA, GET_FORMAT_NAME, GET_OWNER, GET_VIEWER,
        SET_VIEWER, GET_SEQUENCE_NUMBER, GET_OPEN_WINDOW, GET_PRIORITY_FORMAT, GET_UPDATED_FORMATS,
        IS_FORMAT_AVAILABLE] {
        assert!(claims(ordinal), "{ordinal:#x}");
    }
    // The open and close ordinals belong to the transaction entry, not here.
    assert!(!claims(0x1351));
    assert!(!claims(0x14c2));
    assert!(!claims(0x0000));
}

#[test]
fn the_updated_formats_query_needs_somewhere_to_report_the_count() {
    assert_eq!(updated_formats_capacity(0x1000, 4, 0), None);
    assert_eq!(updated_formats_capacity(0x1000, 4, 0x2000), Some(4));
}

#[test]
fn a_measuring_call_passes_no_buffer_and_therefore_takes_no_formats() {
    assert_eq!(updated_formats_capacity(0, 8, 0x2000), Some(0));
}

#[test]
fn a_stored_format_fits_a_measuring_call_and_only_a_large_enough_buffer() {
    assert!(fits(100, 0));
    assert!(fits(100, 100));
    assert!(!fits(101, 100));
    assert!(fits(0, 1));
}

#[test]
fn the_parameter_records_keep_their_field_order() {
    assert_eq!((GET_PARAMS_DATA, GET_PARAMS_SIZE, GET_PARAMS_DATA_SIZE, GET_PARAMS_SEQNO), (0, 8, 16, 24));
    assert_eq!((SET_PARAMS_DATA, SET_PARAMS_SIZE, SET_PARAMS_CACHE_ONLY, SET_PARAMS_SEQNO), (0, 8, 16, 20));
}

#[test]
fn the_transfer_and_priority_bounds_are_the_ones_the_wiring_applies() {
    assert_eq!(MAX_FORMAT_BYTES, 64 * 1024 * 1024);
    assert_eq!(MAX_PRIORITY_FORMATS, 4096);
}
