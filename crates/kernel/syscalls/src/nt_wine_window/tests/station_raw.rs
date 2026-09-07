//! Window-station and desktop admission, access widening and the record layouts.
use super::*;

#[test]
fn the_family_claims_exactly_its_own_ordinals() {
    for ordinal in [CLOSE_DESKTOP, CLOSE_WINDOW_STATION, CREATE_DESKTOP_EX, CREATE_WINDOW_STATION,
        BUILD_NAME_LIST, GET_OBJECT_INFORMATION, GET_PROCESS_WINDOW_STATION, GET_THREAD_DESKTOP,
        OPEN_DESKTOP, OPEN_INPUT_DESKTOP, OPEN_WINDOW_STATION, SET_OBJECT_INFORMATION,
        SET_PROCESS_WINDOW_STATION, SET_THREAD_DESKTOP, SWITCH_DESKTOP] {
        assert!(claims(ordinal), "{ordinal:#x}");
    }
    assert!(!claims(0x1351));
    assert!(!claims(0));
}

#[test]
fn a_desktop_open_always_carries_the_read_and_write_rights() {
    assert_eq!(desktop_access(0), DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS);
    assert_eq!(desktop_access(0x1000) & 0x1000, 0x1000);
    assert_eq!(desktop_access(DESKTOP_READOBJECTS), DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS);
}

#[test]
fn a_name_longer_than_the_addressable_length_is_refused() {
    assert!(name_length_ok(0));
    assert!(name_length_ok((MAX_OBJECT_NAME * 2 - 2) as u16));
    assert!(!name_length_ok((MAX_OBJECT_NAME * 2) as u16));
}

#[test]
fn a_desktop_creation_refuses_a_display_device_name() {
    assert!(!admit_desktop_creation(2, 0, 0));
    assert!(admit_desktop_creation(0, 0, 0));
}

#[test]
fn a_display_mode_needs_the_virtual_desktop_request() {
    const DF_WINE_VIRTUAL_DESKTOP: u32 = 0x8000_0000;
    assert!(!admit_desktop_creation(0, 0x1000, 0));
    assert!(admit_desktop_creation(0, 0x1000, DF_WINE_VIRTUAL_DESKTOP));
}

#[test]
fn each_object_answers_its_own_type_name_with_a_terminator() {
    assert_eq!(type_name(true), &DESKTOP_TYPE_NAME[..]);
    assert_eq!(type_name(false), &STATION_TYPE_NAME[..]);
    assert_eq!(*DESKTOP_TYPE_NAME.last().unwrap(), 0);
    assert_eq!(*STATION_TYPE_NAME.last().unwrap(), 0);
}

#[test]
fn only_the_flags_name_and_type_classes_are_answerable() {
    assert!(queryable(UOI_FLAGS) && queryable(UOI_NAME) && queryable(UOI_TYPE));
    assert!(!queryable(UOI_USER_SID));
    assert!(!queryable(0));
}

#[test]
fn a_short_buffer_reports_overflow_for_flags_and_an_insufficient_buffer_otherwise() {
    assert_eq!(short_buffer_error(UOI_FLAGS), ERROR_BUFFER_OVERFLOW);
    assert_eq!(short_buffer_error(UOI_NAME), ERROR_INSUFFICIENT_BUFFER);
    assert_eq!(short_buffer_error(UOI_TYPE), ERROR_INSUFFICIENT_BUFFER);
}

#[test]
fn only_the_flags_class_is_settable_and_only_with_a_whole_record() {
    assert!(settable(UOI_FLAGS, USEROBJECTFLAGS_BYTES));
    assert!(!settable(UOI_FLAGS, USEROBJECTFLAGS_BYTES - 1));
    assert!(!settable(UOI_NAME, USEROBJECTFLAGS_BYTES));
}

#[test]
fn the_records_keep_their_field_order() {
    assert_eq!((OBJECT_ATTRIBUTES_ROOT, OBJECT_ATTRIBUTES_NAME, OBJECT_ATTRIBUTES_FLAGS), (8, 16, 24));
    assert_eq!((USEROBJECTFLAGS_INHERIT, USEROBJECTFLAGS_FLAGS), (0, 8));
    assert_eq!(ERROR_FILENAME_EXCED_RANGE, 206);
    assert_eq!(ERROR_INVALID_PARAMETER, 87);
}
