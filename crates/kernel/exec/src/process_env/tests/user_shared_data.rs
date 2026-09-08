use super::*;

/// The page is exactly one frame and its published fields land where the
/// layout says, so a stub reading an absolute offset reads what it expects.
#[test]
fn the_page_is_one_frame_and_carries_the_published_version_fields() {
    let page = page_bytes().expect("the shared page must build");
    assert_eq!(page.len(), USER_SHARED_DATA_BYTES);
    assert_eq!(&page[NT_SYSTEM_ROOT_OFF..NT_SYSTEM_ROOT_OFF + 4], &[b'C', 0, b':', 0]);
    assert_eq!(u32::from_le_bytes(page[NT_MAJOR_VERSION_OFF..NT_MAJOR_VERSION_OFF + 4].try_into().unwrap()), 10);
    assert_eq!(u32::from_le_bytes(page[NT_MINOR_VERSION_OFF..NT_MINOR_VERSION_OFF + 4].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(page[NT_BUILD_NUMBER_OFF..NT_BUILD_NUMBER_OFF + 4].try_into().unwrap()), NT_BUILD_NUMBER);
}

/// The decision this module exists for: a stock system-service stub tests one
/// byte of this page and takes the architectural syscall instruction only
/// while that byte's low bit is clear. The kernel owns the syscall
/// instruction, so the byte stays clear and no user-mode dispatcher is
/// reached. Setting it would silently route every service call through an
/// indirect call this kernel does not publish.
#[test]
fn a_stock_service_stub_reads_this_page_and_takes_the_architectural_entry() {
    const SHIPPED_STUB: [u8; pe::ntdll::stub::SERVICE_STUB_BYTES] = [
        0x4c, 0x8b, 0xd1,
        0xb8, 0x06, 0x00, 0x00, 0x00,
        0xf6, 0x04, 0x25, 0x08, 0x03, 0xfe, 0x7f, 0x01,
        0x75, 0x03,
        0x0f, 0x05,
        0xc3,
    ];
    let stub = pe::ntdll::stub::decode(&SHIPPED_STUB).expect("the shipped stub body must decode");
    // The stub names an absolute address; it must fall inside this page, and
    // the byte it lands on must leave it on the architectural entry.
    let offset = stub.flag_address.checked_sub(USER_SHARED_DATA_BASE).expect("the flag is inside the shared page");
    assert!((offset as usize) < USER_SHARED_DATA_BYTES);
    assert_eq!(offset as usize, SYSTEM_CALL_OFF);
    let page = page_bytes().expect("the shared page must build");
    assert!(pe::ntdll::stub::takes_architectural_entry(page[offset as usize]));
}

/// Every byte of the field, not only the tested bit: a stale write anywhere in
/// the word would be read as a set flag by a stub that tests a different bit.
#[test]
fn the_whole_system_call_field_is_the_architectural_value() {
    let page = page_bytes().expect("the shared page must build");
    for byte in &page[SYSTEM_CALL_OFF..SYSTEM_CALL_OFF + 4] {
        assert!(pe::ntdll::stub::takes_architectural_entry(*byte), "byte {byte:#x} in the field selects a dispatcher");
    }
}

/// A running image asks whether a processor feature is present by indexing the
/// page's feature array directly; an unpublished array answers "absent" for
/// every query, including the extensions the instruction set requires.
#[test]
fn the_page_publishes_the_processor_feature_vector_it_is_indexed_for() {
    use super::processor_features::{PF_COMPARE_EXCHANGE_DOUBLE, PF_FASTFAIL_AVAILABLE, PROCESSOR_FEATURE_MAX};
    let page = page_bytes().expect("the shared page must build");
    let features = &page[PROCESSOR_FEATURES_OFF..PROCESSOR_FEATURES_OFF + PROCESSOR_FEATURE_MAX];
    assert_eq!(features, &super::processor_features::local()[..]);
    assert_eq!(features[PF_FASTFAIL_AVAILABLE], 1);
    assert_eq!(features[PF_COMPARE_EXCHANGE_DOUBLE], 1);
    assert!(features.iter().any(|byte| *byte != 0), "an all-zero vector denies every feature");
    // The array must not run past its own field into the words that follow.
    assert!(PROCESSOR_FEATURES_OFF + PROCESSOR_FEATURE_MAX <= 0x2b4);
}
