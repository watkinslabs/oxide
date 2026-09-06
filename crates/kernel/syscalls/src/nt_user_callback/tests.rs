use super::*;

#[test]
fn the_init_builtin_classes_ordinal_matches_the_client_table_order() {
    assert_eq!(NT_USER_INIT_BUILTIN_CLASSES, 13);
    assert_eq!(NT_USER_CALL_COUNT, 256);
}

#[test]
fn the_table_is_reached_through_the_teb_then_the_peb() {
    assert_eq!(peb_pointer(0x1000), Some(0x1060));
    assert_eq!(peb_pointer(0), None);
    assert_eq!(peb_pointer(u64::MAX), None);
    assert_eq!(table_pointer(0x2000), Some(0x2058));
    assert_eq!(table_pointer(0), None);
    assert_eq!(table_pointer(u64::MAX), None);
}

#[test]
fn an_entry_is_one_pointer_per_ordinal_and_an_unpublished_table_has_none() {
    assert_eq!(entry_pointer(0x3000, 0), Some(0x3000));
    assert_eq!(entry_pointer(0x3000, NT_USER_INIT_BUILTIN_CLASSES), Some(0x3000 + 13 * 8));
    assert_eq!(entry_pointer(0, NT_USER_INIT_BUILTIN_CLASSES), None);
    assert_eq!(entry_pointer(0x3000, NT_USER_CALL_COUNT), None);
    assert_eq!(entry_pointer(u64::MAX, 1), None);
}
