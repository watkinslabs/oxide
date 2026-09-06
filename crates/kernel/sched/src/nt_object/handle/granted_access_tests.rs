use super::*;

#[test]
fn an_object_the_table_never_held_grants_nothing() {
    let table = NtHandleTable::new();
    let object = NtObject::new(NtObjectType::WindowStation, 900);
    assert_eq!(table.granted_access_for(&object), None);
}

#[test]
fn granted_rights_are_the_ones_the_handle_actually_carries() {
    let table = NtHandleTable::new();
    let object = NtObject::new(NtObjectType::Desktop, 901);
    table.insert(Arc::clone(&object), 0x0000_01ff).unwrap();
    assert_eq!(table.granted_access_for(&object), Some(0x0000_01ff));
}

#[test]
fn two_handles_to_one_object_grant_the_union_of_their_rights() {
    let table = NtHandleTable::new();
    let object = NtObject::new(NtObjectType::Desktop, 902);
    table.insert(Arc::clone(&object), 0x0000_0001).unwrap();
    table.insert(Arc::clone(&object), 0x0000_0100).unwrap();
    assert_eq!(table.granted_access_for(&object), Some(0x0000_0101));
}

#[test]
fn a_distinct_object_with_equal_rights_is_not_confused_for_this_one() {
    let table = NtHandleTable::new();
    let held = NtObject::new(NtObjectType::Desktop, 903);
    let other = NtObject::new(NtObjectType::Desktop, 903);
    table.insert(Arc::clone(&held), 0x0000_00ff).unwrap();
    // Equal numeric identity is not identity: only the object this table holds
    // may report rights, or a child could inherit access to a foreign desktop.
    assert_eq!(table.granted_access_for(&held), Some(0x0000_00ff));
    assert_eq!(table.granted_access_for(&other), None);
}

#[test]
fn closing_the_last_handle_withdraws_the_rights() {
    let table = NtHandleTable::new();
    let object = NtObject::new(NtObjectType::WindowStation, 904);
    let handle = table.insert(Arc::clone(&object), 0x0000_0037).unwrap();
    assert_eq!(table.granted_access_for(&object), Some(0x0000_0037));
    table.close(handle);
    assert_eq!(table.granted_access_for(&object), None);
}
