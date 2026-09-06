use super::*;

// Wine 10.20 server/winstation.c set_thread_desktop: typed handle with access 0,
// exact station check before busy; selecting the same desktop remains legal.
#[test]
fn selected_identity_needs_no_root_and_does_not_amplify_handle_access() {
    let table = NtHandleTable::new();
    let station = NtObject::new(NtObjectType::WindowStation, 91001);
    let desktop = NtObject::new_desktop(91002, station.clone()).unwrap();
    let handle = table.insert(desktop.clone(), 0).unwrap();
    let mut thread = ThreadDesktop::default();
    assert_eq!(thread.identity(&station).err(), Some(DesktopError::NotAttached));
    thread.select_handle(&table, &station, handle, false).unwrap();
    thread.select_handle(&table, &station, handle, true).unwrap();
    assert!(Arc::ptr_eq(&thread.identity(&station).unwrap(), &desktop));
    assert_eq!(table.access_and_handle_count(handle), Some((0, 1)));
    assert_eq!(desktop.desktop().unwrap().root().err(), Some(DesktopError::MissingRoot));
}

#[test]
fn equal_numeric_station_is_not_authority_and_rejection_preserves_membership() {
    let table = NtHandleTable::new();
    let station = NtObject::new(NtObjectType::WindowStation, 91003);
    let impostor = NtObject::new(NtObjectType::WindowStation, 91003);
    let a = NtObject::new_desktop(91004, station.clone()).unwrap();
    let b = NtObject::new_desktop(91005, impostor.clone()).unwrap();
    let ah = table.insert(a.clone(), 0).unwrap(); let bh = table.insert(b, 0).unwrap();
    let mut thread = ThreadDesktop::default();
    thread.select_handle(&table, &station, ah, false).unwrap();
    assert_eq!(thread.select_handle(&table, &station, bh, true), Err(DesktopError::WrongStation));
    assert_eq!(thread.identity(&impostor).err(), Some(DesktopError::WrongStation));
    assert!(Arc::ptr_eq(&thread.identity(&station).unwrap(), &a));
}

#[test]
fn stale_wrong_type_and_busy_handles_cannot_replace_identity() {
    let table = NtHandleTable::new();
    let station = NtObject::new(NtObjectType::WindowStation, 91006);
    let a = NtObject::new_desktop(91007, station.clone()).unwrap();
    let b = NtObject::new_desktop(91008, station.clone()).unwrap();
    let ah = table.insert(a.clone(), 0).unwrap(); let bh = table.insert(b, 0).unwrap();
    let wrong = table.insert(station.clone(), 0).unwrap();
    let mut thread = ThreadDesktop::default();
    thread.select_handle(&table, &station, ah, false).unwrap();
    assert_eq!(thread.select_handle(&table, &station, wrong, true), Err(DesktopError::WrongType));
    assert_eq!(thread.select_handle(&table, &station, bh, true), Err(DesktopError::Busy));
    table.close(bh);
    assert_eq!(thread.select_handle(&table, &station, bh, false), Err(DesktopError::NotAttached));
    assert!(Arc::ptr_eq(&thread.identity(&station).unwrap(), &a));
}
