use super::*;

#[test]
fn desktop_publication_reuses_canonical_namespace_identity_and_checks_parent() {
    let station=NtObject::new(NtObjectType::WindowStation,1001);
    let path="\\Windows\\desktop_fixture_station";
    assert_eq!(publish_window_station(path,station.clone()).unwrap().1,NamedObjectState::Created);
    let first=NtObject::new_desktop(1002,station.clone()).unwrap();
    let name="\\Windows\\desktop_fixture_station\\Default";
    assert_eq!(publish_desktop(name,first.clone()).unwrap().1,NamedObjectState::Created);
    let second=NtObject::new_desktop(1003,station.clone()).unwrap();
    let (found,state)=publish_desktop("\\windows\\DESKTOP_FIXTURE_STATION\\default",second).unwrap();
    assert_eq!(state,NamedObjectState::Existing);assert!(Arc::ptr_eq(&found,&first));
    assert!(Arc::ptr_eq(&lookup_object(name,NtObjectType::Desktop).unwrap(),&first));
    let wrong=NtObject::new_desktop(1004,NtObject::new(NtObjectType::WindowStation,1001)).unwrap();
    assert!(matches!(publish_desktop(name,wrong),Err(DesktopPublishError::WrongStation)));
    assert!(matches!(publish_desktop("\\Windows\\absent_station\\Default",first.clone()),Err(DesktopPublishError::ParentMissing)));
    assert!(matches!(publish_desktop("\\Windows\\..\\Default",first),Err(DesktopPublishError::InvalidPath)));
}
