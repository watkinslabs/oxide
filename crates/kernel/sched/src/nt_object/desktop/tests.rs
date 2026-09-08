use super::*;

fn station(id: u64) -> Arc<NtObject> { NtObject::new(NtObjectType::WindowStation, id) }

#[test]
fn desktop_membership_uses_station_identity_before_busy_and_retains_default() {
    // Wine 10.20 server/winstation.c set_thread_desktop checks the station
    // object before desktop_users, and permits reselection of the same object.
    let station=station(1);let foreign=super::tests::station(1);
    let first=NtObject::new_desktop(2,station.clone()).unwrap();
    let second=NtObject::new_desktop(3,station.clone()).unwrap();
    let mut member=ThreadDesktop::default();member.select(&station,first.clone(),false).unwrap();
    assert_eq!(member.select(&foreign,second.clone(),true),Err(DesktopError::WrongStation));
    assert_eq!(member.select(&station,second.clone(),true),Err(DesktopError::Busy));
    assert!(Arc::ptr_eq(&member.object().unwrap(),&first));
    member.select(&station,first.clone(),true).unwrap();
    let mut child=ThreadDesktop::default();child.inherit_default(&member);
    member.select(&station,second.clone(),false).unwrap();child.inherit_default(&member);
    assert!(Arc::ptr_eq(&child.object().unwrap(),&first));
    assert!(Arc::ptr_eq(&member.object().unwrap(),&second));
}

#[test]
fn one_desktop_has_one_desktop_window_that_every_attached_process_shares() {
    let object=NtObject::new_desktop(2,station(1)).unwrap();let desktop=object.desktop().unwrap();
    assert_eq!(desktop.publish_root(0),Err(DesktopError::InvalidWindow));
    assert_eq!(desktop.publish_root(7).unwrap(),7);
    // The second process to attach is answered with the established window
    // rather than refused: the previous contract recorded the first
    // process's own top-level window as the desktop and rejected every
    // later one, so the second process resolved a handle it did not own.
    assert_eq!(desktop.publish_root(9).unwrap(),7);
    assert_eq!(desktop.root().unwrap().hwnd(),7);
    assert!(!desktop.clear_root(9));
    assert!(desktop.clear_root(7));assert!(desktop.root().is_err());
}

#[test]
fn desktop_handles_share_payload_and_wrong_object_types_are_rejected() {
    let station=station(1);let desktop=NtObject::new_desktop(2,station.clone()).unwrap();
    let a=super::super::NtHandleTable::new();let b=super::super::NtHandleTable::new();
    let ha=a.insert(desktop.clone(),1).unwrap();let hb=b.insert(desktop.clone(),1).unwrap();
    assert!(Arc::ptr_eq(&a.get(ha,1).unwrap().desktop().unwrap(),&b.get(hb,1).unwrap().desktop().unwrap()));
    let event=NtObject::new(NtObjectType::Event,1);
    assert!(matches!(NtObject::new_desktop(3,event.clone()),Err(DesktopError::WrongType)));
    assert_eq!(ThreadDesktop::default().select(&station,event,false),Err(DesktopError::WrongType));
}

#[test]
fn desktop_zero_resolution_requires_membership_and_answers_the_desktops_own_window() {
    let station=station(1);
    let desktop=NtObject::new_desktop(2,station.clone()).unwrap();
    let mut thread=ThreadDesktop::default();
    assert!(matches!(thread.resolve_root(&station),Err(DesktopError::NotAttached)));
    thread.select(&station,desktop.clone(),false).unwrap();
    assert!(matches!(thread.resolve_root(&station),Err(DesktopError::MissingRoot)));
    desktop.desktop().unwrap().publish_root(11).unwrap();
    assert_eq!(thread.resolve_root(&station).unwrap(),11);
    assert!(matches!(thread.resolve_root(&super::tests::station(1)),Err(DesktopError::WrongStation)));
}

/// Two processes attached to one desktop see one desktop window, and neither
/// sees a handle belonging to the other.
#[test]
fn a_second_process_resolves_the_same_desktop_window_as_the_first() {
    let station=station(1);
    let desktop=NtObject::new_desktop(2,station.clone()).unwrap();
    let mut first=ThreadDesktop::default();let mut second=ThreadDesktop::default();
    first.select(&station,desktop.clone(),false).unwrap();
    second.select(&station,desktop.clone(),false).unwrap();
    desktop.desktop().unwrap().publish_root(21).unwrap();
    assert_eq!(first.resolve_root(&station).unwrap(),second.resolve_root(&station).unwrap());
    assert_eq!(second.resolve_root(&station).unwrap(),21);
}

#[test]
fn thread_spawn_hook_inherits_process_default_not_switched_parent() {
    // Wine 10.20 server/thread.c:570-576 selects process->desktop;
    // server/winstation.c:set_thread_default_desktop preserves existing membership.
    let parent=crate::Task::new(99171,"desktop-parent",crate::SchedClass::Normal {weight:1024});
    let mut child=crate::Task::new(99172,"desktop-child",crate::SchedClass::Normal {weight:1024});
    let station=station(1);let desktop=NtObject::new_desktop(2,station.clone()).unwrap();
    let switched=NtObject::new_desktop(3,station.clone()).unwrap();
    parent.thread_group.nt_default_desktop.lock().select(&station,desktop.clone(),false).unwrap();
    parent.nt_desktop.lock().select(&station,switched.clone(),false).unwrap();
    assert!(!ThreadDesktop::inherit_thread(&parent,&child));
    child.thread_group=parent.thread_group.clone();assert!(ThreadDesktop::inherit_thread(&parent,&child));
    assert!(Arc::ptr_eq(&child.nt_desktop.lock().object().unwrap(),&desktop));
    child.nt_desktop.lock().select(&station,switched.clone(),false).unwrap();
    assert!(ThreadDesktop::inherit_thread(&parent,&child));
    assert!(Arc::ptr_eq(&child.nt_desktop.lock().object().unwrap(),&switched));
    let detached=child.nt_desktop.lock().detach();assert!(detached.is_some());
    assert!(child.nt_desktop.lock().object().is_none());
    assert!(Arc::ptr_eq(&parent.nt_desktop.lock().object().unwrap(),&switched));
    assert!(Arc::ptr_eq(&parent.thread_group.nt_default_desktop.lock().object().unwrap(),&desktop));
}

#[test]
fn absent_process_default_does_not_fall_back_to_parent_selection() {
    let parent=crate::Task::new(99173,"desktop-parent",crate::SchedClass::Normal {weight:1024});
    let mut child=crate::Task::new(99174,"desktop-child",crate::SchedClass::Normal {weight:1024});
    child.thread_group=parent.thread_group.clone();
    let station=station(1);let desktop=NtObject::new_desktop(2,station.clone()).unwrap();
    parent.nt_desktop.lock().select(&station,desktop,false).unwrap();
    assert!(ThreadDesktop::inherit_thread(&parent,&child));
    assert!(child.nt_desktop.lock().object().is_none());
}
