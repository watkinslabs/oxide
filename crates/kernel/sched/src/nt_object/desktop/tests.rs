use super::*;
use crate::pid::PidIdentity;

fn process() -> Arc<ThreadGroup> { Arc::new(ThreadGroup::new(Arc::new(PidIdentity::new(71)))) }
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
fn desktop_root_is_single_real_owner_reference_not_numeric_alias() {
    let object=NtObject::new_desktop(2,station(1)).unwrap();let desktop=object.desktop().unwrap();
    let owner=process();let other=process();
    assert_eq!(desktop.publish_root(&owner,0),Err(DesktopError::InvalidWindow));
    desktop.publish_root(&owner,1).unwrap();desktop.publish_root(&owner,1).unwrap();
    assert_eq!(desktop.publish_root(&other,1),Err(DesktopError::RootOccupied));
    assert!(!desktop.clear_root(&other,1));assert!(!desktop.clear_root(&owner,2));
    let root=desktop.root().unwrap();let (resolved,hwnd)=root.resolve().unwrap();
    assert!(Arc::ptr_eq(&resolved,&owner));assert_eq!(hwnd,1);drop(resolved);
    assert!(desktop.clear_root(&owner,1));assert!(desktop.root().is_err());
    drop(owner);assert!(root.resolve().is_none());
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
fn desktop_zero_resolution_requires_membership_and_preserves_root_process() {
    let station=station(1);let owner=process();
    let desktop=NtObject::new_desktop(2,station.clone()).unwrap();
    let mut thread=ThreadDesktop::default();
    assert!(matches!(thread.resolve_root(&station),Err(DesktopError::NotAttached)));
    thread.select(&station,desktop.clone(),false).unwrap();
    assert!(matches!(thread.resolve_root(&station),Err(DesktopError::MissingRoot)));
    desktop.desktop().unwrap().publish_root(&owner,1).unwrap();
    let (resolved,hwnd)=thread.resolve_root(&station).unwrap();
    assert!(Arc::ptr_eq(&resolved,&owner));assert_eq!(hwnd,1);drop(resolved);
    assert!(matches!(thread.resolve_root(&super::tests::station(1)),Err(DesktopError::WrongStation)));
    drop(owner);assert!(matches!(thread.resolve_root(&station),Err(DesktopError::MissingRoot)));
}

#[test]
fn checked_root_publication_drops_root_lock_before_gui_validation_and_rolls_back_race() {
    let object=NtObject::new_desktop(2,station(1)).unwrap();let desktop=object.desktop().unwrap();let owner=process();
    let mut calls=0;
    assert_eq!(desktop.publish_root_checked(&owner,1,|| {
        calls+=1;let _snapshot=desktop.root();calls==1
    }),Err(DesktopError::InvalidWindow));
    assert_eq!(calls,2);assert!(desktop.root().is_err());
    desktop.publish_root_checked(&owner,1,||true).unwrap();assert!(desktop.root().is_ok());
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
