use super::*;

#[test]
fn bootstrap_reopens_same_desktop_for_two_processes_and_preserves_other_handles() {
    let a=NtHandleTable::new();let b=NtHandleTable::new();
    let first=bootstrap_desktop(&a,"\\Windows\\bootstrap_shared_station","Default",1,3).unwrap();
    let second=bootstrap_desktop(&b,"\\windows\\BOOTSTRAP_SHARED_STATION","default",1,3).unwrap();
    assert!(Arc::ptr_eq(&first.station,&second.station));assert!(Arc::ptr_eq(&first.desktop,&second.desktop));
    let mut thread=ThreadDesktop::default();first.attach(&mut thread).unwrap();
    assert!(Arc::ptr_eq(&thread.object().unwrap(),&first.desktop));
    assert_eq!(b.access_and_handle_count(second.desktop_handle),Some((3,2)));
    let desktop=second.desktop.clone();drop(first);
    assert_eq!(b.handle_count(second.desktop_handle),Some(1));
    assert!(Arc::ptr_eq(&namespace::lookup_object("\\Windows\\bootstrap_shared_station\\Default",super::super::super::NtObjectType::Desktop).unwrap(),&desktop));
    second.commit();assert_eq!(b.live_handle_count(),2);drop(b);
    assert!(namespace::lookup_object("\\Windows\\bootstrap_shared_station\\Default",super::super::super::NtObjectType::Desktop).is_none());
}

#[test]
fn failed_bootstrap_or_attachment_does_not_leak_handles_or_replace_membership() {
    let table=NtHandleTable::new();
    assert!(bootstrap_desktop(&table,"\\Windows\\bootstrap_invalid","..\\Other",1,1).is_err());
    assert_eq!(table.live_handle_count(),0);
    let a=bootstrap_desktop(&table,"\\Windows\\bootstrap_no_replace","A",1,1).unwrap();
    let b=bootstrap_desktop(&table,"\\Windows\\bootstrap_no_replace","B",1,1).unwrap();
    let mut thread=ThreadDesktop::default();a.attach(&mut thread).unwrap();
    assert_eq!(b.attach(&mut thread),Err(DesktopError::Busy));drop(b);
    assert_eq!(table.live_handle_count(),2);drop(a);assert_eq!(table.live_handle_count(),0);
}
