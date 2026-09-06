use super::*;

#[test]
fn cross_process_close_keeps_name_and_reports_global_handle_count() {
    // Wine 10.20 server/handle.c owns handle_count on the object, not its table.
    let path="\\BaseNamedObjects\\cross_process_handle_lifetime";
    let (object,_)=namespace::create_event(path,false,false);
    let a=NtHandleTable::new();let b=NtHandleTable::new();
    let ha=a.insert(object.clone(),1).unwrap();let hb=b.insert(object.clone(),1).unwrap();
    assert_eq!(a.handle_count(ha),Some(2));assert_eq!(b.access_and_handle_count(hb),Some((1,2)));
    assert_eq!(a.close_with_last(ha),Some(false));
    assert!(Arc::ptr_eq(&namespace::lookup_object(path,NtObjectType::Event).unwrap(),&object));
    assert_eq!(b.handle_count(hb),Some(1));assert_eq!(b.close_with_last(hb),Some(true));
    assert!(namespace::lookup_object(path,NtObjectType::Event).is_none());
}

#[test]
fn table_drop_releases_global_handles_including_protected_entries() {
    let path="\\BaseNamedObjects\\table_drop_handle_lifetime";
    let (object,_)=namespace::create_event(path,false,false);
    let a=NtHandleTable::new();let b=NtHandleTable::new();
    let ha=a.insert(object.clone(),1).unwrap();a.set_flags(ha,2).unwrap();
    let hb=b.insert(object.clone(),1).unwrap();assert!(!a.close(ha));assert_eq!(b.handle_count(hb),Some(2));
    drop(a);assert_eq!(b.handle_count(hb),Some(1));assert!(namespace::lookup_object(path,NtObjectType::Event).is_some());
    drop(b);assert!(namespace::lookup_object(path,NtObjectType::Event).is_none());
    assert_eq!(object.handle_refs.load(Ordering::Acquire),0);
}

#[test]
fn duplicate_and_stale_close_account_exactly_once() {
    let table=NtHandleTable::new();let object=table.new_object(NtObjectType::Event);
    let first=table.insert(object.clone(),3).unwrap();let second=table.duplicate(first,1).unwrap();
    assert!(table.duplicate(second,3).is_none());assert_eq!(table.handle_count(first),Some(2));
    assert_eq!(table.close_with_last(first),Some(false));assert!(!table.close(first));
    assert_eq!(table.handle_count(second),Some(1));assert_eq!(table.close_with_last(second),Some(true));
    assert_eq!(object.handle_refs.load(Ordering::Acquire),0);
}

#[test]
fn local_close_hint_cannot_unlink_another_process_handle() {
    let path="\\BaseNamedObjects\\untrusted_local_close_hint";
    let (object,_)=namespace::create_event(path,false,false);let table=NtHandleTable::new();
    let handle=table.insert(object.clone(),1).unwrap();namespace::release_temporary(&object,false);
    assert!(namespace::lookup_object(path,NtObjectType::Event).is_some());assert!(table.close(handle));
}

#[test]
fn concurrent_table_retirement_preserves_anchor_handle_and_name() {
    let path="\\BaseNamedObjects\\concurrent_global_handle_lifetime";
    let (object,_)=namespace::create_event(path,false,false);let anchor=NtHandleTable::new();
    let handle=anchor.insert(object.clone(),1).unwrap();let other=object.clone();
    let worker=std::thread::spawn(move|| {
        for _ in 0..1000 { let table=NtHandleTable::new();let h=table.insert(other.clone(),1).unwrap();
            let copy=table.duplicate(h,1).unwrap();assert_eq!(table.close_with_last(copy),Some(false)); }
    });
    for _ in 0..1000 { assert!(namespace::lookup_object(path,NtObjectType::Event).is_some()); }
    worker.join().unwrap();assert_eq!(anchor.handle_count(handle),Some(1));
    assert_eq!(anchor.close_with_last(handle),Some(true));assert!(namespace::lookup_object(path,NtObjectType::Event).is_none());
}
