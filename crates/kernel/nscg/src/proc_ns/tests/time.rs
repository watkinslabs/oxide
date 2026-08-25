use super::*;

#[cfg(test)]
#[test]
fn time_setns_installs_both_slots_and_freezes_offsets() {
    let user = namespace_identity::initial(NamespaceKind::User);
    let time = namespace_identity::allocate(NamespaceKind::Time, user, None).unwrap();
    crate::time_ns::clone_from(&time,
        &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    let ns = NsInode::new(NsKind::Time, NsOwner::Time(time.clone()));
    let destination = sched::Task::new(84, "time-destination",
        sched::SchedClass::Normal { weight: 1024 });

    assert_eq!(setns_apply(&ns, CLONE_NEWTIME, &destination), 0);
    assert!(NamespaceRef::ptr_eq(&destination.namespace_owner(NamespaceKind::Time).unwrap(), &time));
    assert!(NamespaceRef::ptr_eq(&destination.time_namespace_for_children().unwrap(), &time));
    assert!(crate::time_ns::snapshot(&time).unwrap().frozen);
}

#[cfg(test)]
fn time_test_inode() -> (NamespaceRef, NsInode) {
    let time = namespace_identity::allocate(NamespaceKind::Time,
        namespace_identity::initial(NamespaceKind::User), None).unwrap();
    crate::time_ns::clone_from(&time,
        &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    let ns = NsInode::new(NsKind::Time, NsOwner::Time(time.clone()));
    (time, ns)
}

#[cfg(test)]
#[test]
fn time_setns_checks_type_then_single_thread_then_capabilities() {
    let (_time, ns) = time_test_inode();
    let destination = sched::Task::new(85, "time-errors",
        sched::SchedClass::Normal { weight: 1024 });
    assert_eq!(setns_apply(&ns, CLONE_NEWUTS, &destination),
        -(syscall::errno::Errno::Einval.as_i32() as i64));

    let mut sibling = sched::Task::new(86, "time-sibling",
        sched::SchedClass::Normal { weight: 1024 });
    sibling.join_thread_group(Arc::clone(&destination.thread_group));
    sibling.thread_group.commit_member();
    assert_eq!(setns_apply(&ns, CLONE_NEWTIME, &destination),
        -(syscall::errno::Errno::Eusers.as_i32() as i64));

    let no_cap = sched::Task::new(87, "time-no-cap",
        sched::SchedClass::Normal { weight: 1024 });
    no_cap.security.creds.cap_effective.store(0, core::sync::atomic::Ordering::Release);
    assert_eq!(setns_apply(&ns, CLONE_NEWTIME, &no_cap),
        -(syscall::errno::Errno::Eperm.as_i32() as i64));
}

#[cfg(test)]
#[test]
fn time_setns_rejects_released_destination_without_freezing_target() {
    let (time, ns) = time_test_inode();
    let destination = sched::Task::new(88, "time-released",
        sched::SchedClass::Normal { weight: 1024 });
    destination.release_namespaces();

    assert_eq!(setns_apply(&ns, CLONE_NEWTIME, &destination),
        -(syscall::errno::Errno::Esrch.as_i32() as i64));
    assert!(!crate::time_ns::snapshot(&time).unwrap().frozen);
}


