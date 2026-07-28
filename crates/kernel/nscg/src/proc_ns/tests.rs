use super::*;
use alloc::format;
use namespace_identity::NamespaceRef;

fn task(pid: u32, name: &'static str) -> sched::Task {
    sched::Task::new(pid, name, sched::SchedClass::Normal { weight: 1024 })
}

fn allocate(kind: NamespaceKind, owner: &NamespaceRef) -> NamespaceRef {
    namespace_identity::allocate(kind, owner.clone(), None).unwrap()
}

fn symlink(kind: NsKind, owner: NsOwner) -> InodeRef {
    let ns = NsInode::new(kind, owner);
    InodeBuilder::new(ns.ino(), mk_mode(FileType::Symlink, 0o777),
        Arc::new(NsLinkOps), default_file_ops()).private(Arc::new(ns)).build()
}

fn followed(link: &InodeRef) -> InodeRef {
    match link.follow_link().unwrap() {
        LinkTarget::Jump(path) => path.inode,
        LinkTarget::Path(_) => panic!("nsfs magic link must jump"),
    }
}

#[test]
fn readlink_and_node_inode_come_from_exact_owner() {
    let user = namespace_identity::initial(NamespaceKind::User);
    let uts = allocate(NamespaceKind::Uts, &user);
    let link = symlink(NsKind::Uts, NsOwner::Uts(uts.clone()));

    assert_eq!(link.ino(), uts.nsfs_ino());
    assert_eq!(link.readlink().unwrap(),
        format!("uts:[{}]", uts.nsfs_ino()).into_bytes());
    let node = followed(&link);
    assert_eq!(node.ino(), uts.nsfs_ino());
    let ns = node.private::<NsInode>().unwrap();
    assert!(matches!(&ns.owner, NsOwner::Uts(owner) if NamespaceRef::ptr_eq(owner, &uts)));
}

#[test]
fn proc_link_retains_exact_owner_after_task_namespace_release() {
    let user = namespace_identity::initial(NamespaceKind::User);
    let uts = allocate(NamespaceKind::Uts, &user);
    let weak = NamespaceRef::downgrade(&uts);
    let source = task(77, "source");
    assert!(source.replace_namespace(uts.clone()).is_ok());
    let link = ns_inode_for(&source, NsKind::Uts).unwrap();
    drop(uts);
    source.release_namespaces();
    assert!(matches!(ns_inode_for(&source, NsKind::Uts), Err(VfsError::Enoent)));

    let node = followed(&link);
    let retained = weak.upgrade().expect("proc link retains exact owner");
    let ns = node.private::<NsInode>().unwrap();
    assert!(matches!(&ns.owner, NsOwner::Uts(owner) if
        namespace_identity::NamespacePin::ptr_eq(&owner.pin(), &retained)));
}

#[test]
fn pid_setns_changes_only_pid_namespace_for_children() {
    let user = namespace_identity::initial(NamespaceKind::User);
    let destination = task(78, "destination");
    let current = destination.namespace_owner(NamespaceKind::Pid).unwrap();
    // Linux `pidns_install` refuses anything outside the caller's active pid
    // namespace subtree, so the target has to be a child of it.
    let target = namespace_identity::allocate(NamespaceKind::Pid, user,
        Some(current.clone())).unwrap();
    let ns = NsInode::new(NsKind::Pid, NsOwner::Pid(target.clone()));

    assert_eq!(setns_apply(&ns, CLONE_NEWPID, &destination), 0);
    assert!(NamespaceRef::ptr_eq(&destination.namespace_owner(NamespaceKind::Pid).unwrap(), &current));
    assert!(NamespaceRef::ptr_eq(&destination.pid_namespace_for_children().unwrap(), &target));
}

#[test]
fn pid_for_children_leaf_and_time_kind_snapshot_exact_slots() {
    assert_eq!(NsKind::from_leaf("pid_for_children"), Some(NsKind::PidForChildren));
    assert_eq!(NsKind::from_leaf("time"), Some(NsKind::Time));
    assert_eq!(NsKind::from_leaf("time_for_children"), Some(NsKind::TimeForChildren));
    assert_eq!(NsKind::Time.clone_bit(), CLONE_NEWTIME);
    assert_eq!(NsKind::TimeForChildren.clone_bit(), CLONE_NEWTIME);

    let user = namespace_identity::initial(NamespaceKind::User);
    let pid = allocate(NamespaceKind::Pid, &user);
    let time = allocate(NamespaceKind::Time, &user);
    let source = task(79, "source");
    assert!(source.replace_pid_namespace_for_children(pid.clone()).is_ok());
    assert!(source.replace_namespace(time.clone()).is_ok());

    let pid_link = ns_inode_for(&source, NsKind::PidForChildren).unwrap();
    let time_link = ns_inode_for(&source, NsKind::Time).unwrap();
    let pid_ns = followed(&pid_link);
    let time_ns = followed(&time_link);
    assert!(matches!(&pid_ns.private::<NsInode>().unwrap().owner,
        NsOwner::Pid(owner) if NamespaceRef::ptr_eq(owner, &pid)));
    assert!(matches!(&time_ns.private::<NsInode>().unwrap().owner,
        NsOwner::Time(owner) if NamespaceRef::ptr_eq(owner, &time)));
}

/// A mount namespace with no resolvable root cannot be entered, and a refused
/// entry must leave the caller in its ORIGINAL namespace — Linux
/// `mntns_install` swaps first, then reverts `nsproxy->mnt_ns` if the root
/// lookup fails. Entering on paper while cwd and root still resolve through the
/// old tree is the containment escape this path exists to prevent.
#[test]
fn mount_setns_refuses_a_rootless_namespace_and_reverts() {
    let user = namespace_identity::initial(NamespaceKind::User);
    let mount = vfs::mntns::allocate(user).unwrap();
    let destination = task(80, "destination");
    let ns = NsInode::new(NsKind::Mnt, NsOwner::Mnt(Arc::clone(&mount)));

    let before = destination.mount_namespace_snapshot().unwrap();
    assert_eq!(setns_apply(&ns, CLONE_NEWNS, &destination), -22);
    let after = destination.mount_namespace_snapshot().unwrap();
    assert!(Arc::ptr_eq(&after, &before), "refused setns must revert the namespace swap");
    assert!(!Arc::ptr_eq(&after, &mount), "caller must not be left in the target namespace");
}

#[test]
fn capability_walk_uses_concrete_user_parent_owners() {
    let initial = namespace_identity::initial(NamespaceKind::User);
    let parent = namespace_identity::allocate(NamespaceKind::User,
        initial.clone(), Some(initial.clone())).unwrap();
    let child = namespace_identity::allocate(NamespaceKind::User,
        parent.clone(), Some(parent.clone())).unwrap();
    let sibling = namespace_identity::allocate(NamespaceKind::User,
        initial.clone(), Some(initial.clone())).unwrap();
    let current = task(81, "current");
    assert!(current.replace_namespace(parent.clone()).is_ok());

    assert!(has_cap_for(&current, &child.pin(), sched::cap::NET_ADMIN));
    assert!(!has_cap_for(&current, &sibling.pin(), sched::cap::NET_ADMIN));

    network_namespace::install_final_drop_callback(final_drop_notify).unwrap();
    let network = network_namespace::allocate(child.clone()).unwrap();
    assert!(has_net_admin_for(&current, &network));
    assert!(has_net_raw_for(&current, &network));
}

#[test]
fn setns_rejects_nonexact_mask_and_released_destination() {
    let user = namespace_identity::initial(NamespaceKind::User);
    let uts = allocate(NamespaceKind::Uts, &user);
    let ns = NsInode::new(NsKind::Uts, NsOwner::Uts(uts));
    let destination = task(82, "destination");

    assert_eq!(setns_apply(&ns, CLONE_NEWUTS | CLONE_NEWNET, &destination),
        -(syscall::errno::Errno::Einval.as_i32() as i64));
    destination.release_namespaces();
    assert_eq!(setns_apply(&ns, CLONE_NEWUTS, &destination),
        -(syscall::errno::Errno::Esrch.as_i32() as i64));
}

#[test]
fn network_proc_link_retains_exact_owner_after_task_exit() {
    network_namespace::install_final_drop_callback(final_drop_notify).unwrap();
    let source = task(83, "source");
    let retained = source.network_namespace_snapshot().unwrap();
    let link = ns_inode_for(&source, NsKind::Net).unwrap();
    source.release_network_namespace();
    assert!(matches!(ns_inode_for(&source, NsKind::Net), Err(VfsError::Enoent)));

    let node = followed(&link);
    let ns = node.private::<NsInode>().unwrap();
    assert!(matches!(&ns.owner, NsOwner::Net(owner) if Arc::ptr_eq(owner, &retained)));
}
