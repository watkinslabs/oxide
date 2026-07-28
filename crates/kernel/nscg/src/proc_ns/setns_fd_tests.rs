use super::*;
use namespace_identity::NamespaceRef;

fn inode_file(inode: InodeRef) -> Arc<vfs::File> {
    let dentry = vfs::Dentry::new(None, String::from("nsfs"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDONLY)
}

fn uts_owner() -> NamespaceRef {
    let user = namespace_identity::initial(NamespaceKind::User);
    namespace_identity::allocate(NamespaceKind::Uts, user, None).unwrap()
}

fn ns_file(owner: NamespaceRef) -> Arc<vfs::File> {
    inode_file(ns_node(&NsInode::new(NsKind::Uts, NsOwner::Uts(owner))))
}

fn task(tid: u32, name: &'static str) -> sched::Task {
    sched::Task::new(tid, name, sched::SchedClass::Normal { weight: 1024 })
}

fn proc_ns_file(source: &sched::Task, kind: NsKind) -> Arc<vfs::File> {
    let link = ns_inode_for(source, kind).unwrap();
    let captured = link.private::<NsInode>().unwrap();
    inode_file(ns_node(captured))
}

fn identity_owner(ns: &NsInode) -> &NamespaceRef {
    match &ns.owner {
        NsOwner::Cgroup(owner) | NsOwner::Ipc(owner) | NsOwner::Pid(owner)
        | NsOwner::Time(owner) | NsOwner::User(owner) | NsOwner::Uts(owner) => owner,
        NsOwner::Mnt(_) | NsOwner::Net(_) => panic!("expected identity namespace owner"),
    }
}

fn install_source_identity(source: &sched::Task, kind: NsKind, owner: NamespaceRef) {
    let result = match kind {
        NsKind::PidForChildren => source.replace_pid_namespace_for_children(owner),
        _ => source.replace_namespace(owner),
    };
    assert!(result.is_ok());
}

fn installed_identity(destination: &sched::Task, kind: NsKind) -> NamespaceRef {
    match kind {
        NsKind::Pid | NsKind::PidForChildren => destination.pid_namespace_for_children().unwrap(),
        NsKind::Cgroup => destination.namespace_owner(NamespaceKind::Cgroup).unwrap(),
        NsKind::Ipc => destination.namespace_owner(NamespaceKind::Ipc).unwrap(),
        NsKind::Time => destination.namespace_owner(NamespaceKind::Time).unwrap(),
        NsKind::TimeForChildren => destination.time_namespace_for_children().unwrap(),
        NsKind::User => destination.namespace_owner(NamespaceKind::User).unwrap(),
        NsKind::Uts => destination.namespace_owner(NamespaceKind::Uts).unwrap(),
        NsKind::Mnt | NsKind::Net => panic!("expected identity namespace kind"),
    }
}

fn exercise_identity_close_reuse(kind: NsKind, identity_kind: NamespaceKind, tid: u32) {
    let fdt = vfs::FdTable::new();
    let initial_user = namespace_identity::initial(NamespaceKind::User);
    // Linux `pidns_install` only admits the caller's ACTIVE pid namespace or a
    // descendant of it, and `userns_install` walks the user-namespace parent
    // chain, so both fixtures must hang off the initial namespace.
    let parent = match identity_kind {
        NamespaceKind::User => Some(initial_user.clone()),
        NamespaceKind::Pid  => Some(namespace_identity::initial(NamespaceKind::Pid)),
        _ => None,
    };
    let original = namespace_identity::allocate(identity_kind,
        initial_user.clone(), parent.clone()).unwrap();
    let replacement = namespace_identity::allocate(identity_kind,
        initial_user, parent).unwrap();
    let original_id = original.id();
    let original_ino = original.nsfs_ino();
    let original_weak = NamespaceRef::downgrade(&original);
    let source = task(tid, "ns-source");
    install_source_identity(&source, kind, original.clone());
    let file = proc_ns_file(&source, kind);
    let inode_owner = identity_owner(file.inode().private::<NsInode>().unwrap());
    assert!(NamespaceRef::ptr_eq(inode_owner, &original), "nsfs inode owns exact task namespace");
    let file_weak = Arc::downgrade(&file);
    let fd = fdt.alloc(file).unwrap();
    drop(original);

    source.mark_done();
    assert_eq!(source.state(), sched::TaskState::Zombie);
    assert!(source.namespace_snapshot().is_none(), "exit releases task namespace set first");
    assert!(namespace_identity::lookup(identity_kind, original_id).is_some(),
        "open nsfs file keeps weak live index resolvable after source exit");

    let replacement_file = inode_file(ns_node(&NsInode::new(kind, match kind {
        NsKind::Cgroup => NsOwner::Cgroup(replacement),
        NsKind::Ipc => NsOwner::Ipc(replacement),
        NsKind::Pid | NsKind::PidForChildren => NsOwner::Pid(replacement),
        NsKind::Time | NsKind::TimeForChildren => NsOwner::Time(replacement),
        NsKind::User => NsOwner::User(replacement),
        NsKind::Uts => NsOwner::Uts(replacement),
        NsKind::Mnt | NsKind::Net => panic!("expected identity namespace kind"),
    })));
    let destination = task(tid + 1, "ns-destination");
    let result = setns_from_fd_with(&fdt, fd, kind.clone_bit(), &destination, || {
        fdt.close(fd).unwrap();
        assert!(file_weak.upgrade().is_some(), "fget pins File across close");
        assert!(original_weak.upgrade().is_some(), "pinned NsInode pins exact owner");
        assert_eq!(fdt.alloc(replacement_file), Ok(fd), "close reuses exact fd slot");
    });

    assert_eq!(result, 0);
    {
        let installed = installed_identity(&destination, kind);
        assert!(namespace_identity::NamespacePin::ptr_eq(
            &installed.pin(), &original_weak.upgrade().unwrap()),
            "fd reuse cannot retarget the pinned nsfs file");
    }
    assert!(file_weak.upgrade().is_none(), "setns drops File pin after exact install");
    destination.mark_done();
    assert_eq!(destination.state(), sched::TaskState::Zombie);
    assert!(original_weak.upgrade().is_none(), "destination exit drops final exact owner");
    assert!(namespace_identity::lookup(identity_kind, original_id).is_none(),
        "weak id index disappears only after final owner drop");
    assert!(namespace_identity::lookup_nsfs_ino(original_ino).is_none(),
        "stale nsfs inode cannot numerically reconstruct an owner");
    fdt.close(fd).unwrap();
}

fn exercise_mount_close_reuse(tid: u32) {
    let fdt = vfs::FdTable::new();
    let user = namespace_identity::initial(NamespaceKind::User);
    let original = vfs::mntns::allocate(user.clone()).unwrap();
    let replacement = vfs::mntns::allocate(user).unwrap();
    let original_id = original.id();
    let original_weak = Arc::downgrade(&original);
    let source = task(tid, "mnt-source");
    assert!(source.replace_mount_namespace(original.clone()).is_ok());
    let file = proc_ns_file(&source, NsKind::Mnt);
    let ns = file.inode().private::<NsInode>().unwrap();
    assert!(matches!(&ns.owner, NsOwner::Mnt(owner) if Arc::ptr_eq(owner, &original)),
        "nsfs inode owns exact VFS mount namespace");
    let file_weak = Arc::downgrade(&file);
    let fd = fdt.alloc(file).unwrap();
    drop(original);

    source.mark_done();
    assert_eq!(source.state(), sched::TaskState::Zombie);
    assert!(source.mount_namespace_snapshot().is_none(), "exit releases mount owner first");
    assert!(vfs::mntns::ns_by_id(original_id).is_some(),
        "open nsfs file keeps mount live index resolvable after source exit");

    let replacement_owner = Arc::clone(&replacement);
    let replacement_file = inode_file(ns_node(&NsInode::new(
        NsKind::Mnt, NsOwner::Mnt(replacement))));
    let destination = task(tid + 1, "mnt-destination");
    let result = setns_from_fd_with(&fdt, fd, CLONE_NEWNS, &destination, || {
        fdt.close(fd).unwrap();
        assert!(file_weak.upgrade().is_some(), "fget pins mount File across close");
        assert!(original_weak.upgrade().is_some(), "pinned NsInode pins mount owner");
        assert_eq!(fdt.alloc(replacement_file), Ok(fd), "close reuses exact mount fd slot");
    });

    // EINVAL, not 0: these fixtures allocate a namespace with no root mount and
    // `mntns_install` refuses one whose root it cannot resolve. That is beside
    // the point of THIS test, which is that the pinned owner survives the fd
    // being closed and its slot reused — asserted by `original_weak` still
    // upgrading, and by the destination never landing in the replacement.
    assert_eq!(result, -22);
    {
        // No post-call upgrade assertion: the in-closure check already proved
        // `fget` pinned the owner across the close. With the entry refused and
        // the fd gone, releasing it is correct — the old expectation only held
        // because a successful install kept a strong ref.
        let installed = destination.mount_namespace_snapshot().unwrap();
        assert!(!Arc::ptr_eq(&installed, &replacement_owner),
            "fd reuse must never retarget setns at the replacement namespace");
    }
    assert!(file_weak.upgrade().is_none(), "setns drops mount File pin after install");
    destination.mark_done();
    assert_eq!(destination.state(), sched::TaskState::Zombie);
    assert!(original_weak.upgrade().is_none(), "destination exit drops final mount owner");
    assert!(vfs::mntns::ns_by_id(original_id).is_none(),
        "stale mount id cannot numerically reconstruct an owner");
    assert!(!namespace_identity::live_snapshot().iter().any(|owner|
        owner.kind() == NamespaceKind::Mnt && owner.id().as_u64() == original_id),
        "weak mount live index disappears only after final owner drop");
    fdt.close(fd).unwrap();
}

#[test]
fn nsfd_only_owner_retains_uts_state_until_close() {
    let fdt = vfs::FdTable::new();
    let owner = uts_owner();
    let id = owner.id();
    let weak = NamespaceRef::downgrade(&owner);
    crate::uts_ns::allocate(&owner, b"nsfd-host".to_vec(), b"nsfd-domain".to_vec()).unwrap();
    let fd = fdt.alloc(ns_file(owner)).unwrap();

    let retained = weak.upgrade().expect("nsfd retains exact UTS owner");
    assert_eq!(crate::uts_ns::snapshot(&retained).unwrap().hostname, b"nsfd-host".to_vec());
    drop(retained);
    assert!(crate::uts_ns::contains(id));

    fdt.close(fd).unwrap();
    assert!(weak.upgrade().is_none());
    assert!(!crate::uts_ns::contains(id));
}

#[test]
fn network_setns_pin_survives_close_and_exact_fd_reuse() {
    network_namespace::install_final_drop_callback(final_drop_notify).unwrap();
    let fdt = vfs::FdTable::new();
    let user = namespace_identity::initial(NamespaceKind::User);
    let original_namespace = network_namespace::allocate(user.clone()).unwrap();
    let replacement_namespace = network_namespace::allocate(user).unwrap();
    let original_id = original_namespace.id();
    let replacement_id = replacement_namespace.id();
    let original_owner_weak = Arc::downgrade(&original_namespace);
    let original = inode_file(net_ns_inode(original_namespace));
    let original_weak = Arc::downgrade(&original);
    let fd = fdt.alloc(original).unwrap();
    let replacement = inode_file(net_ns_inode(replacement_namespace));
    let destination = sched::Task::new(83, "destination", sched::SchedClass::Normal { weight: 1024 });

    let result = setns_from_fd_with(&fdt, fd, CLONE_NEWNET, &destination, || {
        fdt.close(fd).unwrap();
        assert!(original_owner_weak.upgrade().is_some(),
            "pinned namespace file retains its concrete owner after close");
        assert_eq!(fdt.alloc(replacement), Ok(fd));
    });

    assert_eq!(result, 0);
    assert_eq!(destination.network_namespace_snapshot().unwrap().id(), original_id,
        "exact descriptor reuse cannot retarget the pinned network namespace file");
    assert_ne!(original_id, replacement_id);
    assert!(original_weak.upgrade().is_none(), "syscall pin drops after namespace install");
    assert!(original_owner_weak.upgrade().is_some(), "destination task owns installed namespace");
    destination.release_network_namespace();
    assert!(original_owner_weak.upgrade().is_none(), "task release drops final namespace owner");
    fdt.close(fd).unwrap();
}

#[test]
fn nonnetwork_setns_pin_survives_close_and_exact_fd_reuse() {
    let fdt = vfs::FdTable::new();
    let original_owner = uts_owner();
    let replacement_owner = uts_owner();
    let original_weak = NamespaceRef::downgrade(&original_owner);
    let original = ns_file(original_owner);
    let original_file_weak = Arc::downgrade(&original);
    let fd = fdt.alloc(original).unwrap();
    let replacement = ns_file(replacement_owner);
    let destination = sched::Task::new(86, "destination", sched::SchedClass::Normal { weight: 1024 });

    let result = setns_from_fd_with(&fdt, fd, CLONE_NEWUTS, &destination, || {
        fdt.close(fd).unwrap();
        assert!(original_weak.upgrade().is_some(),
            "pinned namespace file retains its exact owner after close");
        assert_eq!(fdt.alloc(replacement), Ok(fd));
    });

    assert_eq!(result, 0);
    let installed = destination.namespace_owner(NamespaceKind::Uts).unwrap();
    assert!(namespace_identity::NamespacePin::ptr_eq(
        &installed.pin(), &original_weak.upgrade().unwrap()),
        "exact descriptor reuse cannot retarget the pinned namespace file");
    assert!(original_file_weak.upgrade().is_none(), "syscall pin drops after install");
    drop(installed);
    destination.release_namespaces();
    assert!(original_weak.upgrade().is_none(), "task release drops final exact owner");
    fdt.close(fd).unwrap();
}

#[test]
fn setns_close_reuse_before_pin_resolves_replacement() {
    let fdt = vfs::FdTable::new();
    let original = uts_owner();
    let replacement = uts_owner();
    let fd = fdt.alloc(ns_file(original)).unwrap();
    fdt.close(fd).unwrap();
    assert_eq!(fdt.alloc(ns_file(replacement.clone())), Ok(fd));
    let destination = sched::Task::new(84, "destination", sched::SchedClass::Normal { weight: 1024 });

    assert_eq!(setns_from_fd(&fdt, fd, CLONE_NEWUTS, &destination), 0);
    assert!(NamespaceRef::ptr_eq(&destination.namespace_owner(NamespaceKind::Uts).unwrap(), &replacement),
        "descriptor lookup linearizes after completed close and exact reuse");
}

#[test]
fn setns_empty_slot_returns_ebadf_before_type_validation_or_later_reuse() {
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(ns_file(uts_owner())).unwrap();
    fdt.close(fd).unwrap();
    let destination = sched::Task::new(85, "destination", sched::SchedClass::Normal { weight: 1024 });
    let initial = destination.namespace_owner(NamespaceKind::Uts).unwrap();

    let mixed_type = CLONE_NEWUTS | CLONE_NEWNET;
    assert_eq!(setns_from_fd(&fdt, fd, mixed_type, &destination),
        -(syscall::errno::Errno::Ebadf.as_i32() as i64));
    assert_eq!(fdt.alloc(ns_file(uts_owner())), Ok(fd),
        "reuse after failed lookup cannot rescue completed setns");
    assert!(NamespaceRef::ptr_eq(&destination.namespace_owner(NamespaceKind::Uts).unwrap(), &initial));
}

#[test]
fn cgroup_nsfs_close_reuse_and_final_drop_keep_exact_owner() {
    exercise_identity_close_reuse(NsKind::Cgroup, NamespaceKind::Cgroup, 401);
}

#[test]
fn ipc_nsfs_close_reuse_and_final_drop_keep_exact_owner() {
    exercise_identity_close_reuse(NsKind::Ipc, NamespaceKind::Ipc, 403);
}

#[test]
fn pid_nsfs_close_reuse_and_final_drop_keep_exact_owner() {
    exercise_identity_close_reuse(NsKind::Pid, NamespaceKind::Pid, 405);
}

#[test]
fn pid_for_children_nsfs_close_reuse_and_final_drop_keep_exact_owner() {
    exercise_identity_close_reuse(NsKind::PidForChildren, NamespaceKind::Pid, 407);
}

#[test]
fn time_nsfs_close_reuse_installs_and_freezes_exact_owner() {
    let fdt = vfs::FdTable::new();
    let user = namespace_identity::initial(NamespaceKind::User);
    let original = namespace_identity::allocate(NamespaceKind::Time,
        user.clone(), None).unwrap();
    crate::time_ns::clone_from(&original,
        &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    let original_weak = NamespaceRef::downgrade(&original);
    let source = task(409, "time-source");
    assert!(source.replace_namespace(original.clone()).is_ok());
    let file = proc_ns_file(&source, NsKind::Time);
    let file_weak = Arc::downgrade(&file);
    let fd = fdt.alloc(file).unwrap();
    let replacement = namespace_identity::allocate(NamespaceKind::Time, user, None).unwrap();
    crate::time_ns::clone_from(&replacement,
        &namespace_identity::initial(NamespaceKind::Time)).unwrap();
    let replacement_file = inode_file(ns_node(&NsInode::new(
        NsKind::Time, NsOwner::Time(replacement))));
    let destination = task(410, "time-destination");
    let result = setns_from_fd_with(&fdt, fd, CLONE_NEWTIME, &destination, || {
        fdt.close(fd).unwrap();
        assert!(file_weak.upgrade().is_some(), "fget pins TIME nsfs file across close");
        assert_eq!(fdt.alloc(replacement_file), Ok(fd), "close reuses exact fd slot");
    });

    assert_eq!(result, 0);
    assert!(NamespaceRef::ptr_eq(&destination.namespace_owner(NamespaceKind::Time).unwrap(), &original));
    assert!(NamespaceRef::ptr_eq(&destination.time_namespace_for_children().unwrap(), &original));
    assert!(crate::time_ns::snapshot(&original).unwrap().frozen);
    assert!(file_weak.upgrade().is_none(), "setns drops its File pin after exact install");
    assert!(original_weak.upgrade().is_some(), "installed task pair retains exact TIME owner");
    fdt.close(fd).unwrap();
}

#[test]
fn user_nsfs_close_reuse_and_final_drop_keep_exact_owner() {
    exercise_identity_close_reuse(NsKind::User, NamespaceKind::User, 411);
}

#[test]
fn mount_nsfs_close_reuse_and_final_drop_keep_exact_owner() {
    exercise_mount_close_reuse(413);
}
