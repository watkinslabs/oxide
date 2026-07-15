use super::*;

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

#[test]
fn network_setns_pin_survives_close_and_exact_fd_reuse() {
    network_namespace::install_final_drop_callback(final_drop_notify).unwrap();
    let fdt = vfs::FdTable::new();
    let user = namespace_identity::initial(NamespaceKind::User);
    let original_namespace = network_namespace::allocate(Arc::clone(&user)).unwrap();
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
    let original_weak = Arc::downgrade(&original_owner);
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
    assert!(Arc::ptr_eq(&installed, &original_weak.upgrade().unwrap()),
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
    assert_eq!(fdt.alloc(ns_file(Arc::clone(&replacement))), Ok(fd));
    let destination = sched::Task::new(84, "destination", sched::SchedClass::Normal { weight: 1024 });

    assert_eq!(setns_from_fd(&fdt, fd, CLONE_NEWUTS, &destination), 0);
    assert!(Arc::ptr_eq(&destination.namespace_owner(NamespaceKind::Uts).unwrap(), &replacement),
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
    assert!(Arc::ptr_eq(&destination.namespace_owner(NamespaceKind::Uts).unwrap(), &initial));
}
