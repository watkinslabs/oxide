use super::*;

fn inode_file(inode: InodeRef) -> Arc<vfs::File> {
    let dentry = vfs::Dentry::new(None, String::from("nsfs"), inode.clone());
    vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDONLY)
}

fn ns_file(kind: NsKind, id: u64) -> Arc<vfs::File> {
    inode_file(ns_node(&NsInode::new(kind, id, None)))
}

#[test]
fn network_setns_pin_survives_close_and_exact_fd_reuse() {
    network_namespace::install_final_drop_callback(final_drop_notify).unwrap();
    let fdt = vfs::FdTable::new();
    let original_namespace = network_namespace::allocate(0x8631).unwrap();
    let replacement_namespace = network_namespace::allocate(0x8632).unwrap();
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
fn setns_close_reuse_before_pin_resolves_replacement() {
    use core::sync::atomic::Ordering;
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(ns_file(NsKind::Uts, 93)).unwrap();
    fdt.close(fd).unwrap();
    assert_eq!(fdt.alloc(ns_file(NsKind::Uts, 94)), Ok(fd));
    let destination = sched::Task::new(84, "destination", sched::SchedClass::Normal { weight: 1024 });

    assert_eq!(setns_from_fd(&fdt, fd, CLONE_NEWUTS, &destination), 0);
    assert_eq!(destination.uts_ns.load(Ordering::Acquire), 94,
        "descriptor lookup linearizes after completed close and reuse");
}

#[test]
fn setns_empty_slot_returns_ebadf_before_type_validation_or_later_reuse() {
    use core::sync::atomic::Ordering;
    let fdt = vfs::FdTable::new();
    let fd = fdt.alloc(ns_file(NsKind::Uts, 95)).unwrap();
    fdt.close(fd).unwrap();
    let destination = sched::Task::new(85, "destination", sched::SchedClass::Normal { weight: 1024 });

    let mixed_type = CLONE_NEWUTS | CLONE_NEWNET;
    assert_eq!(setns_from_fd(&fdt, fd, mixed_type, &destination),
        -(syscall::errno::Errno::Ebadf.as_i32() as i64));
    assert_eq!(fdt.alloc(ns_file(NsKind::Uts, 96)), Ok(fd),
        "reuse after failed lookup cannot rescue completed setns");
    assert_eq!(destination.uts_ns.load(Ordering::Acquire), 0);
}
