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
    let fdt = vfs::FdTable::new();
    let namespace = network_namespace::initial();
    let original = inode_file(net_ns_inode(namespace.clone()));
    let original_weak = Arc::downgrade(&original);
    let fd = fdt.alloc(original).unwrap();
    let replacement = ns_file(NsKind::Uts, 92);
    let destination = sched::Task::new(83, "destination", sched::SchedClass::Normal { weight: 1024 });

    let result = setns_from_fd_with(&fdt, fd, CLONE_NEWNET, &destination, || {
        fdt.close(fd).unwrap();
        assert_eq!(fdt.alloc(replacement), Ok(fd));
    });

    assert_eq!(result, 0);
    assert!(Arc::ptr_eq(&destination.network_namespace_snapshot().unwrap(), &namespace),
        "exact descriptor reuse cannot retarget the pinned network namespace file");
    assert!(original_weak.upgrade().is_none(), "syscall pin drops after namespace install");
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
