use super::*;

#[test]
fn staged_proc_leaf_self_bind_uses_staged_parent() {
    let _g = guard();
    let host: u64 = 0x5150_6000;
    let sandbox: u64 = 0x5150_6001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x700);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), None).expect("bind /");
    let _stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("stage bind").mnt_id;
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let src = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
        LookupFlags::default(), vfs::Cred::root()).expect("source proc leaf");
    let tgt = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/proc/sys/kernel/domainname",
        LookupFlags::default(), vfs::Cred::root()).expect("target proc leaf");
    assert!(Arc::ptr_eq(&src.dentry, &tgt.dentry), "proc leaf dentry is shared across the staged bind");

    register_test_bind_path_at(Some(tgt.dentry.clone()), Arc::new(NamedFs { n: "bind", root: tgt.inode.clone() }),
        src.dentry.clone(), Some(src.mnt_id)).expect("self bind proc leaf");
    let b = vfs::mount::__lookup_mnt(src.mnt_id, &tgt.dentry).expect("bind must be under staged proc parent");
    assert_eq!(b.parent_id.load(Ordering::Acquire), src.mnt_id,
        "self-bind parent must be the source/staged proc mount, not the old /proc mount");
    assert_eq!(b.mount_point_str(), "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
        "mountinfo-visible path must be the staged prefix systemd is scanning");
    vfs::mount::remount_flags_by_id(b.mnt_id, vfs::mount::MS_RDONLY).expect("remount read-only");
    assert_ne!(b.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY, 0,
        "recursive bind-remount convergence requires the top leaf mount to read back ro");
}


