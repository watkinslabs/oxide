use super::*;

#[test]
fn bind_under_derives_rendered_path_from_parent_mount_identity() {
    let _g = guard();
    let host: u64 = 0x5150_7000;
    let sandbox: u64 = 0x5150_7001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x710);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), None).expect("bind /");
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let src = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/run/systemd/mount-rootfs/proc/kallsyms",
        LookupFlags::default(), vfs::Cred::root()).expect("staged kallsyms");
    let tgt = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/proc/kallsyms",
        LookupFlags::default(), vfs::Cred::root()).expect("global kallsyms alias");
    assert!(Arc::ptr_eq(&src.dentry, &tgt.dentry), "proc leaf dentry is shared across staged and global proc");

    vfs::mount::register_bind_clone_under(src.mnt_id, tgt.dentry.clone(), src.mnt_id, src.dentry.clone())
        .expect("bind under staged proc");
    let b = vfs::mount::__lookup_mnt(src.mnt_id, &tgt.dentry).expect("bind under staged proc parent");
    assert_eq!(b.mount_point_str(), "/run/systemd/mount-rootfs/proc/kallsyms",
        "bind-under must derive rendered path from parent mount identity, not caller's stale global string");
}

#[test]
fn bind_clone_shares_source_superblock_and_staged_identity() {
    let _g = guard();
    let host: u64 = 0x5150_8000;
    let sandbox: u64 = 0x5150_8001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    mount_pseudo(&root, "/proc", "procfs", 0x720);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), None).expect("bind /");
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let src = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
        LookupFlags::default(), vfs::Cred::root()).expect("staged domainname");
    let tgt = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root, "/proc/sys/kernel/domainname",
        LookupFlags::default(), vfs::Cred::root()).expect("global domainname alias");
    assert!(Arc::ptr_eq(&src.dentry, &tgt.dentry), "proc leaf dentry is shared across staged and global proc");
    let src_m = vfs::mount::mount_by_id(src.mnt_id).expect("source proc mount");
    assert_eq!(src_m.sb().s_type.name(), "procfs", "precondition: source is procfs");

    vfs::mount::register_bind_clone_under(src.mnt_id, tgt.dentry.clone(), src.mnt_id, src.dentry.clone())
        .expect("bind clone under staged proc");
    let b = vfs::mount::__lookup_mnt(src.mnt_id, &tgt.dentry).expect("bind clone under staged proc parent");
    assert_eq!(b.parent_id.load(Ordering::Acquire), src.mnt_id,
        "bind clone parent must be the walked staged proc mount");
    assert_eq!(b.mount_point_str(), "/run/systemd/mount-rootfs/proc/sys/kernel/domainname",
        "mountinfo-visible path must be the staged prefix");
    assert_eq!(vfs::mount::mountinfo_root_field(&b), "/sys/kernel/domainname",
        "bind mountinfo root must be the source path relative to the source superblock root");
    assert!(Arc::ptr_eq(b.sb(), src_m.sb()),
        "Linux bind clone shares the source superblock; no synthetic bind SB");
    assert_eq!(b.sb().s_type.name(), "procfs",
        "bind mount fstype must be the source fstype, not a fake bind filesystem");
    assert_eq!(b.mnt_root().and_then(|d| d.inode()).map(|i| i.ino()), Some(src.inode.ino()),
        "bind mnt_root must be the source leaf dentry");
    vfs::mount::remount_flags_by_id(b.mnt_id, vfs::mount::MS_RDONLY).expect("remount read-only");
    assert_ne!(b.flags.load(Ordering::Acquire) & vfs::mount::MNT_RDONLY, 0,
        "mountinfo convergence must observe the remounted bind clone as ro");
}

