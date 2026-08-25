use super::*;

#[test]
fn staged_root_exposes_plain_ext4_var_tmp_before_pivot() {
    let _g = guard();
    let host: u64 = 0x5150_4100;
    let sandbox: u64 = 0x5150_4101;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri }),
        root.clone(), None).expect("bind /");
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let var_tmp = vfs::path_lookup_at_root_cred(
        root.clone(), source_root, root.clone(), source_root,
        "/run/systemd/mount-rootfs/var/tmp", LookupFlags::default(), vfs::Cred::root())
        .expect("systemd destination /run/systemd/mount-rootfs/var/tmp must resolve through staged /");
    assert_eq!(var_tmp.inode.ino(), 0x19, "staged root must expose the source rootfs /var/tmp dentry");
    assert_eq!(vfs::mount::render_path_for_mount(var_tmp.mnt_id, &var_tmp.dentry),
        "/run/systemd/mount-rootfs/var/tmp",
        "rendered identity for plain rootfs children must stay under the staged root");
}

#[test]
fn private_devices_tmpfs_dev_move_into_staged_root_succeeds() {
    let _g = guard();
    let host: u64 = 0x5150_5000;
    let sandbox: u64 = 0x5150_5001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    let dev_d = mount_pseudo(&root, "/dev", "devtmpfs", 0x600);
    mount_pseudo(&root, "/dev/pts", "devpts", 0x601);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/mount-rootfs",
        LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }),
        root.clone(), None).expect("bind /");
    let stage_id = vfs::mount::mount_at_path_exact(&stage_d).expect("stage bind").mnt_id;
    let source_root = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let stage_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(source_root), &root, &stage_d, Some(stage_parent));

    let (_, tmp_dev_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/systemd/namespace-test/dev",
        LookupFlags::default()).expect("tmp private dev path");
    let tmp_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &tmp_dev_d);
    register_test_mount_at(Some(tmp_dev_d.clone()), Arc::new(NamedFs { n: "tmpfs", root: facdir(0x602) }),
        Some(tmp_parent)).expect("tmpfs private /dev");
    let tmp_dev = vfs::mount::__lookup_mnt(tmp_parent, &tmp_dev_d).expect("private dev mount");
    let tmp_dev_id = tmp_dev.mnt_id;
    assert_eq!(tmp_dev.flags() & vfs::mount::MNT_RDONLY, 0,
        "private /dev tmpfs starts writable");

    assert!(vfs::mount::__lookup_mnt(stage_id, &dev_d).is_some(),
        "recursive bind should place a /dev submount under the staged root");
    vfs::mount::unregister_top(&dev_d, true);

    vfs::mount::move_mount_by_id_to(tmp_dev_id, Some(stage_id), &dev_d)
        .expect("MS_MOVE private tmpfs /dev onto staged /dev must not EINVAL");
    let moved = vfs::mount::__lookup_mnt(stage_id, &dev_d).expect("moved private dev under stage");
    assert_eq!(moved.mnt_id, tmp_dev_id, "private /dev mount moved to the staged root");
    assert_eq!(moved.flags() & vfs::mount::MNT_RDONLY, 0,
        "moving private /dev must preserve its writable mount state");
    assert_eq!(moved.parent_id.load(Ordering::Acquire), stage_id,
        "moved private /dev parent must be the walked staged root");
    vfs::mount::pivot_root(&stage_d, &stage_d).expect("pivot_root after private /dev move");
    let new_root_id = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("post-pivot root id");
    let new_root = vfs::mount::root_dentry_for_mount_id(new_root_id).expect("post-pivot root dentry");
    let dev = vfs::path_lookup_at_root_cred(
        new_root.clone(), new_root_id, new_root.clone(), new_root_id, "/dev",
        LookupFlags::default(), vfs::Cred::root())
        .expect("private /dev must survive pivot");
    assert_eq!(dev.mnt_id, tmp_dev_id, "private /dev mount identity must survive pivot");
    assert_eq!(dev.inode.ino(), 0x602, "post-pivot /dev must resolve private tmpfs root");
    let post_pivot = vfs::mount::mount_by_id(tmp_dev_id)
        .expect("post-pivot private /dev mount");
    assert_eq!(post_pivot.flags() & vfs::mount::MNT_RDONLY, 0,
        "pivoting private /dev must preserve its writable mount state");
}


