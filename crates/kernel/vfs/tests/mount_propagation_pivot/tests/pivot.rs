use super::*;

#[test]
fn full_service_setup_pivot_and_switch_root_detach() {
    let _g = guard();
    let host: u64 = 0x5150_4000;
    let sandbox: u64 = 0x5150_4001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    // Real submounts under `/` so the recursive bind + pivot carry a subtree.
    mount_pseudo(&root, "/proc", "procfs", 0x500);
    mount_pseudo(&root, "/sys", "sysfs", 0x501);
    mount_pseudo(&root, "/dev", "devtmpfs", 0x502);

    // 1. make-rshared / at boot.
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    // 2. unshare -> sandbox.
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);
    // 3. make-rslave / (recursive) — breaks propagation to host.
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    // 4. recursive-bind / onto the stage (+ its /proc,/sys,/dev submounts).
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/mount-rootfs", LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }), root.clone(), None).expect("bind /");
    vfs::mount::propagate_mount(&stage_d);
    let root_id = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("source root id");
    let target_parent = vfs::mount::containing_mount_id(common::namespace_id(sandbox), &stage_d);
    vfs::mount::bind_submounts_rec_at(Some(root_id), &root, &stage_d, Some(target_parent));
    // The bind must be PRIVATE (the fix): a shared put_old EINVALs pivot_root.
    let bindm = vfs::mount::mount_at_path_exact(&stage_d).expect("bind mount");
    assert_ne!(bindm.propagation.load(Ordering::Acquire), Propagation::Shared as u8,
        "service rootfs bind must be PRIVATE, not SHARED");
    let stage_id = bindm.mnt_id;

    // Submount carry-through: bind_submounts_rec MUST replicate the tmpfs /run
    // (and pseudo-fs) UNDER the stage, so after pivot `/run` resolves to tmpfs,
    // not the ext4 underlay. If the tmpfs submount is dropped, `mkdir /run/udev`
    // lands on ext4 -> the boot's `mkdir /run/udev err=5`. Assert a tmpfs mount
    // now lives inside the stage subtree.
    let is_under = |m: &Arc<vfs::mount::Mount>, top: u64| -> bool {
        let mut id = m.parent_id.load(Ordering::Acquire);
        for _ in 0..64 { if id == top { return true; } match vfs::mount::mount_by_id(id) {
            Some(p) => { let np = p.parent_id.load(Ordering::Acquire); if np == id { break; } id = np; }
            None => break, } }
        false
    };
    let tmpfs_under_stage = vfs::mount::all_mounts().iter()
        .filter(|m| m.namespace_id() == common::namespace_id(sandbox) && m.sb().s_type.name() == "tmpfs" && is_under(m, stage_id))
        .count();
    assert!(tmpfs_under_stage >= 1,
        "tmpfs /run must be carried UNDER the stage by bind_submounts_rec (else mkdir /run/udev hits ext4 -> EIO)");

    // 5. pivot_root(stage, stage) — stacked. MUST succeed; stage becomes `/`.
    let old_root_id = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("pre-pivot root id");
    assert_ne!(old_root_id, stage_id, "precondition: stage != old root");
    vfs::mount::pivot_root(&stage_d, &stage_d).expect("pivot_root(stage, stage)");
    let new_root_id = vfs::mount::root_mount_id(common::namespace_id(sandbox)).expect("post-pivot root id");
    assert_eq!(new_root_id, stage_id, "after pivot_root the stage bind IS the ns root");
    let new_root = vfs::mount::root_dentry_for_mount_id(stage_id).expect("post-pivot root dentry");
    let dev = vfs::path_lookup_at_root_cred(
        new_root.clone(), stage_id, new_root.clone(), stage_id, "/dev",
        LookupFlags::default(), vfs::Cred::root())
        .expect("post-pivot /dev must resolve");
    assert_ne!(dev.mnt_id, stage_id, "post-pivot /dev must remain a carried submount");
    assert_eq!(dev.inode.ino(), 0x502, "post-pivot /dev must resolve the carried devtmpfs root");

    // 6. umount2(old_root, MNT_DETACH): the old root is now stacked under `/`.
    //    systemd's `pivot_root(., .); umount2(., MNT_DETACH)` idiom. The old-root
    //    mount must still exist and detach cleanly (recursive == MNT_DETACH lazy).
    let om = vfs::mount::mount_by_id(old_root_id).expect("old root still present after pivot");
    let omp = om.mountpoint().expect("old root has a mountpoint after stacking pivot");
    // Overmount lookup (Linux `lookup_mnt`): resolving the mountpoint dentry that
    // `.`/`/` map to after the stacking pivot MUST find the STACKED old root, not
    // the underlay ns-root. This is precisely what lets the syscall's
    // `umount2(".", MNT_DETACH)` (resolved via the live cwd dentry) reach the old
    // root instead of the ns-root — without it, the switch-root cleanup EINVALs.
    assert_eq!(vfs::mount::mount_at_path_exact(&omp).map(|m| m.mnt_id), Some(old_root_id),
        "mountpoint dentry must resolve to the stacked old root (overmount), not the ns-root");
    let n = vfs::mount::unregister_top(&omp, true);
    assert!(n > 0, "umount2(old_root, MNT_DETACH) must detach the stacked old root (got {n})");
    assert!(vfs::mount::mount_by_id(old_root_id).is_none(),
        "old root gone from the ns after detach");
    // The ns root is still the stage bind — the switch-root completed.
    assert_eq!(vfs::mount::root_mount_id(common::namespace_id(sandbox)), Some(stage_id),
        "ns root remains the stage bind after old-root detach");
    let new_root = vfs::mount::root_dentry_for_mount_id(stage_id).expect("post-pivot root dentry");
    let run_dir = vfs::path_lookup_at_root_cred(
        new_root.clone(), stage_id, new_root, stage_id, "/run",
        LookupFlags::default(), vfs::Cred::root())
        .expect("post-pivot /run must resolve through tmpfs, not ext4 underlay");
    assert_ne!(run_dir.inode.ino(), 0x13, "/run fell back to ext4 underlay");
}


