use super::*;

#[test]
fn service_namespace_bind_stays_private_pivot_succeeds() {
    let _g = guard();
    let host: u64 = 0x5150_1000;
    let sandbox: u64 = 0x5150_1001;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);

    // 1. systemd makes / SHARED recursively at boot.
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");

    // 2. per-service: unshare mount ns → sandbox, switch to it.
    common::copy_mnt_ns(host, sandbox).unwrap();
    set_ns(sandbox);

    // 3. make-rslave / (recursive) to break propagation to host.
    vfs::mount::set_propagation_recursive(&root, Propagation::Slave).expect("make-rslave /");

    // 4. recursive-bind / onto /run/mount-rootfs (the service rootfs).
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/mount-rootfs", LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    register_test_bind_path_at(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }), root.clone(), None).expect("bind /");
    vfs::mount::bind_submounts_rec(&root, &stage_d);

    // 5. pivot_root(stage, stage): after make-rslave, the bind is NOT shared, so
    //    pivot_root's "old_mnt shared" check MUST pass. If the stage mount is
    //    still SHARED (the bug), this returns EINVAL.
    vfs::mount::pivot_root(&stage_d, &stage_d)
        .expect("pivot_root(stage,stage) — fails EINVAL if the bind stayed SHARED (the sysinit-deadlock bug)");
}

/// The boot does NOT bind `/` directly — it `open_tree(OPEN_TREE_CLONE)`s `/`
/// (while `/` is still SHARED from the boot-time make-rshared) into a DETACHED
/// tree, then binds that fd. Linux `copy_tree` for an open_tree copy makes the
/// clone PRIVATE (no CL_MAKE_SHARED). If ours keeps it SHARED, the service
/// rootfs is shared -> pivot_root EINVAL -> the sysinit deadlock. Isolates that.
#[test]
fn open_tree_clone_of_shared_mount_is_private() {
    let _g = guard();
    let host: u64 = 0x5150_2000;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    let rootm = vfs::mount::mount_at_path_exact(&root).expect("root mount");
    assert_eq!(rootm.propagation.load(Ordering::Acquire), Propagation::Shared as u8, "precondition: / is shared");
    let clone = vfs::mount::clone_mount_tree(&rootm, true);
    let top = &clone[0].m;
    assert_ne!(top.propagation.load(Ordering::Acquire), Propagation::Shared as u8,
        "open_tree(OPEN_TREE_CLONE) of a SHARED mount must yield a PRIVATE clone");
}

#[test]
fn copy_mnt_ns_reports_old_to_new_mount_ids_for_fs_path_remap() {
    let _g = guard();
    let host: u64 = 0x5150_2500;
    let sandbox: u64 = 0x5150_2501;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    let old_root_id = vfs::mount::root_mount_id(common::namespace_id(host)).expect("host root id");
    let run_d = vfs::d_lookup(&root, "run").expect("/run mountpoint dentry");
    let old_run_id = vfs::mount::mount_at_path_exact(&run_d).expect("/run mount").mnt_id;

    let map = common::snapshot_ns_map(host, sandbox).unwrap();
    let mapped = |old| map.iter().find_map(|(o, n)| if *o == old { Some(*n) } else { None });
    let new_root_id = mapped(old_root_id).expect("root mount id remapped");
    let new_run_id = mapped(old_run_id).expect("/run mount id remapped");

    assert_ne!(new_root_id, old_root_id, "namespace copy must mint a new root mount id");
    assert_ne!(new_run_id, old_run_id, "namespace copy must mint a new /run mount id");
    assert_eq!(vfs::mount::root_mount_id(common::namespace_id(sandbox)), Some(new_root_id));
    let new_run = vfs::mount::mount_by_id(new_run_id).expect("new /run mount exists");
    assert_eq!(new_run.namespace_id(), common::namespace_id(sandbox));
    assert_eq!(new_run.mount_point_str(), "/run");
}

/// The `mount(MS_BIND, source, target)` syscall must NOT make the new mount a
/// peer of the SOURCE. Linux `do_loopback` clones with flag 0 (no CL_MAKE_SHARED):
/// a bind's shared-ness comes ONLY from the destination. This is exactly the
/// `165_mount.rs` regression that EINVAL'd pivot_root — the syscall used to
/// `join_peer_group(target, peer_group_of(source))`, so binding a SHARED source
/// onto a NON-shared dest wrongly produced a SHARED mount. Pin it: bind a shared
/// source onto a private `/run` child; the bind must stay PRIVATE (pg 0).
#[test]
fn bind_of_shared_source_onto_private_dest_stays_private() {
    let _g = guard();
    let host: u64 = 0x5150_3000;
    vfs::mount::set_current_ns_provider(cur_ns);
    let root = setup_host(host);
    // Make the SOURCE (`/`) shared — the boot's `make-rshared /`.
    vfs::mount::set_propagation_recursive(&root, Propagation::Shared).expect("make-rshared /");
    let srcm = vfs::mount::mount_at_path_exact(&root).expect("root mount");
    assert_ne!(srcm.peer_group.load(Ordering::Acquire), 0, "precondition: source is in a peer group");
    // `/run` (the destination parent) is a PLAIN mount (private) — models the
    // per-service ns where `make-rslave /` already broke propagation.
    let (_, stage_d) = vfs::path_lookup(root.clone(), root.clone(), "/run/mount-rootfs", LookupFlags::default()).expect("stage");
    let hri = HOST_ROOT_INODE.get().unwrap().clone();
    // The Linux-correct bind path (register_bind + dest-based propagate_mount),
    // WITHOUT the removed source-peer-group inheritance.
    register_test_bind(Some(stage_d.clone()), Arc::new(NamedFs { n: "ext4", root: hri.clone() }), hri).expect("bind");
    let _ = vfs::mount::propagate_mount(&stage_d);
    let bindm = vfs::mount::mount_at_path_exact(&stage_d).expect("bind mount");
    assert_ne!(bindm.propagation.load(Ordering::Acquire), Propagation::Shared as u8,
        "bind of a SHARED source onto a private dest must NOT be shared (Linux do_loopback flag 0)");
    assert_eq!(bindm.peer_group.load(Ordering::Acquire), 0,
        "bind must NOT inherit the source's peer group");
}


