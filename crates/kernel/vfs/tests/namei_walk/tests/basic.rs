use super::*;

#[test]
fn descends_to_file() {
    let (root, host_ino, _) = build_root();
    let (i, _) = look(&root, "/etc/hostname", LookupFlags::default()).expect("resolve");
    assert_eq!(i.ino(), host_ino);
}

#[test]
fn dot_and_dotdot() {
    let (root, host_ino, _) = build_root();
    let (i, _) = look(&root, "/etc/./hostname", LookupFlags::default()).expect("dot");
    assert_eq!(i.ino(), host_ino);
    let (j, _) = look(&root, "/etc/../etc/hostname", LookupFlags::default()).expect("dotdot");
    assert_eq!(j.ino(), host_ino);
    // `..` at root stays at root.
    let (k, _) = look(&root, "/../etc/hostname", LookupFlags::default()).expect("dotdot-root");
    assert_eq!(k.ino(), host_ino);
}

#[test]
fn follows_relative_symlink() {
    let (root, host_ino, _) = build_root();
    let (i, _) = look(&root, "/link_rel", LookupFlags::default()).expect("rel symlink");
    assert_eq!(i.ino(), host_ino, "link_rel → etc/hostname");
}

#[test]
fn follows_non_utf8_symlink_target_without_lossy_decode() {
    let (root, _, _) = build_root();
    let (i, _) = look(&root, "/link_raw", LookupFlags::default()).expect("raw-byte symlink target");
    assert_eq!(i.ino(), 41, "symlink target bytes must not be replaced by U+FFFD");
}

#[test]
fn follows_absolute_symlink() {
    let (root, _, utc_ino) = build_root();
    let (i, _) = look(&root, "/etc/localtime", LookupFlags::default()).expect("abs symlink");
    assert_eq!(i.ino(), utc_ino, "localtime → /usr/share/zoneinfo/UTC");
}

#[test]
fn o_nofollow_returns_symlink() {
    let (root, _, _) = build_root();
    let mut f = LookupFlags::default();
    f.no_follow_final = true;
    let (i, _) = look(&root, "/link_rel", f).expect("nofollow");
    assert_eq!(i.file_type(), FileType::Symlink, "final symlink returned, not followed");
}

#[test]
fn resolve_no_symlinks_errors() {
    let (root, _, _) = build_root();
    let mut f = LookupFlags::default();
    f.no_symlinks = true;
    assert_eq!(look(&root, "/link_rel", f).err(), Some(VfsError::Eloop));
}

#[test]
fn symlink_loop_is_eloop() {
    let (root, _, _) = build_root();
    assert_eq!(look(&root, "/loopa", LookupFlags::default()).err(), Some(VfsError::Eloop));
}

#[test]
fn missing_component_enoent() {
    let (root, _, _) = build_root();
    assert_eq!(look(&root, "/etc/nope", LookupFlags::default()).err(), Some(VfsError::Enoent));
}

// Mount crossing: /mnt whose root holds `file` is crossed by DENTRY
// IDENTITY plus namespace-scoped covering mount id; resolution below the
// mount root is per-component (`d_lookup → i_op->lookup`).
#[test]
fn crosses_mount_point() {
    let mnt_file = file(99);
    let mnt_root = dir(98, &[("file", mnt_file)]);

    // Root tree gains an empty `/mnt` directory the fs is mounted over.
    let empty_mnt = dir(50, &[]);
    let root_inode = dir(2, &[("mnt", empty_mnt)]);
    let root = Dentry::new_root(root_inode);

    // Resolve /mnt to its canonical dentry, then mount the test fs there
    // (`register_bind` inserts the `(parent,dentry)` crossing into the strict
    // mount hash — the walk crosses via `__lookup_mnt`).
    let (_, mnt_d) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("resolve /mnt");
    let _mnt_id = mount_id_for(&mnt_d, mnt_root);

    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/mnt/file", LookupFlags::default())
        .expect("cross into mount");
    assert_eq!(i.ino(), 99, "resolved file inside the mounted fs, not the underlay");
}

// Deep crossing into a mounted (procfs-style) filesystem: the walker
// crosses at `/proc` by dentry identity, then resolves `123 → stat`
// per-component through the mount root's inode tree — NO whole-path
// delegate (WP2 deleted it).
#[test]
fn crosses_into_mount_and_resolves_per_component() {
    let stat = file(301);
    let pid_dir = dir(124, &[("stat", stat)]);
    let proc_root = dir(123, &[("123", pid_dir)]);

    let empty_proc = dir(60, &[]);
    let root_inode = dir(2, &[("proc", empty_proc)]);
    let root = Dentry::new_root(root_inode);

    let (_, proc_d) = vfs::path_lookup(root.clone(), root.clone(), "/proc", LookupFlags::default())
        .expect("resolve /proc");
    let _mnt_id = mount_id_for(&proc_d, proc_root);

    let (i, _) = vfs::path_lookup(root.clone(), root, "/proc/123/stat", LookupFlags::default())
        .expect("cross into procfs mount + resolve per-component");
    assert_eq!(i.ino(), 301, "resolved /proc/123/stat per-component across the mount");
}

// Per-fs conformance: a multi-component path resolves PURELY via
// `d_lookup → i_op->lookup → d_add`. This is the WP2 end-state contract for
// every SuperBlock-owned fs (ext4/tmpfs/devfs/sysfs/procfs/cgroup): the first
// walk populates the (parent,name)-keyed dcache from each directory inode's
// per-component `lookup`, and a second walk is served from that cache.
#[test]
fn multi_component_resolves_via_dlookup_iop_lookup_dadd() {
    // A real fs-root shape: / → a → b → c (regular file), all per-component.
    let c = file(0xC);
    let b = dir(0xB, &[("c", c)]);
    let a = dir(0xA, &[("b", b)]);
    let root_inode = dir(2, &[("a", a)]);
    let root = Dentry::new_root(root_inode);

    // First walk: the dcache for each component starts empty, so each step
    // takes the slow path `i_op->lookup(parent_inode, name)` then `d_add`.
    assert!(vfs::d_lookup(&root, "a").is_none(), "cache cold before the walk");
    let (i, leaf_d) = vfs::path_lookup(root.clone(), root.clone(), "/a/b/c", LookupFlags::default())
        .expect("multi-component per-component resolve");
    assert_eq!(i.ino(), 0xC, "resolved /a/b/c to the file inode");

    // d_add populated every (parent,name) edge along the path: the dcache
    // fast path `d_lookup` now returns the SAME dentry objects (by identity).
    let a_d = vfs::d_lookup(&root, "a").expect("a cached by d_add");
    assert!(!a_d.is_negative());
    let b_d = vfs::d_lookup(&a_d, "b").expect("b cached by d_add");
    let c_d = vfs::d_lookup(&b_d, "c").expect("c cached by d_add");
    assert!(alloc_ptr_eq(&c_d, &leaf_d), "second lookup returns the walk's leaf dentry");

    // Second walk is served from the dcache (fast path) and agrees.
    let (i2, _) = vfs::path_lookup(root.clone(), root, "/a/b/c", LookupFlags::default())
        .expect("cached re-resolve");
    assert_eq!(i2.ino(), 0xC, "cached resolution matches");
}


