use super::*;

// Regression (B53): a mount on a TREE-BACKED directory reached only by
// FIRST crossing an outer mount — the `/sys` (devfs sub-tree) → then
// `/sys/fs/cgroup` (cgroupfs) shape. The inner mountpoint dentry is
// produced lazily during the walk (cached under the crossed-into
// sub-tree's dentry), so marking it via the covering mount id must be
// visible to a SUBSEQUENT walk of a CHILD path — proving the dcache is
// canonical: one dentry per (parent,name) shared by the marking walk and
// the child-resolving walk. This is exactly what the boot cgroupfs
// (mounted before the resolver) needs once `rewire_all_crossings` runs.
#[test]
fn crosses_mount_on_tree_backed_subtree() {
    // Inner mounted fs (cgroupfs analogue): root holds `init.scope`.
    let cg_scope = dir(0x301, &[]);
    let cg_root: InodeRef = dir(0x300, &[("init.scope", cg_scope)]);

    // The crossed-into sub-tree (devfs `/sys` analogue): a tree-backed
    // directory whose own children are produced per-component by lookup.
    // `/sys` underlay dir on the ext4 root, mounted over by `sys_tree`.
    let sys_tree_fs: InodeRef = dir(0x200, &[("fs", dir(0x201, &[("cgroup", dir(0x202, &[]))]))]);
    let sys_underlay = dir(0x100, &[]);
    let root_inode = dir(2, &[("sys", sys_underlay)]);
    let root = Dentry::new_root(root_inode);

    // Mount the sub-tree fs ON `/sys` by dentry identity (outer mount).
    let (_, sys_d) = vfs::path_lookup(root.clone(), root.clone(), "/sys", LookupFlags::default())
        .expect("resolve /sys");
    let _sys_mnt = mount_id_for(&sys_d, sys_tree_fs);

    // Now resolve the INNER mountpoint dentry the way the late
    // rewire does — a full walk that crosses `/sys` then descends the
    // sub-tree. The landed dentry is the canonical one cached under the
    // sub-tree's `fs` dentry.
    let (_, cg_mp) = vfs::path_lookup(root.clone(), root.clone(), "/sys/fs/cgroup", LookupFlags::default())
        .expect("resolve /sys/fs/cgroup mountpoint");
    let _cg_mnt = mount_id_for(&cg_mp, cg_root);

    // A SUBSEQUENT child-path walk must cross into cgroupfs by hitting the
    // SAME cached dentry — proving the mark is canonical / visible.
    let (i, _) = vfs::path_lookup(root.clone(), root, "/sys/fs/cgroup/init.scope", LookupFlags::default())
        .expect("cross into cgroupfs and resolve init.scope");
    assert_eq!(i.ino(), 0x301, "resolved init.scope inside the cgroupfs mount, not the underlay");
}

// chroot confinement (the mechanism pathresolve::resolution_root uses):
// with a sub-dentry as the resolution root + RESOLVE_BENEATH, absolute
// paths restart at that root and `..` cannot ascend above it.
#[test]
fn beneath_confines_dotdot_to_root() {
    let (root, host_ino, _) = build_root();
    // /etc is the "chroot" root.
    let (_, etc_d) = look(&root, "/etc", LookupFlags::default()).expect("etc");
    let mut f = LookupFlags::default();
    f.beneath = true;
    // Absolute path restarts at the chroot root: "/hostname" → etc/hostname.
    let (i, _) = vfs::path_lookup(etc_d.clone(), etc_d.clone(), "/hostname", f).expect("confined");
    assert_eq!(i.ino(), host_ino, "absolute path confined to the chroot root");
    // `..` cannot escape above the chroot root: "/../hostname" stays in etc.
    let (j, _) = vfs::path_lookup(etc_d.clone(), etc_d.clone(), "/../hostname", f).expect("dotdot confined");
    assert_eq!(j.ino(), host_ino, ".. clamped at the chroot root (no escape)");
    // Sanity: the chroot root has no "etc" child, so "/etc/x" must NOT
    // resolve (proves we're rooted at /etc, not the global root).
    assert!(vfs::path_lookup(etc_d.clone(), etc_d.clone(), "/etc/hostname", f).is_err(),
        "global tree not visible from inside the chroot");
}

