use super::*;

#[test]
fn crossing_returns_mounted_s_root_not_underlay() {
    let mnt_file = file(99);
    let mnt_root = dir(98, &[("file", mnt_file)]);

    let empty_mnt = dir(50, &[]);
    let root_inode = dir(2, &[("mnt", empty_mnt)]);
    let root = Dentry::new_root(root_inode);

    let (_, underlay_mnt) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("resolve /mnt underlay");
    let mnt_id = mount_id_for(&underlay_mnt, mnt_root);
    let s_root = vfs::mount::root_dentry_for_mount_id(mnt_id).expect("mount s_root");

    // Walking exactly the mountpoint returns the mounted s_root, not underlay.
    let (i, d) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("cross at mountpoint");
    assert_eq!(i.ino(), 98, "inode is the mounted-fs root");
    assert!(Arc::ptr_eq(&d, &s_root), "dentry IS the mount s_root (keystone)");
    assert!(!Arc::ptr_eq(&d, &underlay_mnt), "dentry is NOT the underlay mountpoint");
    assert!(d.is_root(), "mounted dentry is a D_ROOT");

    // A child under the mount is parented on the mounted s_root chain.
    let (ci, cd) = vfs::path_lookup(root.clone(), root, "/mnt/file", LookupFlags::default())
        .expect("resolve child in mount");
    assert_eq!(ci.ino(), 99);
    assert!(Arc::ptr_eq(cd.parent().expect("child parent"), &s_root),
        "child's parent is the mount s_root, not the underlay");
}

// d_path / absolute_path is mount-aware (Linux `prepend_path`): a file inside a
// mount reconstructs the GLOBAL path `/dev/null`, crossing from the mounted
// `s_root` back to the `/dev` mountpoint — not the collapsed `/null`.
#[test]
fn d_path_is_mount_aware_across_crossing() {
    let null = file(0xF0);
    let dev_root = dir(0xD0, &[("null", null)]);
    let underlay_dev = dir(0x10, &[]);
    let root_inode = dir(2, &[("dev", underlay_dev)]);
    let root = Dentry::new_root(root_inode);

    let (_, underlay) = vfs::path_lookup(root.clone(), root.clone(), "/dev", LookupFlags::default())
        .expect("resolve /dev");
    let _mnt = mount_id_for(&underlay, dev_root);

    let (_, nulld) = vfs::path_lookup(root.clone(), root, "/dev/null", LookupFlags::default())
        .expect("resolve /dev/null");
    assert_eq!(nulld.absolute_path(), b"/dev/null",
        "global path reconstructed across the mount, not collapsed to /null");
}

// `..` across a mount (`follow_dotdot`): from inside a mount at `/mnt`, `..`
// crosses back to the mountpoint's PARENT in the underlay tree — landing on the
// global `/` (ino 2), not stuck at the parentless mounted s_root.
#[test]
fn dotdot_crosses_back_over_mount() {
    let mnt_file = file(99);
    let mnt_root = dir(98, &[("file", mnt_file)]);
    let empty_mnt = dir(50, &[]);
    let root_inode = dir(2, &[("mnt", empty_mnt)]);
    let root = Dentry::new_root(root_inode);

    let (_, underlay_mnt) = vfs::path_lookup(root.clone(), root.clone(), "/mnt", LookupFlags::default())
        .expect("resolve /mnt");
    let _mnt_id = mount_id_for(&underlay_mnt, mnt_root);

    // /mnt/.. : cross into the mount (s_root), then `..` crosses back over the
    // mountpoint to the underlay parent = global root.
    let (i, _) = vfs::path_lookup(root.clone(), root.clone(), "/mnt/..", LookupFlags::default())
        .expect("dotdot across mount");
    assert_eq!(i.ino(), 2, ".. from a mount root lands on the global / (underlay parent)");

    // /mnt/../mnt/file resolves the child again after crossing back.
    let (j, _) = vfs::path_lookup(root.clone(), root, "/mnt/../mnt/file", LookupFlags::default())
        .expect("dotdot then re-descend");
    assert_eq!(j.ino(), 99);
}

// ELOOP at MAXSYMLINKS=40 (nd.depth): a chain of >40 symlinks exhausts the
// budget and returns Eloop.
#[test]
fn eloop_at_max_symlink_depth() {
    // s0 -> s1 -> ... -> s49 -> target(file). 50 symlink follows > 40.
    let target = file(0x7777);
    let mut kids: Vec<(String, InodeRef)> = Vec::new();
    kids.push(("target".to_string(), target));
    for i in 0..50u32 {
        let next = if i + 1 < 50 { format!("s{}", i + 1) } else { "target".to_string() };
        kids.push((format!("s{}", i), sym(1000 + i as u64, &next)));
    }
    let refs: Vec<(&str, InodeRef)> = kids.iter().map(|(n, i)| (n.as_str(), i.clone())).collect();
    let root_inode = dir(2, &refs);
    let root = Dentry::new_root(root_inode);
    assert_eq!(look(&root, "/s0", LookupFlags::default()).err(), Some(VfsError::Eloop),
        "chain of >40 symlinks is ELOOP");
}

// RESOLVE_NO_SYMLINKS rejects an INTERMEDIATE-component symlink (not just the
// final), complementing `resolve_no_symlinks_errors`.
#[test]
fn resolve_no_symlinks_errors_on_intermediate() {
    let leaf = file(0x88);
    let real = dir(0x80, &[("leaf", leaf)]);
    let root_inode = dir(2, &[("real", real), ("lnk", sym(0x81, "real"))]);
    let root = Dentry::new_root(root_inode);
    // Sanity: without the flag, /lnk/leaf resolves via the symlink.
    assert_eq!(look(&root, "/lnk/leaf", LookupFlags::default()).map(|(i, _)| i.ino()), Ok(0x88));
    let mut f = LookupFlags::default();
    f.no_symlinks = true;
    assert_eq!(look(&root, "/lnk/leaf", f).err(), Some(VfsError::Eloop),
        "intermediate symlink rejected under RESOLVE_NO_SYMLINKS");
}


