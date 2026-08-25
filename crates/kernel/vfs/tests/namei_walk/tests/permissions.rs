use super::*;

// may_lookup (MAY_EXEC per directory): a non-root cred is denied search on a
// directory lacking the exec bit; root (CAP_DAC_OVERRIDE) and exec-able dirs
// resolve.
#[test]
fn may_lookup_denies_non_exec_dir() {
    let secret = file(0x91);
    // /priv perm 0600 (no exec/search), owned by uid 0; /open perm 0755.
    let priv_dir = perm_dir(0x90, 0o600, &[("secret", secret.clone())]);
    let open_dir = perm_dir(0x95, 0o755, &[("secret", secret)]);
    let root_inode = perm_dir(2, 0o755, &[("priv", priv_dir), ("open", open_dir)]);
    let root = Dentry::new_root(root_inode);

    let user = vfs::namei::Cred { uid: 1000, gid: 1000, cap_dac_override: false, cap_dac_read_search: false,
        cap_fowner: false, cap_chown: false, cap_fsetid: false, groups: vfs::GroupList::empty() };

    // Non-root user: search through /priv (no exec bit) is EACCES.
    let denied = vfs::namei::path_lookup_cred(root.clone(), root.clone(), "/priv/secret",
        LookupFlags::default(), user.clone());
    assert_eq!(denied.err(), Some(VfsError::Eacces), "non-exec dir denies search for non-root");

    // Same user CAN search /open (0755).
    let ok = vfs::namei::path_lookup_cred(root.clone(), root.clone(), "/open/secret",
        LookupFlags::default(), user.clone());
    assert_eq!(ok.map(|p| p.inode.ino()), Ok(0x91), "exec dir permits search");

    // Root (default cred, CAP_DAC_OVERRIDE) bypasses the missing exec bit.
    assert_eq!(look(&root, "/priv/secret", LookupFlags::default()).map(|(i, _)| i.ino()), Ok(0x91),
        "root bypasses DAC via CAP_DAC_OVERRIDE");
}

// LOOKUP_DIRECTORY: the final component must be a directory.
#[test]
fn lookup_directory_requires_dir() {
    let (root, _, _) = build_root();
    let mut f = LookupFlags::default();
    f.directory = true;
    assert_eq!(look(&root, "/etc/hostname", f).err(), Some(VfsError::Enotdir),
        "LOOKUP_DIRECTORY on a file is ENOTDIR");
    assert!(look(&root, "/etc", f).is_ok(), "LOOKUP_DIRECTORY on a dir resolves");
}

// LOOKUP_PARENT: stop before the final component, returning the parent dir +
// the leaf name (the mknod/rename/create shape).
#[test]
fn lookup_parent_returns_parent_and_leaf() {
    let (root, _, _) = build_root();
    let mut f = LookupFlags::default();
    f.parent = true;
    let p = vfs::path_lookup_path(root.clone(), root, "/etc/newfile", f).expect("parent walk");
    assert_eq!(p.inode.ino(), 10, "returned dentry is the parent dir /etc (ino 10)");
    assert_eq!(p.last_component.as_deref(), Some("newfile"), "leaf name carried out");
}


