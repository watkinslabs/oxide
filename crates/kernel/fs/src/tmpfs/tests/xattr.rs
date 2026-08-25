// D45: xattrs are FILESYSTEM-backed — each tmpfs inode OWNS its own xattr store
// (Linux shmem_inode_info / `simple_xattrs`), so set/get/list/remove round-trip
// per-inode and two inodes never see each other's attributes. Exercised through
// the `i_op` hooks (the same path `fs::xattr` dispatches to), no global table,
// no PMM (xattr ops touch no frames).
#[cfg(test)]
    use super::*;
    use alloc::vec;
    use alloc::vec::Vec;
    use vfs::posix_acl::{from_xattr, to_xattr, AclEntry, ACL_GROUP_OBJ, ACL_MASK, ACL_OTHER,
                         ACL_UNDEFINED_ID, ACL_USER, ACL_USER_OBJ};
    use vfs::xattr::XattrError;
    use vfs::{Cred, GroupList, Iattr, ATTR_MODE, MAY_READ, MAY_WRITE};

    fn file() -> InodeRef { make_tmpfs_file_inode(false, 0o644, 0, 0, Weak::new(), TmpfsSb::unlimited()) }

    fn entry(tag: u16, perm: u16, id: u32) -> AclEntry { AclEntry { tag, perm, id } }

    fn named_user_acl() -> Vec<u8> {
        to_xattr(&[
            entry(ACL_USER_OBJ, 0o6, ACL_UNDEFINED_ID),
            entry(ACL_USER, 0o6, 1000),
            entry(ACL_GROUP_OBJ, 0o4, ACL_UNDEFINED_ID),
            entry(ACL_MASK, 0o6, ACL_UNDEFINED_ID),
            entry(ACL_OTHER, 0o4, ACL_UNDEFINED_ID),
        ])
    }

    fn user() -> Cred {
        Cred { uid: 1000, gid: 9, cap_dac_override: false, cap_dac_read_search: false,
               cap_fowner: false, cap_chown: false, cap_fsetid: false,
               groups: GroupList::empty() }
    }

    #[test]
    fn chmod_narrows_the_stored_acl_not_only_the_mode() {
        let i = make_tmpfs_file_inode(false, 0o664, 0, 0, Weak::new(), TmpfsSb::unlimited());
        i.setxattr("system.posix_acl_access", named_user_acl(), false, false).expect("set acl");
        assert_eq!(i.permission(MAY_READ | MAY_WRITE, &user()), Ok(()));

        i.setattr(&vfs::IDENTITY,
                  &Iattr { valid: ATTR_MODE, mode: 0o600, ..Iattr::default() })
            .expect("chmod");

        assert_eq!(i.permission(MAY_READ, &user()), Err(VfsError::Eacces));
        let stored = i.getxattr("system.posix_acl_access").expect("acl remains named");
        let acl = from_xattr(&stored).expect("decode acl");
        assert_eq!(acl.iter().find(|e| e.tag == ACL_MASK).unwrap().perm, 0);
    }

    // set → get → list → remove round-trip on ONE tmpfs inode.
    #[test]
    fn set_get_list_remove_roundtrip() {
        let i = file();
        assert!(i.simple_xattrs().is_some(), "tmpfs inode owns an xattr store");
        // set
        i.setxattr("user.color", b"blue".to_vec(), false, false).expect("set");
        i.setxattr("user.size",  b"10".to_vec(),   false, false).expect("set2");
        // get
        assert_eq!(i.getxattr("user.color"), Ok(b"blue".to_vec()));
        assert_eq!(i.getxattr("user.missing"), Err(XattrError::NotFound));
        // list (order-independent membership)
        let mut names = i.listxattr().expect("list");
        names.sort();
        assert_eq!(names, alloc::vec![String::from("user.color"), String::from("user.size")]);
        // remove
        i.removexattr("user.color").expect("remove");
        assert_eq!(i.getxattr("user.color"), Err(XattrError::NotFound));
        assert_eq!(i.removexattr("user.color"), Err(XattrError::NotFound));
        assert_eq!(i.listxattr().unwrap(), alloc::vec![String::from("user.size")]);
    }

    // XATTR_CREATE/XATTR_REPLACE flag semantics, atomic under the store lock.
    #[test]
    fn create_replace_flags() {
        let i = file();
        // REPLACE of an absent name → ENODATA (NotFound).
        assert_eq!(i.setxattr("user.a", b"1".to_vec(), false, true), Err(XattrError::NotFound));
        // CREATE of a new name → ok; CREATE again → EEXIST.
        i.setxattr("user.a", b"1".to_vec(), true, false).expect("create");
        assert_eq!(i.setxattr("user.a", b"2".to_vec(), true, false), Err(XattrError::Exists));
        // REPLACE of an existing name → ok, value updated.
        i.setxattr("user.a", b"3".to_vec(), false, true).expect("replace");
        assert_eq!(i.getxattr("user.a"), Ok(b"3".to_vec()));
    }

    #[test]
    fn xattrs_consume_and_release_tmpfs_inode_space() {
        let fs = TmpfsFs::with_limits(String::from("/"), TmpfsSb::new(64, 2));
        let root = fs.root_inode();
        let large = vec![b'x'; 900];
        root.setxattr("user.payload", large.clone(), false, false).expect("first xattr fits");
        // Replacement charges only the growth delta, so an in-place rewrite
        // remains possible even when the mount has no spare full inode unit.
        root.setxattr("user.payload", large, false, false).expect("same-size replacement");
        assert_eq!(root.setxattr("user.other", vec![b'y'; 100], false, false),
                   Err(XattrError::Fs(VfsError::Enospc)));
        root.removexattr("user.payload").expect("remove releases space");
        root.setxattr("user.other", vec![b'y'; 100], false, false).expect("released space reused");
    }

    // Two inodes are INDEPENDENT — no global table, no cross-inode leakage.
    #[test]
    fn two_inodes_independent() {
        let a = file();
        let b = file();
        a.setxattr("user.k", b"A".to_vec(), false, false).expect("set a");
        b.setxattr("user.k", b"B".to_vec(), false, false).expect("set b");
        assert_eq!(a.getxattr("user.k"), Ok(b"A".to_vec()));
        assert_eq!(b.getxattr("user.k"), Ok(b"B".to_vec()));
        // Removing from one leaves the other untouched.
        a.removexattr("user.k").expect("remove a");
        assert_eq!(a.getxattr("user.k"), Err(XattrError::NotFound));
        assert_eq!(b.getxattr("user.k"), Ok(b"B".to_vec()));
    }
