    use super::*;

    // D32: a fresh file starts at nlink=1; a hardlink raises it; unlink lowers
    // it (Linux tmpfs/simple_fs link accounting).
    #[test]
    fn hardlink_raises_and_unlink_lowers_nlink() {
        let fs = TmpfsFs::new(String::from("/"));
        let root = fs.root_inode();
        let f = root.create_child("a", 0o644, &CreateCtx::root()).expect("create a");
        assert_eq!(f.nlink(), 1);
        root.link_child(&f, "b", &CreateCtx::root()).expect("hardlink b");
        assert_eq!(f.nlink(), 2);
        root.unlink_child("b").expect("unlink b");
        assert_eq!(f.nlink(), 1);
        root.unlink_child("a").expect("unlink a");
        assert_eq!(f.nlink(), 0);
    }

    // D32: mkdir starts the child at nlink=2 (".", parent's link down) and
    // raises the PARENT's nlink (the child's ".."); rmdir reverses both.
    #[test]
    fn mkdir_rmdir_maintains_dir_nlink() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        assert_eq!(root.nlink(), 2);
        let sub = root.mkdir("d", 0o755, &CreateCtx::root()).expect("mkdir d");
        assert_eq!(sub.nlink(), 2);
        assert_eq!(root.nlink(), 3); // gained child's ".."
        root.rmdir("d").expect("rmdir d");
        assert_eq!(root.nlink(), 2);
    }

    // D35: mkdir/create honour Linux-prepared permission bits instead of a
    // hardcoded 0o755/0o644; mkdir masks caller-supplied SGID unless inherited
    // from an SGID parent.
    #[test]
    fn create_and_mkdir_honour_mode() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        let f = root.create_child("f", 0o600, &CreateCtx::root()).expect("create f");
        assert_eq!(f.perm(), Some(0o600));
        let d = root.mkdir("d", 0o2750, &CreateCtx::root()).expect("mkdir d");
        assert_eq!(d.perm(), Some(0o750));
    }

    // D35 (idmap lane): a new tmpfs inode takes its owner from the caller cred
    // (fsuid/fsgid) mapped DOWN through the mount idmap, and clears the umask
    // from its perm bits — closing the "tmpfs dirs land uid/gid=0" defect.
    #[test]
    fn create_mkdir_set_owner_from_cred_and_honour_umask() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        let mut cred = vfs::Cred::root();
        cred.uid = 1000; cred.gid = 2000;
        // Non-idmapped (identity) mount: stored fs ids == caller ids; umask
        // clears the group/other write bits (Linux `inode_init_owner`).
        let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0o022 };
        let f = root.create_child("f", 0o666, &ctx).expect("create f");
        assert_eq!((f.uid(), f.gid()), (Some(1000), Some(2000)));
        assert_eq!(f.perm(), Some(0o644)); // 0o666 & ~0o022
        let d = root.mkdir("d", 0o777, &ctx).expect("mkdir d");
        assert_eq!((d.uid(), d.gid()), (Some(1000), Some(2000)));
        assert_eq!(d.perm(), Some(0o755)); // 0o777 & ~0o022

        // Idmapped mount: caller vfs ids are mapped DOWN to the fs ids stored in
        // i_uid/i_gid (uniform extent fs=vfs+10000) — the mnt_idmap path.
        let idmap = vfs::Idmap::uniform(/*fs_lo*/10000, /*vfs_lo*/0, /*count*/65536);
        let ctx2 = CreateCtx { idmap: &idmap, cred: &cred, umask: 0 };
        let g = root.create_child("g", 0o600, &ctx2).expect("create g");
        assert_eq!((g.uid(), g.gid()), (Some(11000), Some(12000)));
    }

    // D24: `i_op->tmpfile` (open(O_TMPFILE)) yields an UNLINKED regular inode in
    // the tree — nlink 0, no directory entry, caller owner, umask-cleared perm —
    // that reads/writes like any file and is reclaimed when its fd closes.
    #[test]
    fn tmpfile_is_anonymous_writable_inode() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        let mut cred = vfs::Cred::root();
        cred.uid = 7; cred.gid = 9;
        let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: &cred, umask: 0o022 };
        let t = root.tmpfile(0o666, &ctx).expect("tmpfile");
        assert_eq!(t.file_type(), FileType::Regular);
        assert_eq!(t.nlink(), 0, "O_TMPFILE inode is unlinked");
        assert_eq!(t.perm(), Some(0o644), "0o666 & ~umask 0o022");
        assert_eq!((t.uid(), t.gid()), (Some(7), Some(9)), "owner from caller cred");
        // No directory entry was created for it (the tree stays empty).
        assert!(matches!(root.lookup("f"), Err(VfsError::Enoent)));
        // It carries this instance's SB so its fsid is the mount's, and it has a
        // page-cache mapping like any regular tmpfs file (data I/O itself needs
        // the PMM, exercised in the boot smoke, not hosted).
        assert!(t.i_mapping().is_some(), "tmpfile has an address_space");
    }

    // D24: a non-directory inode has no `tmpfile` op (the default), so the dir
    // ops' override is what makes O_TMPFILE work only on a directory.
    #[test]
    fn tmpfile_on_file_is_eopnotsupp() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        let f = root.create_child("f", 0o644, &CreateCtx::root()).expect("create f");
        assert!(matches!(f.tmpfile(0o644, &CreateCtx::root()), Err(VfsError::Eopnotsupp)));
    }

    // D28: unlink of a directory returns EISDIR (Linux unlink(2); rmdir is the
    // directory removal path).
    #[test]
    fn unlink_directory_is_eisdir() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        root.mkdir("d", 0o755, &CreateCtx::root()).expect("mkdir d");
        assert!(matches!(root.unlink_child("d"), Err(VfsError::Eisdir)));
        // A regular file still unlinks fine.
        root.create_child("f", 0o644, &CreateCtx::root()).expect("create f");
        assert!(root.unlink_child("f").is_ok());
    }
