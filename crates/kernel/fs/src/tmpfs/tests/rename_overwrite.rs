    use super::*;
    use vfs::fs::FileSystem;

    // A plain rename that OVERWRITES an existing destination drops the replaced
    // target's in-memory nlink to 0 (Linux `vfs_rename`), and reclaims its inode
    // charge; the source inode takes the destination name.
    #[test]
    fn rename_overwrite_drops_replaced_target_nlink() {
        let fs = TmpfsFs::with_limits(String::from("/"), TmpfsSb::new(64, 16));
        let root = fs.root_inode();
        let src = root.create_child("src", 0o644, &CreateCtx::root()).expect("create src");
        let dst = root.create_child("dst", 0o644, &CreateCtx::root()).expect("create dst");
        assert_eq!(dst.nlink(), 1);
        let free_before = fs.super_ops().unwrap().statfs().unwrap().f_ffree;

        root.rename_child("src", &root, "dst", 0, &CreateCtx::root()).expect("rename overwrite");

        // Replaced target lost its link; its inode charge was reclaimed.
        assert_eq!(dst.nlink(), 0, "replaced destination nlink dropped to 0");
        assert_eq!(fs.super_ops().unwrap().statfs().unwrap().f_ffree, free_before + 1);
        // The destination name now resolves to the SOURCE inode (survivor).
        let now = root.lookup("dst").expect("dst present");
        assert!(Arc::ptr_eq(&now, &src), "dst name now holds the source inode");
        assert_eq!(now.nlink(), 1, "moved source keeps its link");
        assert!(matches!(root.lookup("src"), Err(VfsError::Enoent)), "source name gone");
    }

    // RENAME_EXCHANGE swaps two existing names through resolved parent inodes;
    // NEITHER inode loses its link (both survive with nlink unchanged).
    #[test]
    fn exchange_does_not_drop_either_nlink() {
        let fs = TmpfsFs::with_limits(String::from("/"), TmpfsSb::new(64, 16));
        let root = fs.root_inode();
        let a = root.create_child("a", 0o644, &CreateCtx::root()).expect("create a");
        let b = root.create_child("b", 0o644, &CreateCtx::root()).expect("create b");

        root.rename_child("a", &root, "b", vfs::namei::RENAME_EXCHANGE, &CreateCtx::root()).expect("exchange");

        // Both inodes survive with their single link intact.
        assert_eq!(a.nlink(), 1, "exchange survivor a keeps its link");
        assert_eq!(b.nlink(), 1, "exchange survivor b keeps its link");
        // Names are swapped: /a now holds the old-b inode and vice-versa.
        assert!(Arc::ptr_eq(&root.lookup("a").unwrap(), &b), "/a now holds old b");
        assert!(Arc::ptr_eq(&root.lookup("b").unwrap(), &a), "/b now holds old a");
    }

    // D9: `i_op->rename` (resolved-parent path) — same-dir plain rename moves the
    // source inode onto the destination name, overwriting (and dropping the link
    // of) an existing target.
    #[test]
    fn iop_rename_same_dir_overwrites() {
        let fs = TmpfsFs::with_limits(String::from("/"), TmpfsSb::new(64, 16));
        let root = fs.root_inode();
        let src = root.create_child("src", 0o644, &CreateCtx::root()).expect("src");
        let dst = root.create_child("dst", 0o644, &CreateCtx::root()).expect("dst");

        root.rename_child("src", &root, "dst", 0, &CreateCtx::root()).expect("iop rename");

        assert_eq!(dst.nlink(), 0, "replaced dest link dropped");
        assert!(Arc::ptr_eq(&root.lookup("dst").unwrap(), &src), "dst now holds source");
        assert!(matches!(root.lookup("src"), Err(VfsError::Enoent)), "src gone");
    }

    // D9: `i_op->rename` across two directories — the source detaches from its
    // parent and re-attaches under the new parent's name.
    #[test]
    fn iop_rename_cross_dir() {
        let fs = TmpfsFs::with_limits(String::from("/"), TmpfsSb::new(64, 16));
        let root = fs.root_inode();
        let a = root.mkdir("a", 0o755, &CreateCtx::root()).expect("mkdir a");
        let b = root.mkdir("b", 0o755, &CreateCtx::root()).expect("mkdir b");
        let f = a.create_child("f", 0o644, &CreateCtx::root()).expect("create f");

        a.rename_child("f", &b, "g", 0, &CreateCtx::root()).expect("cross-dir rename");

        assert!(matches!(a.lookup("f"), Err(VfsError::Enoent)), "f gone from a");
        assert!(Arc::ptr_eq(&b.lookup("g").unwrap(), &f), "f now b/g");
    }

    // D9/D13: `i_op->link` (resolved-parent path) — hardlink an existing inode
    // into a NON-ROOT directory under a new name. The new name resolves to the
    // SAME inode (`Arc::ptr_eq`), its `i_nlink` bumps, EEXIST on a taken name,
    // EPERM on a directory source. This is the path tmpfs link/linkat now take,
    // and it must work at a non-root parent (the `/run/.../cred` systemd case).
    #[test]
    fn iop_link_child_at_nonroot_dir() {
        let fs = TmpfsFs::with_limits(String::from("/run"), TmpfsSb::new(64, 16));
        let root = fs.root_inode();
        let sub = root.mkdir("sub", 0o755, &CreateCtx::root()).expect("mkdir sub");
        let f = root.create_child("f", 0o644, &CreateCtx::root()).expect("create f");
        assert_eq!(f.nlink(), 1);

        // Hardlink root/f into sub as "alias".
        sub.link_child(&f, "alias", &CreateCtx::root()).expect("iop link");
        let aliased = sub.lookup("alias").expect("alias present");
        assert!(Arc::ptr_eq(&aliased, &f), "alias resolves to the same inode");
        assert_eq!(f.nlink(), 2, "hardlink bumped nlink");

        // EEXIST on a taken name.
        assert!(matches!(sub.link_child(&f, "alias", &CreateCtx::root()), Err(VfsError::Eexist)));
        // EPERM on a directory source (no fs permits directory hardlinks).
        assert!(matches!(sub.link_child(&sub, "dlink", &CreateCtx::root()), Err(VfsError::Eperm)));
    }

    // D13: tmpfs is TARGET-INDEPENDENT — a non-root mount (`/run`) behaves
    // identically to `/` for resolved-parent i_op write ops.
    #[test]
    fn nonroot_mount_realizes_identically() {
        let fs = TmpfsFs::with_limits(String::from("/run"), TmpfsSb::new(64, 16));
        let root = fs.root_inode();
        assert_eq!(root.ino(), ROOT_INO, "root ino is the fixed constant, not target-derived");
        root.create_child("a", 0o644, &CreateCtx::root()).expect("iop create");
        let a = root.lookup("a").expect("a");
        root.link_child(&a, "b", &CreateCtx::root()).expect("iop link");
        assert!(Arc::ptr_eq(&root.lookup("b").unwrap(), &root.lookup("a").unwrap()), "b is a hardlink of a");
    }

    // D9: `i_op->rename` handles EXCHANGE/WHITEOUT by resolved parent inodes;
    // the syscall path must not rewalk filesystem strings for these variants.
    #[test]
    fn iop_rename_handles_exchange_whiteout() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        root.create_child("x", 0o644, &CreateCtx::root()).expect("x");
        root.create_child("y", 0o644, &CreateCtx::root()).expect("y");
        let x = root.lookup("x").expect("x lookup");
        let y = root.lookup("y").expect("y lookup");

        root.rename_child("x", &root, "y", vfs::namei::RENAME_EXCHANGE, &CreateCtx::root()).expect("exchange");
        assert!(Arc::ptr_eq(&root.lookup("x").unwrap(), &y), "x now names old y");
        assert!(Arc::ptr_eq(&root.lookup("y").unwrap(), &x), "y now names old x");

        root.rename_child("y", &root, "z", vfs::namei::RENAME_WHITEOUT, &CreateCtx::root()).expect("whiteout");
        assert!(Arc::ptr_eq(&root.lookup("z").unwrap(), &x), "z now names moved source");
        assert_eq!(root.lookup("y").unwrap().file_type(), FileType::CharDev, "source became whiteout");
    }
