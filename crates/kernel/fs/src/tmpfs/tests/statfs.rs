    use super::*;
    use vfs::fs::FileSystem;

    // D33/D6: the accounting arithmetic statfs reports — block charge/free hits
    // the limit (the ENOSPC source) and f_bfree/f_ffree track usage. Exercised
    // directly so it needs no initialised PMM (frame alloc) in hosted tests.
    #[test]
    fn sb_block_inode_accounting_arithmetic() {
        let sb = TmpfsSb::new(4, 4);
        let s0 = sb.statfs(TMPFS_MAGIC);
        assert_eq!((s0.f_type, s0.f_bsize as usize), (TMPFS_MAGIC, PG));
        assert_eq!((s0.f_blocks, s0.f_bfree, s0.f_files, s0.f_ffree), (4, 4, 4, 4));
        // Charge 4 blocks → 5th is refused (ENOSPC).
        for _ in 0..4 { assert!(sb.charge_blocks(1)); }
        assert!(!sb.charge_blocks(1));
        assert_eq!(sb.statfs(TMPFS_MAGIC).f_bfree, 0);
        sb.free_blocks(2);
        assert_eq!(sb.statfs(TMPFS_MAGIC).f_bfree, 2);
        // Inodes behave the same.
        for _ in 0..4 { assert!(sb.charge_inode()); }
        assert!(!sb.charge_inode());
        assert_eq!(sb.statfs(TMPFS_MAGIC).f_ffree, 0);
        sb.free_inode();
        assert_eq!(sb.statfs(TMPFS_MAGIC).f_ffree, 1);
    }

    // D33: per-instance inode accounting through the directory ops — the root
    // counts, create/mkdir charge, unlink/rmdir reclaim, and an inode-limit hit
    // returns ENOSPC. (No data writes → no PMM dependency.)
    #[test]
    fn instance_inode_accounting_and_enospc() {
        // 3 inodes: root takes one, leaving room for two entries.
        let fs = TmpfsFs::with_limits(String::from("/"), TmpfsSb::new(64, 3));
        let root = fs.root_inode();
        let sops = fs.super_ops().expect("tmpfs super_ops");
        assert_eq!(sops.statfs().unwrap().f_ffree, 2); // root charged

        root.create_child("f", 0o644, &CreateCtx::root()).expect("create f");
        root.mkdir("d", 0o755, &CreateCtx::root()).expect("mkdir d");
        assert_eq!(sops.statfs().unwrap().f_ffree, 0);
        // Inode limit reached → next create is ENOSPC.
        assert!(matches!(root.create_child("g", 0o644, &CreateCtx::root()), Err(VfsError::Enospc)));

        // Reclaim both entries.
        root.unlink_child("f").expect("unlink f");
        root.rmdir("d").expect("rmdir d");
        assert_eq!(sops.statfs().unwrap().f_ffree, 2);
    }

    // statfs `f_type` is the mount's own identity. ramfs and tmpfs share this
    // in-memory tree but are DISTINCT Linux filesystems: a probe that keys on
    // `f_type` (or reads /proc/mounts) must be able to tell them apart, so
    // reporting one hardcoded magic for both is a real userspace-visible bug.
    #[test]
    fn ramfs_and_tmpfs_report_their_own_magic_and_name() {
        use super::super::uapi::RAMFS_MAGIC;
        let t = TmpfsFs::from_mount_data(String::from("/run"), "").unwrap();
        let r = TmpfsFs::ramfs_from_mount_data("").unwrap();
        assert_eq!(t.magic(), TMPFS_MAGIC);
        assert_eq!(r.magic(), RAMFS_MAGIC);
        assert_ne!(TMPFS_MAGIC, RAMFS_MAGIC);
        assert_eq!(RAMFS_MAGIC, 0x8584_58f6, "RAMFS_MAGIC statfs f_type value");
        assert_eq!(t.name(), "tmpfs");
        assert_eq!(r.name(), "ramfs");
        // The magic reaches statfs through `s_op`, not just `FileSystem::magic`.
        assert_eq!(t.super_ops().unwrap().statfs().unwrap().f_type, TMPFS_MAGIC);
        assert_eq!(r.super_ops().unwrap().statfs().unwrap().f_type, RAMFS_MAGIC);
    }

    // Linux `shmem_statfs` leaves the counters zero when the instance has no
    // ceiling; reporting u64::MAX blocks would make `df` print an exabyte-scale
    // filesystem. ramfs (limit-less by design) is exactly that case.
    #[test]
    fn an_unbounded_instance_reports_zero_accounting_not_a_saturated_count() {
        let st = TmpfsSb::unlimited().statfs(TMPFS_MAGIC);
        assert_eq!((st.f_blocks, st.f_bfree, st.f_bavail), (0, 0, 0));
        assert_eq!((st.f_files, st.f_ffree), (0, 0));
        // Identity fields are still reported.
        assert_eq!(st.f_type, TMPFS_MAGIC);
        assert_eq!(st.f_bsize as usize, PG);
        assert_eq!(st.f_frsize as usize, PG);
        assert_eq!(st.f_namelen, vfs::path::NAME_MAX as u64, "shmem_statfs sets NAME_MAX");
    }

    // A BOUNDED instance reports its real ceiling and live usage.
    #[test]
    fn a_bounded_instance_reports_its_real_limits() {
        let sb = TmpfsSb::new(100, 10);
        assert!(sb.charge_blocks(1));
        assert!(sb.charge_inode());
        let st = sb.statfs(TMPFS_MAGIC);
        assert_eq!((st.f_blocks, st.f_bfree, st.f_bavail), (100, 99, 99));
        assert_eq!((st.f_files, st.f_ffree), (10, 9));
        assert_eq!(st.f_namelen, vfs::path::NAME_MAX as u64);
    }
