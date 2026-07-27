use alloc::string::String;
use alloc::sync::{Arc, Weak};

use vfs::{CreateCtx, FileType, InodeRef, VfsError};

use super::{TmpfsFs, TmpfsSb};
use super::dir::make_tmpfs_dir_inode;
use super::file::make_tmpfs_file_inode;
use super::limits::{PG, ROOT_INO};
use super::symlink::make_tmpfs_symlink_inode;
use super::uapi::TMPFS_MAGIC;

mod statfs_tests {
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
        for _ in 0..4 { assert!(sb.charge_block()); }
        assert!(!sb.charge_block());
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
        let t = TmpfsFs::from_mount_data(String::from("/run"), "");
        let r = TmpfsFs::ramfs_from_mount_data("");
        assert_eq!(t.magic(), TMPFS_MAGIC);
        assert_eq!(r.magic(), RAMFS_MAGIC);
        assert_ne!(TMPFS_MAGIC, RAMFS_MAGIC);
        assert_eq!(RAMFS_MAGIC, 0x8584_58f6, "linux/magic.h RAMFS_MAGIC");
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
        assert!(sb.charge_block());
        assert!(sb.charge_inode());
        let st = sb.statfs(TMPFS_MAGIC);
        assert_eq!((st.f_blocks, st.f_bfree, st.f_bavail), (100, 99, 99));
        assert_eq!((st.f_files, st.f_ffree), (10, 9));
        assert_eq!(st.f_namelen, vfs::path::NAME_MAX as u64);
    }
}

#[cfg(test)]
mod iget;

#[cfg(test)]
mod rename_overwrite_tests {
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
}

#[cfg(test)]
mod symlink_tests {
    use super::*;
    // tmpfs symlink inode round-trips its target (the systemd /run case).
    #[test]
    fn symlink_inode_readlink_roundtrips() {
        let s = make_tmpfs_symlink_inode(b"/usr/share/zoneinfo/UTC", 0, 0, Weak::new());
        assert_eq!(s.file_type(), FileType::Symlink);
        assert_eq!(s.size(), 23);
        assert_eq!(s.readlink().unwrap(), b"/usr/share/zoneinfo/UTC".to_vec());
    }
    // symlink_child creates a followable symlink resolved per-component from
    // the dir's own kids map (no global registry).
    #[test]
    fn dir_symlink_child_creates_followable_link() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        root.symlink_child("tz", b"/etc/localtime", &CreateCtx::root()).expect("create symlink");
        let resolved = root.lookup("tz").expect("symlink in tree");
        assert_eq!(resolved.file_type(), FileType::Symlink);
        assert_eq!(resolved.readlink().unwrap(), b"/etc/localtime".to_vec());
        // Eexist on a second create.
        assert!(matches!(root.symlink_child("tz", b"/x", &CreateCtx::root()), Err(VfsError::Eexist)));
    }
}

#[cfg(test)]
mod nlink_mode_tests {
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
}

// D45: xattrs are FILESYSTEM-backed — each tmpfs inode OWNS its own xattr store
// (Linux shmem_inode_info / `simple_xattrs`), so set/get/list/remove round-trip
// per-inode and two inodes never see each other's attributes. Exercised through
// the `i_op` hooks (the same path `fs::xattr` dispatches to), no global table,
// no PMM (xattr ops touch no frames).
#[cfg(test)]
mod xattr_tests {
    use super::*;
    use vfs::xattr::XattrError;

    fn file() -> InodeRef { make_tmpfs_file_inode(false, 0o644, 0, 0, Weak::new(), TmpfsSb::unlimited()) }

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
}

// `mount -o mode=/uid=/gid=/size=/nr_inodes=` option-string parsing + the
// root-inode ownership/limits it drives. This is the /run/user/UID blocker:
// systemd-user-runtime-dir mounts the per-user runtime dir mode 0700 owned by
// UID:UID; before the parser the option string was dropped, mounting root:root
// 0755 which pam_systemd / `systemd --user` reject.
mod mount_opts_tests {
    use super::*;
    use super::super::mount_opts::{SizeVal, TmpfsOpts};
    use super::super::limits::PG;

    // The exact string systemd-user-runtime-dir passes for uid 979.
    #[test]
    fn parses_systemd_run_user_string() {
        // size in bytes (systemd's `size=%lu`), nr_inodes an explicit count.
        let data = "mode=0700,uid=979,gid=979,size=402886656,nr_inodes=819200";
        let o = TmpfsOpts::parse(data, 0);
        assert_eq!(o.mode, Some(0o700));
        assert_eq!(o.uid, Some(979));
        assert_eq!(o.gid, Some(979));
        assert_eq!(o.size_bytes, Some(402_886_656));
        assert_eq!(o.nr_inodes, Some(819_200));
        // 402886656 bytes / 4096 = 98362 pages (exact multiple here).
        assert_eq!(o.resolve_blocks(1 << 20), 402_886_656 / PG as u64);
        assert_eq!(o.resolve_inodes(1 << 20), 819_200);
    }

    // A partial `size` (non-page-multiple) rounds UP to whole pages, and unknown
    // keys / bare flags are ignored rather than causing a parse failure.
    #[test]
    fn size_rounds_up_and_unknown_keys_ignored() {
        let o = TmpfsOpts::parse("size=4097,noswap,smackfsroot=*,mode=1777", 0);
        assert_eq!(o.size_bytes, Some(4097));
        assert_eq!(o.resolve_blocks(999), 2); // ceil(4097/4096)
        assert_eq!(o.mode, Some(0o1777)); // sticky+rwx (Linux /tmp default)
        // Nothing specified for inodes → falls back to the supplied default.
        assert_eq!(o.resolve_inodes(555), 555);
    }

    // Suffixes (k/m/g) and `%`-of-RAM sizing.
    #[test]
    fn size_suffixes_and_percent() {
        assert_eq!(TmpfsOpts::parse("size=64m", 0).size_bytes, Some(64 << 20));
        assert_eq!(TmpfsOpts::parse("size=2g", 0).size_bytes, Some(2u64 << 30));
        // 50% of a 1000-page RAM = 500 pages → 500*PG bytes.
        let o = TmpfsOpts::parse("size=50%", 1000);
        assert_eq!(o.size_bytes, Some(500 * PG as u64));
        // Sanity: parse_size percent helper.
        // (Exercised through parse; also assert the SizeVal variant is right by
        // re-checking the resolved page count.)
        assert_eq!(o.resolve_blocks(1), 500);
        let _ = SizeVal::Bytes(0); // keep the enum import exercised
    }

    // Empty / absent option string → all Linux defaults (0755, 0:0, half-RAM).
    #[test]
    fn empty_data_is_all_defaults() {
        let o = TmpfsOpts::parse("", 0);
        assert_eq!((o.mode, o.uid, o.gid), (None, None, None));
        assert_eq!(o.resolve_blocks(1234), 1234);
        assert_eq!(o.resolve_inodes(1234), 1234);
    }

    // End-to-end: from_mount_data must stamp the ROOT inode's mode/uid/gid so a
    // stat(2) of /run/user/979 shows 0700 owned by 979:979 (the pam_systemd /
    // `systemd --user` requirement). This is the actual regression fixed.
    #[test]
    fn from_mount_data_sets_root_owner_and_mode() {
        let fs = TmpfsFs::from_mount_data(
            String::from("/run/user/979"),
            "mode=0700,uid=979,gid=979,size=402886656,nr_inodes=819200",
        );
        let root = fs.root_inode();
        assert_eq!(root.file_type(), FileType::Directory);
        assert_eq!(root.perm(), Some(0o700), "root must be mode 0700");
        assert_eq!(root.uid(), Some(979), "root must be owned by uid 979");
        assert_eq!(root.gid(), Some(979), "root must be owned by gid 979");
    }

    // No-option mount keeps the historical Linux default (0755 root:root) so the
    // rootfs `/tmp`, `/run`, `/dev/shm` mounts are unchanged.
    #[test]
    fn from_mount_data_default_is_root_owned_0755() {
        let fs = TmpfsFs::from_mount_data(String::from("/tmp"), "");
        let root = fs.root_inode();
        assert_eq!(root.perm(), Some(0o755));
        assert_eq!((root.uid(), root.gid()), (Some(0), Some(0)));
    }
}
