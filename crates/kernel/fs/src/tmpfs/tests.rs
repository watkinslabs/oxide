use alloc::string::String;
use alloc::sync::{Arc, Weak};

use vfs::{CreateCtx, FileType, InodeRef, VfsError};
use vfs::superblock::SuperBlock;

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
        let s0 = sb.statfs();
        assert_eq!((s0.f_type, s0.f_bsize as usize), (TMPFS_MAGIC, PG));
        assert_eq!((s0.f_blocks, s0.f_bfree, s0.f_files, s0.f_ffree), (4, 4, 4, 4));
        // Charge 4 blocks → 5th is refused (ENOSPC).
        for _ in 0..4 { assert!(sb.charge_block()); }
        assert!(!sb.charge_block());
        assert_eq!(sb.statfs().f_bfree, 0);
        sb.free_blocks(2);
        assert_eq!(sb.statfs().f_bfree, 2);
        // Inodes behave the same.
        for _ in 0..4 { assert!(sb.charge_inode()); }
        assert!(!sb.charge_inode());
        assert_eq!(sb.statfs().f_ffree, 0);
        sb.free_inode();
        assert_eq!(sb.statfs().f_ffree, 1);
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
}

#[cfg(test)]
mod iget_tests {
    use super::*;
    use vfs::fs::FileSystem;

    // Build a live tmpfs SuperBlock (fill_super back-stamps the root dir's sb
    // weak, after which children build through `iget`). No PMM needed — no data
    // writes, only inode lifecycle.
    fn live_sb() -> Arc<SuperBlock> {
        let fs = TmpfsFs::new(String::from("/"));
        let root = fs.root_inode();
        SuperBlock::for_backend(fs as Arc<dyn FileSystem>, Some(root), 0x1234_5678, String::from("tmpfs"))
    }

    // [inode D2] A child created on a back-stamped tmpfs mount is registered in
    // the per-SB icache, and a later `ilookup`/`iget` of its ino returns the
    // SAME `Arc` (shared inode identity, Linux iget) — never a fresh duplicate.
    #[test]
    fn create_child_has_icache_identity() {
        let sb = live_sb();
        let root = sb.s_root_inode().expect("root inode");
        let child = root.create_child("f", 0o644, &CreateCtx::root()).expect("create f");
        let ino = child.ino();

        // Registered at build: visible in the icache immediately (no dentry yet).
        let via_lookup = sb.ilookup(ino).expect("child cached in icache");
        assert!(Arc::ptr_eq(&child, &via_lookup), "ilookup returns the SAME Arc");

        // iget is a cache HIT — the build closure must NOT run (would be a fresh
        // duplicate, the bug iget prevents).
        let via_iget = sb.iget(ino, || panic!("iget must hit the cache, not rebuild"));
        assert!(Arc::ptr_eq(&child, &via_iget), "iget returns the SAME Arc");

        // The child carries the mount's SB (fsid derives from s_dev).
        assert_eq!(child.fsid(), 0x1234_5678);
    }

    // [inode D2] An OPEN/held inode is NOT evicted: while any strong `Arc`
    // lives (here the tree's `kids` ref + our handles), the icache `Weak` keeps
    // upgrading. Once the last strong ref drops (unlink removed the kids ref +
    // we drop our handles), the `Weak` dies and the slot reclaims — the
    // Arc/`Weak` reclaim path, exactly as ext4 operates (no `iput` needed).
    #[test]
    fn held_inode_not_evicted_then_reclaimed_on_last_drop() {
        let sb = live_sb();
        let root = sb.s_root_inode().expect("root inode");
        let child = root.create_child("g", 0o644, &CreateCtx::root()).expect("create g");
        let ino = child.ino();

        // Unlink drops the name (and the kids strong ref) but we still hold one.
        root.unlink_child("g").expect("unlink g");
        assert!(sb.ilookup(ino).is_some(), "still held → NOT evicted");

        // Drop the last strong reference → the cache Weak can no longer upgrade.
        drop(child);
        assert!(sb.ilookup(ino).is_none(), "last ref gone → reclaimed");
    }

    // [inode D2] A second create of the SAME name path after reclaim yields a
    // DISTINCT inode (fresh ino), and both never collide in the icache.
    #[test]
    fn distinct_children_distinct_icache_slots() {
        let sb = live_sb();
        let root = sb.s_root_inode().expect("root inode");
        let a = root.create_child("a", 0o644, &CreateCtx::root()).expect("create a");
        let b = root.mkdir("d", 0o755, &CreateCtx::root()).expect("mkdir d");
        assert_ne!(a.ino(), b.ino());
        assert!(Arc::ptr_eq(&a, &sb.ilookup(a.ino()).unwrap()));
        assert!(Arc::ptr_eq(&b, &sb.ilookup(b.ino()).unwrap()));
    }
}

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

        fs.rename("/src", "/dst").expect("rename overwrite");

        // Replaced target lost its link; its inode charge was reclaimed.
        assert_eq!(dst.nlink(), 0, "replaced destination nlink dropped to 0");
        assert_eq!(fs.super_ops().unwrap().statfs().unwrap().f_ffree, free_before + 1);
        // The destination name now resolves to the SOURCE inode (survivor).
        let now = root.lookup("dst").expect("dst present");
        assert!(Arc::ptr_eq(&now, &src), "dst name now holds the source inode");
        assert_eq!(now.nlink(), 1, "moved source keeps its link");
        assert!(matches!(root.lookup("src"), Err(VfsError::Enoent)), "source name gone");
    }

    // RENAME_EXCHANGE (FileSystem::exchange) swaps two existing paths; NEITHER
    // inode loses its link (both survive with nlink unchanged).
    #[test]
    fn exchange_does_not_drop_either_nlink() {
        let fs = TmpfsFs::with_limits(String::from("/"), TmpfsSb::new(64, 16));
        let root = fs.root_inode();
        let a = root.create_child("a", 0o644, &CreateCtx::root()).expect("create a");
        let b = root.create_child("b", 0o644, &CreateCtx::root()).expect("create b");

        fs.exchange("/a", "/b").expect("exchange");

        // Both inodes survive with their single link intact.
        assert_eq!(a.nlink(), 1, "exchange survivor a keeps its link");
        assert_eq!(b.nlink(), 1, "exchange survivor b keeps its link");
        // Names are swapped: /a now holds the old-b inode and vice-versa.
        assert!(Arc::ptr_eq(&root.lookup("a").unwrap(), &b), "/a now holds old b");
        assert!(Arc::ptr_eq(&root.lookup("b").unwrap(), &a), "/b now holds old a");
    }

    // D9: `i_op->rename` (resolved-parent path) — same-dir plain rename moves the
    // source inode onto the destination name, overwriting (and dropping the link
    // of) an existing target, byte-equivalent to `FileSystem::rename`.
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
    // identically to `/` for the i_op write ops, and the whole-path FileSystem
    // fallbacks (mount-relative, leading-`/` stripped) address the same tree.
    #[test]
    fn nonroot_mount_realizes_identically() {
        let fs = TmpfsFs::with_limits(String::from("/run"), TmpfsSb::new(64, 16));
        let root = fs.root_inode();
        assert_eq!(root.ino(), ROOT_INO, "root ino is the fixed constant, not target-derived");
        // i_op create + whole-path FileSystem fallbacks operate on the same tree.
        root.create_child("a", 0o644, &CreateCtx::root()).expect("iop create");
        // FileSystem::create with a mount-relative path hits the SAME inode tree.
        let viafs = fs.create("/a", 0o644).expect("fs create resolves existing");
        assert!(Arc::ptr_eq(&viafs, &root.lookup("a").unwrap()), "fs path == i_op tree");
        // FileSystem::link fallback (whole-path) links within the tree.
        fs.link("/a", "/b").expect("fs link fallback");
        assert!(Arc::ptr_eq(&root.lookup("b").unwrap(), &root.lookup("a").unwrap()), "b is a hardlink of a");
    }

    // D9: `i_op->rename` rejects EXCHANGE/WHITEOUT (those keep the FileSystem
    // path); the inode-op handles only the plain rename.
    #[test]
    fn iop_rename_rejects_exchange_whiteout() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        root.create_child("x", 0o644, &CreateCtx::root()).expect("x");
        assert!(matches!(
            root.rename_child("x", &root, "y", vfs::namei::RENAME_EXCHANGE, &CreateCtx::root()),
            Err(VfsError::Einval)));
        assert!(matches!(
            root.rename_child("x", &root, "y", vfs::namei::RENAME_WHITEOUT, &CreateCtx::root()),
            Err(VfsError::Einval)));
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
    use vfs::fs::FileSystem;

    // D32: a fresh file starts at nlink=1; a hardlink raises it; unlink lowers
    // it (Linux tmpfs/simple_fs link accounting).
    #[test]
    fn hardlink_raises_and_unlink_lowers_nlink() {
        let fs = TmpfsFs::new(String::from("/"));
        let root = fs.root_inode();
        let f = root.create_child("a", 0o644, &CreateCtx::root()).expect("create a");
        assert_eq!(f.nlink(), 1);
        fs.link_inode(f.clone(), "/b").expect("hardlink b");
        assert_eq!(f.nlink(), 2);
        fs.unlink("/b").expect("unlink b");
        assert_eq!(f.nlink(), 1);
        fs.unlink("/a").expect("unlink a");
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

    // D35: mkdir/create honour the caller-supplied permission bits instead of
    // a hardcoded 0o755/0o644.
    #[test]
    fn create_and_mkdir_honour_mode() {
        let root = make_tmpfs_dir_inode(ROOT_INO, 0o755, 0, 0, Weak::new(), TmpfsSb::unlimited());
        let f = root.create_child("f", 0o600, &CreateCtx::root()).expect("create f");
        assert_eq!(f.perm(), Some(0o600));
        let d = root.mkdir("d", 0o2750, &CreateCtx::root()).expect("mkdir d");
        assert_eq!(d.perm(), Some(0o2750));
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
