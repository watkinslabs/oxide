// A pty endpoint is what its `i_private` says it is. These pin that a foreign
// inode carrying the EXACT same number resolves to nothing, that a
// cgroup-directory-shaped inode is never a pty, and that the ptmx/slave number
// alias the 15-bit index produced cannot recur.

use alloc::sync::Arc;

use vfs::pseudo_ino::{CGROUP_DIR, DEVPTS};
use vfs::{default_file_ops, default_inode_ops, mk_mode, FileType, InodeBuilder, InodeRef};

use crate::ids;
use crate::inodes::{make_master_inode, make_ptmx_sentinel_inode, make_slave_inode};
use crate::pair::LockedPair;

/// An inode that copies a devpts endpoint's NUMBER, fsid and CharDev type but
/// carries no devpts backend state — the shape the `ino & KIND_MASK` resolver
/// accepted as a live pty.
fn foreign_lookalike(ino: u64, ty: FileType, fsid: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(ty, 0o666), default_inode_ops(), default_file_ops())
        .fsid(fsid)
        .build()
}

#[test]
fn both_halves_resolve_to_their_own_pair_and_side() {
    let a = LockedPair::new(0);
    let b = LockedPair::new(1);
    let (ma, sa) = (make_master_inode(Arc::clone(&a)), make_slave_inode(Arc::clone(&a), &crate::mount_opts::PtsMountOpts::default(), 0, 0));
    let mb = make_master_inode(Arc::clone(&b));

    assert!(crate::is_master_inode(&ma), "master half reports master");
    assert!(!crate::is_master_inode(&sa), "slave half reports slave");
    assert!(crate::is_pty_endpoint(&sa), "the slave is still a pty endpoint");

    let ra = crate::pair_for_inode(&ma).expect("master resolves a pair");
    assert!(Arc::ptr_eq(&ra, &a), "master resolves ITS pair, not another");
    let rs = crate::pair_for_inode(&sa).expect("slave resolves a pair");
    assert!(Arc::ptr_eq(&rs, &a), "both halves share one pair object");
    let rb = crate::pair_for_inode(&mb).expect("second master resolves a pair");
    assert!(!Arc::ptr_eq(&rb, &a), "a different pty resolves a different pair");
}

#[test]
fn foreign_inode_with_the_same_number_is_rejected() {
    let pair = LockedPair::new(7);
    let master = make_master_inode(Arc::clone(&pair));
    let slave = make_slave_inode(Arc::clone(&pair), &crate::mount_opts::PtsMountOpts::default(), 0, 0);

    for real in [&master, &slave] {
        let fake = foreign_lookalike(real.ino(), FileType::CharDev, real.fsid());
        assert_eq!(fake.ino(), real.ino(), "the lookalike copies the number exactly");
        assert!(crate::pair_for_inode(&fake).is_none(),
            "an inode number is not proof of devpts ownership");
        assert!(!crate::is_master_inode(&fake), "nor of which half it is");
        assert!(!crate::is_pty_endpoint(&fake));
    }
}

#[test]
fn a_cgroup_directory_shaped_inode_never_resolves_as_a_pty() {
    // The exact collision: cgroupfs' DIR_INO_BASE and devpts'
    // PTY_MASTER_INO_BASE were both 0x6000_0000, so cgroup dir `cgid` had the
    // number of pty master `cgid`. Only the CharDev-vs-Directory type check in
    // devpts' callers kept it unreachable.
    for cgid in [0u64, 1, 2, 0x3FFF, 0x7FFF] {
        let ino = CGROUP_DIR.at(cgid);
        let dir = foreign_lookalike(ino, FileType::Directory, 0x6367_7270);
        assert!(crate::pair_for_inode(&dir).is_none(), "cgroup dir {ino:#x} is not a pty");
        // …and even if a CharDev ever lands on that number, state decides.
        let chr = foreign_lookalike(ino, FileType::CharDev, 0x6367_7270);
        assert!(crate::pair_for_inode(&chr).is_none(), "type is not what saves us now");
    }
    assert!(!vfs::pseudo_ino::overlaps(&DEVPTS, &CGROUP_DIR),
        "and the two number spaces are disjoint besides");
}

#[test]
fn the_ptmx_sentinel_is_not_an_endpoint() {
    let ptmx = make_ptmx_sentinel_inode();
    assert!(crate::pair_for_inode(&ptmx).is_none(), "/dev/ptmx is a factory, not a pty");
    assert!(!crate::is_master_inode(&ptmx));
}

#[test]
fn no_pts_index_can_alias_a_ptmx_inode() {
    // With the old 15-bit index, slave 0x7FFE/0x7FFF WERE PTMX_MOUNT_INO and
    // PTMX_ROOT_INO. Walk the whole index space and prove it cannot recur.
    for idx in 0..ids::MAX_PTY_PAIRS {
        let (m, s) = (ids::master_ino(idx), ids::slave_ino(idx));
        assert_ne!(m, ids::PTMX_ROOT_INO, "master {idx} aliases /dev/ptmx");
        assert_ne!(m, ids::PTMX_MOUNT_INO, "master {idx} aliases /dev/pts/ptmx");
        assert_ne!(s, ids::PTMX_ROOT_INO, "slave {idx} aliases /dev/ptmx");
        assert_ne!(s, ids::PTMX_MOUNT_INO, "slave {idx} aliases /dev/pts/ptmx");
        assert_ne!(m, s, "the two halves of pty {idx} share a number");
    }
}

#[test]
fn every_minted_number_stays_inside_the_devpts_region() {
    for idx in [0u32, 1, 0x3FFE, ids::MAX_PTY_PAIRS - 1] {
        assert!(DEVPTS.contains(ids::master_ino(idx)), "master {idx} inside DEVPTS");
        assert!(DEVPTS.contains(ids::slave_ino(idx)), "slave {idx} inside DEVPTS");
    }
    assert!(DEVPTS.contains(ids::PTMX_ROOT_INO));
    assert!(DEVPTS.contains(ids::PTMX_MOUNT_INO));
}
