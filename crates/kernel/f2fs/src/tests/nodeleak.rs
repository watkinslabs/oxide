//! What a write that runs out of room must NOT leave behind.
//!
//! Two failures live here, and both are invisible to a healthy volume. A node
//! whose parent link never landed is allocated, charged and unreachable, so
//! nothing will ever free it; and a node taken while the volume has no space
//! left is metadata growing on a filesystem that is already full. The
//! reference cannot reach either state — its parent link is a memory update,
//! and both its node and its data allocations consult one volume-wide count —
//! so both are checked here against what the tree and the counts say.

use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::quota_image as qi;
use crate::test_image::{self, nodes, ROOT_INO};
use crate::uapi::BLKSIZE;
use crate::volume::quotas::USRQUOTA;
use crate::volume::{NewInode, Volume};
use alloc::vec;
use alloc::vec::Vec;
use sectors::MemImage;
use syscall::errno::Errno;

const NOW: (u64, u32) = (1_800_000_000, 0);
const UID: u32 = 4242;
const QUOTA_INO: u32 = 9;

fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: UID, gid: UID, rdev: 0, now: NOW }
}

/// A volume that accounts space to `UID`, so a charge can be compared with
/// what the file's own tree holds.
fn vol() -> Volume<MemImage> {
    let file = qi::user_file(UID, 0, 0);
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_QUOTA_INO;
    b.qf_ino[USRQUOTA] = QUOTA_INO;
    let blocks: Vec<(u64, Vec<u8>)> =
        file.chunks(BLKSIZE).enumerate().map(|(i, c)| (i as u64, c.to_vec())).collect();
    nodes::add_sparse_file(&mut b, QUOTA_INO, file.len() as u64, &blocks);
    let mut o = Options::defaults();
    o.usrquota = true;
    let mut v = b.mount_opts(o).unwrap();
    v.set_clock(NOW.0);
    v
}

#[test]
fn a_write_that_runs_out_of_room_leaves_no_node_the_tree_cannot_reach() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    // Far apart, so each write builds its own branch of the node tree, until
    // the volume has nothing left to build one out of.
    for i in 0..1024u64 {
        // The room is taken at the write and the block is chosen at the
        // flush, so either can be the one that runs out.
        let r = v.write_file(ino, (i + 1) * 4096 * BLKSIZE as u64, b"x")
            .and_then(|n| v.sync_data().map(|()| n));
        let charged = v.quota_record(USRQUOTA, UID).unwrap().curspace / BLKSIZE as u64;
        let held = v.count_blocks(ino).unwrap();
        // The inode's own block is counted by the tree walk and never charged
        // as space, so the two differ by exactly one — a wider gap is a node
        // charged to the owner that the tree can no longer reach.
        assert_eq!(charged + 1, held, "write {i} charged {charged} but the tree holds {held}");
        if r.is_err() { return; }
    }
    panic!("the volume never ran out of room, so nothing was exercised");
}

#[test]
fn a_volume_with_no_room_left_refuses_a_node_as_well_as_a_block() {
    let mut v = vol();
    let ino = v.create(ROOT_INO, b"f", &spec(), None).unwrap();
    v.write_file(ino, 0, &vec![1u8; BLKSIZE]).unwrap();
    v.sync_data().unwrap();
    let nodes_before = v.valid_node_count;
    // Every remaining block spoken for. The logs still have room inside their
    // open segments, which is exactly the state in which a node allocation
    // that consults only its own log keeps succeeding.
    let left = v.cp.user_block_count - v.valid_block_count;
    v.opts.reserve_root = left as u32;
    // Past the inode's own address array, so it needs a direct node first.
    let apb = v.read_inode(ino).unwrap().addrs_per_inode() as u64;
    let r = v.write_file(ino, apb * BLKSIZE as u64, b"x");
    v.sync_data().unwrap();
    assert_eq!(r, Err(Errno::Enospc), "a full volume let a write through");
    assert_eq!(v.valid_node_count, nodes_before, "a full volume handed out a node block");
}

