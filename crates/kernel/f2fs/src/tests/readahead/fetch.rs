//! Readahead against a real volume, asserted on the REQUESTS it makes.
//!
//! Every test here is written so it can fail for the right reason. Contents
//! are identical with readahead and without it, so an assertion over bytes
//! measures nothing; what the medium was ASKED for is the observable, and the
//! fixture records it. Each test names the shape it expects — how many
//! requests, from which block, how many blocks each — so removing the
//! readahead call turns a run of eight blocks into eight requests of one and
//! the test goes red.

use alloc::vec;
use alloc::vec::Vec;

use crate::opts::Options;
use crate::test_image::{self, nodes};
use crate::uapi::BLKSIZE;
use crate::volume::map::Mapped;
use crate::volume::readahead::window::MAX_RA_NODE;
use crate::volume::readahead::RaMeta;
use crate::volume::Volume;

use super::count::Counting;

#[test]
fn compressed_readahead_respects_the_low_memory_mount_mode() {
    assert!(!crate::volume::readahead::data::compressed_readahead_allowed(
        crate::opts::MemoryMode::Low, None));
}

#[test]
fn compressed_readahead_stops_below_the_pmm_low_watermark() {
    assert!(!crate::volume::readahead::data::compressed_readahead_allowed(
        crate::opts::MemoryMode::Normal, Some((99, 100))));
    assert!(crate::volume::readahead::data::compressed_readahead_allowed(
        crate::opts::MemoryMode::Normal, Some((100, 100))));
}

#[test]
fn missing_hosted_pmm_keeps_normal_readahead_advisory() {
    assert!(crate::volume::readahead::data::compressed_readahead_allowed(
        crate::opts::MemoryMode::Normal, None));
}

const FILE_INO: u32 = 9;
/// First block of the main area in the fixture geometry.
const MAIN: u32 = test_image::MAIN_BLKADDR;

/// A volume holding one file with a block at each named index. Consecutive
/// indices get consecutive blocks, because the fixture allocates in the order
/// it is given them — which is the layout a sequential write produces and the
/// one readahead is for.
/// # C: O(blocks)
fn vol_with(indices: &[u64], size: u64) -> Volume<Counting> {
    let mut b = test_image::with_root();
    let blocks: Vec<(u64, Vec<u8>)> = indices.iter()
        .map(|&i| (i, vec![(i as u8).wrapping_add(1); BLKSIZE]))
        .collect();
    nodes::add_sparse_file(&mut b, FILE_INO, size, &blocks);
    Volume::mount_with(Counting::new(b.image()), Options::defaults(), false).unwrap()
}

/// The address of one of the file's blocks, resolved before any measurement
/// so the walk that resolves it is not counted. # C: O(1)
fn addr_of(v: &Volume<Counting>, index: u64) -> u32 {
    let inode = v.read_inode(FILE_INO).unwrap();
    match v.map_block(&inode, FILE_INO, index).unwrap() {
        Mapped::At(a) => a,
        other => panic!("index {index} is {other:?}, not a block"),
    }
}

/// A read spanning a contiguous run of a file asks the medium ONCE.
///
/// The load-bearing test of the whole lane. Without the readahead call in the
/// read path this is eight requests of one block, so the assertion fails on
/// the shape rather than on the contents — which are the same either way.
/// # C: O(1)
#[test]
fn a_sequential_read_is_one_request_for_the_whole_run() {
    let n = 8u64;
    let v = vol_with(&(0..n).collect::<Vec<_>>(), n * BLKSIZE as u64);
    let first = addr_of(&v, 0);
    let inode = v.read_inode(FILE_INO).unwrap();
    v.source_ref().clear();
    let got = v.read_whole(&inode, FILE_INO).unwrap();
    assert_eq!(got.len(), (n * BLKSIZE as u64) as usize);
    assert_eq!(v.source_ref().reqs_in(first, n as u32),
               vec![(u64::from(first), n as usize)]);
}

/// The bytes a merged read returns are the file's bytes, in order.
///
/// The request-shape test above cannot catch a run assembled with the wrong
/// offsets — it would still be one request — so the contents are asserted
/// separately, per block, against what the fixture wrote.
/// # C: O(blocks)
#[test]
fn a_merged_read_returns_each_block_at_its_own_offset() {
    let n = 8u64;
    let v = vol_with(&(0..n).collect::<Vec<_>>(), n * BLKSIZE as u64);
    let inode = v.read_inode(FILE_INO).unwrap();
    let got = v.read_whole(&inode, FILE_INO).unwrap();
    for i in 0..n as usize {
        let want = (i as u8).wrapping_add(1);
        assert!(got[i * BLKSIZE..(i + 1) * BLKSIZE].iter().all(|&b| b == want),
                "block {i} holds another block's bytes");
    }
}

/// A hole ends the run. The blocks either side of it are not adjacent on the
/// medium, so they are two requests — and the hole itself is never fetched,
/// because readahead may not invent the zeroes a hole reads as.
/// # C: O(1)
#[test]
fn a_hole_splits_the_read_into_two_requests() {
    let v = vol_with(&[0, 1, 3, 4], 5 * BLKSIZE as u64);
    let first = addr_of(&v, 0);
    let inode = v.read_inode(FILE_INO).unwrap();
    v.source_ref().clear();
    let got = v.read_whole(&inode, FILE_INO).unwrap();
    assert_eq!(got.len(), 5 * BLKSIZE);
    // Four blocks, in two runs of two: the fixture allocated them in index
    // order, so the hole at index 2 costs no block but does end the run.
    assert_eq!(v.source_ref().reqs_in(first, 4),
               vec![(u64::from(first), 2), (u64::from(first) + 2, 2)]);
    // The hole reads as zeroes and none of them came off the medium.
    assert!(got[2 * BLKSIZE..3 * BLKSIZE].iter().all(|&b| b == 0));
}

/// Readahead never fetches what the caller did not ask for.
///
/// A one-block read stays one block: the window is the request, and a window
/// grown past it would pull in blocks a reader may never touch — and, on a
/// medium that can fail, would report an error for a block nobody wanted.
/// # C: O(1)
#[test]
fn a_short_read_does_not_widen_the_window() {
    let n = 8u64;
    let v = vol_with(&(0..n).collect::<Vec<_>>(), n * BLKSIZE as u64);
    let first = addr_of(&v, 0);
    let inode = v.read_inode(FILE_INO).unwrap();
    v.source_ref().clear();
    let mut buf = [0u8; 16];
    assert_eq!(v.read_file(&inode, FILE_INO, 0, &mut buf).unwrap(), 16);
    assert_eq!(v.source_ref().reqs_in(first, n as u32), vec![(u64::from(first), 1)]);
}

/// A window the mapping already holds costs no transfer at all: the second
/// read of a file asks the medium for none of it. # C: O(1)
#[test]
fn a_window_already_held_costs_no_transfer() {
    let n = 8u64;
    let v = vol_with(&(0..n).collect::<Vec<_>>(), n * BLKSIZE as u64);
    let first = addr_of(&v, 0);
    let inode = v.read_inode(FILE_INO).unwrap();
    v.read_whole(&inode, FILE_INO).unwrap();
    v.source_ref().clear();
    v.read_whole(&inode, FILE_INO).unwrap();
    assert_eq!(v.source_ref().reqs_in(first, n as u32), vec![]);
}

/// A file whose data is inside its own inode gets no window: it has no blocks
/// to fetch, and a window over its address array would read its own bytes as
/// block addresses. # C: O(1)
#[test]
fn an_inline_file_gets_no_window() {
    let mut b = test_image::with_root();
    nodes::add_inline_file(&mut b, FILE_INO, b"small");
    let v = Volume::mount_with(Counting::new(b.image()), Options::defaults(), false).unwrap();
    let inode = v.read_inode(FILE_INO).unwrap();
    v.source_ref().clear();
    assert_eq!(v.read_whole(&inode, FILE_INO).unwrap(), b"small");
    // Nothing in the main area was read: the bytes came out of the inode.
    assert_eq!(v.source_ref().reqs_in(MAIN, u32::MAX - MAIN), vec![]);
}

/// A window past the end of the file fetches nothing. The last block is whole
/// on the medium and its tail is padding, so a readahead bounded by blocks
/// rather than by size would file padding as a page of the file.
/// # C: O(1)
#[test]
fn a_window_past_the_end_fetches_nothing() {
    let v = vol_with(&[0, 1], 2 * BLKSIZE as u64);
    let first = addr_of(&v, 0);
    let inode = v.read_inode(FILE_INO).unwrap();
    v.source_ref().clear();
    v.readahead_data(&inode, FILE_INO, 2, 8);
    assert_eq!(v.source_ref().reqs_in(first, 8), vec![]);
    // From inside the file, the window still stops at the file's size.
    v.readahead_data(&inode, FILE_INO, 0, 8);
    assert_eq!(v.source_ref().reqs_in(first, 8), vec![(u64::from(first), 2)]);
}

/// Sibling node blocks written together are fetched together.
///
/// The two direct nodes under one indirect node are adjacent on the medium
/// because the fixture placed them in order, so prefetching the siblings of a
/// walk costs one request rather than one per node.
/// # C: O(1)
#[test]
fn sibling_nodes_are_one_request() {
    let per_block = crate::uapi::DEF_ADDRS_PER_BLOCK as u64;
    let inode = nodes::Spec::file(FILE_INO);
    // The first index that reaches an indirect node, and the first index under
    // the NEXT direct node below the same indirect node.
    let base = inode.addrs_per_inode() as u64 + 2 * per_block;
    let v = vol_with(&[base, base + per_block], (base + per_block + 1) * BLKSIZE as u64);
    let ino_ref = v.read_inode(FILE_INO).unwrap();
    // Walking to the first index reads the indirect node and the first direct
    // node, and prefetches the second; the walk is done before measuring.
    assert!(matches!(v.map_block(&ino_ref, FILE_INO, base).unwrap(), Mapped::At(_)));
    v.source_ref().clear();
    // The second direct node is already held, so reaching a block under it
    // asks the medium for no node at all.
    assert!(matches!(v.map_block(&ino_ref, FILE_INO, base + per_block).unwrap(), Mapped::At(_)));
    assert_eq!(v.source_ref().reqs_in(MAIN, u32::MAX - MAIN), vec![]);
}

/// Prefetching siblings merges the ones that are adjacent.
///
/// Driven through the sibling entry point directly, with the mapping emptied
/// first, so the assertion is about the transfer shape and not about which
/// walk happened to warm which node.
/// # C: O(1)
#[test]
fn adjacent_siblings_merge_into_one_transfer() {
    let per_block = crate::uapi::DEF_ADDRS_PER_BLOCK as u64;
    let inode = nodes::Spec::file(FILE_INO);
    let base = inode.addrs_per_inode() as u64 + 2 * per_block;
    let v = vol_with(&[base, base + per_block], (base + per_block + 1) * BLKSIZE as u64);
    let ino_ref = v.read_inode(FILE_INO).unwrap();
    let _ = v.map_block(&ino_ref, FILE_INO, base).unwrap();
    // The parent, and the two children it names.
    let inode_block = v.read_inode_ref(FILE_INO).unwrap().1.block;
    let parent_nid = crate::uapi::le32(&inode_block, crate::uapi::I_NID_OFF + 2 * 4).unwrap();
    let parent = v.read_node(parent_nid, Some(FILE_INO)).unwrap().block;
    let kids: Vec<u32> = (0..2).map(|i| crate::node::indirect_nid(&parent, i).unwrap()).collect();
    let addrs: Vec<u32> = kids.iter().map(|&n| v.node_addr(n).unwrap()).collect();
    assert_eq!(addrs[1], addrs[0] + 1, "fixture placed the siblings apart");
    for &n in &kids { v.node_cache.forget(n); }
    v.source_ref().clear();
    v.ra_node_pages(&parent, 0, MAX_RA_NODE);
    assert_eq!(v.source_ref().reqs_in(addrs[0], 2), vec![(u64::from(addrs[0]), 2)]);
    // And both are now held, so a walk through either costs no request.
    assert!(v.node_cache.holds(kids[0]) && v.node_cache.holds(kids[1]));
}

/// A metadata window is one transfer for the consecutive blocks it covers.
/// # C: O(1)
#[test]
fn a_metadata_window_is_one_request() {
    let v = vol_with(&[0], BLKSIZE as u64);
    let start = test_image::CP_BLKADDR;
    v.source_ref().clear();
    assert_eq!(v.ra_meta_pages(start, 4, RaMeta::Cp), 4);
    assert_eq!(v.source_ref().reqs_in(start, 4), vec![(u64::from(start), 4)]);
    // Held now, so the same window asks for nothing.
    v.source_ref().clear();
    assert_eq!(v.ra_meta_pages(start, 4, RaMeta::Cp), 4);
    assert_eq!(v.source_ref().reqs_in(start, 4), vec![]);
}

/// Recovery's main-area window is filed in the same metadata owner as its
/// demand reads, so the chain walk can consume it without another transfer.
/// # C: O(1)
#[test]
fn a_recovery_window_holds_main_nodes_for_the_chain_walk() {
    let v = vol_with(&[0], BLKSIZE as u64);
    v.source_ref().clear();
    assert_eq!(v.ra_meta_pages(MAIN, 4, RaMeta::Por), 4);
    assert_eq!(v.source_ref().reqs_in(MAIN, 4), vec![(u64::from(MAIN), 4)]);
    assert!(v.meta_cache.load_por(MAIN).is_some());

    v.source_ref().clear();
    assert_eq!(v.ra_meta_pages(MAIN, 4, RaMeta::Por), 4);
    assert_eq!(v.source_ref().reqs_in(MAIN, 4), vec![]);
}

/// A metadata window stops at the first index its kind may not reach, and
/// reports how far it got. Reading on would file one area's blocks under
/// another area's name. # C: O(1)
#[test]
fn a_metadata_window_stops_at_its_area_boundary() {
    let v = vol_with(&[0], BLKSIZE as u64);
    let sit = test_image::SIT_BLKADDR;
    v.source_ref().clear();
    // Two blocks below the segment table, asked for four: two are in the pack
    // and the window stops at the boundary.
    assert_eq!(v.ra_meta_pages(sit - 2, 4, RaMeta::Cp), 2);
    assert_eq!(v.source_ref().reqs_in(sit - 2, 4), vec![(u64::from(sit) - 2, 2)]);
    // A summary index that names a checkpoint block is refused outright.
    v.source_ref().clear();
    assert_eq!(v.ra_meta_pages(test_image::CP_BLKADDR, 4, RaMeta::Ssa), 0);
    assert_eq!(v.source_ref().reqs(), vec![]);
}

/// A free-id scan reads its node-table blocks as ONE transfer.
///
/// The wiring test for the metadata window, not a test of the window itself:
/// without the readahead call in the scan this is one request per table block,
/// so the assertion fails on the request shape while the ids handed out stay
/// identical. Consecutive table blocks are adjacent on the medium, which is
/// what makes the merge possible at all.
/// # C: O(1)
#[test]
fn a_free_id_scan_reads_its_table_blocks_in_one_transfer() {
    let mut v = vol_with(&[0], BLKSIZE as u64);
    let nat = test_image::NAT_BLKADDR;
    v.source_ref().clear();
    v.build_free_nids().unwrap();
    let reqs = v.source_ref().reqs_in(nat, crate::freenid::FREE_NID_PAGES);
    // The scan plans a bounded number of blocks and every one of them is in
    // this run, so the whole plan is one request.
    assert_eq!(reqs.len(), 1, "the scan issued {reqs:?}");
    assert!(reqs[0].1 > 1, "one block per request means the window never merged");
}

/// Listing a directory fetches the node block of every inode it names, in one
/// transfer for the ones that were written together.
///
/// The listing itself returns the same entries either way, so the assertion is
/// on the requests: with the prefetch off, reading the listed inodes costs one
/// request each, and the same test with it on costs none.
/// # C: O(1)
#[test]
fn a_listing_prefetches_the_inodes_it_names() {
    const A: u32 = 20;
    const B: u32 = 21;
    let mut b = test_image::with_root();
    // Two empty files, placed one after the other, so nothing lies between
    // their inode blocks and a merged prefetch is one request.
    nodes::add_sparse_file(&mut b, A, 0, &[]);
    nodes::add_sparse_file(&mut b, B, 0, &[]);
    let dir_ino = 22u32;
    nodes::dir::add_block_dir(&mut b, dir_ino, 0, 0,
                              &[nodes::dir::ent("a", A, 1), nodes::dir::ent("b", B, 1)]);
    let mut v = Volume::mount_with(Counting::new(b.image()), Options::defaults(), false).unwrap();
    let dir = v.read_inode(dir_ino).unwrap();
    let (aa, ba) = (v.node_addr(A).unwrap(), v.node_addr(B).unwrap());
    // With the prefetch off, each inode costs its own request.
    v.set_readdir_ra(false);
    v.node_cache.forget(A);
    v.node_cache.forget(B);
    v.source_ref().clear();
    assert_eq!(v.read_dir(&dir, dir_ino).unwrap().len(), 4);
    assert!(!v.node_cache.holds(A) && !v.node_cache.holds(B),
            "the listing prefetched with the control off");
    // With it on, the listing itself brings both in.
    v.set_readdir_ra(true);
    v.source_ref().clear();
    assert_eq!(v.read_dir(&dir, dir_ino).unwrap().len(), 4);
    assert!(v.node_cache.holds(A) && v.node_cache.holds(B));
    let lo = aa.min(ba);
    assert_eq!(v.source_ref().reqs_in(lo, 2), vec![(u64::from(lo), 2)]);
}
