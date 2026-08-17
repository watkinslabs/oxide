//! The mount's cache of compressed blocks, driven through a real volume.
//!
//! Two properties carry the whole feature and both are asserted against the
//! MEDIUM rather than against the cache's own bookkeeping: a second read of a
//! cluster does not go to the device, and a block that has left the file does
//! not answer for it afterwards. A cache that only reported hits would pass a
//! test written against its counters while serving the wrong bytes.

use alloc::vec::Vec;

use sectors::MemImage;

use crate::compress::algo::COMPRESS_LZ4;
use crate::compress::cache::COMPRESS_CACHE_MAX_BLOCKS;
use crate::compress::plan;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{le32, BLKSIZE, COMPRESS_ADDR, I_COMPRESS_ALGORITHM, I_FLAGS,
                  I_LOG_CLUSTER_SIZE};
use crate::volume::dnode::{put32, Holder};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 7);
/// Four blocks to a cluster, which is the width the write tests use.
const LOG: u8 = 2;

/// The option set a mount that asked for the cache runs with. # C: O(1)
fn caching() -> Options {
    let mut o = Options::defaults();
    o.compress_cache = true;
    o
}

/// A writable volume holding one compressed file, and that file's number.
///
/// `cache` decides whether the mount asked to hold what it reads, so the same
/// fixture serves the cached and uncached cases and any difference between
/// them is the option rather than the image.
/// # C: O(1 image)
fn volume(cache: bool) -> (Volume<MemImage>, u32) {
    let mut b = test_image::with_root();
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let opts = if cache { caching() } else { Options::defaults() };
    let mut v = b.mount_opts(opts).unwrap();
    let spec = NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW };
    let ino = v.create(ROOT_INO, b"c", &spec, None).unwrap();
    v.stamp_inode(ino, |blk| {
        let f = le32(blk, I_FLAGS).unwrap_or(0) | crate::flags::F2FS_COMPR_FL;
        put32(blk, I_FLAGS, f);
        blk[I_COMPRESS_ALGORITHM] = COMPRESS_LZ4;
        blk[I_LOG_CLUSTER_SIZE] = LOG;
    })
    .unwrap();
    (v, ino)
}

/// Bytes that compress into a single block, so a cluster's stored image is one
/// address and a test can name it. # C: O(n)
fn patterned(n: usize, seed: u8) -> Vec<u8> { (0..n).map(|_| seed).collect() }

/// Write, PLACE, and let the plain pages go.
///
/// Two steps, each answering a different thing this cache needs.
///
/// The write is deferred: a compressed cluster's addresses are chosen at
/// writeback, so a case that reads them — or the blocks they name — has to ask
/// for the placement, exactly as an fsync or a checkpoint does.
///
/// The plain pages are then dropped, because a writer keeps them: they are the
/// file's own bytes and the mapping answers every read of them without going
/// near the medium. This cache exists for the reads that DO go to the medium —
/// after reclaim, after a fresh mount — so a case that left the plain pages in
/// place would never reach it and would prove nothing about it.
/// # C: O(bytes)
fn wrote(v: &mut Volume<MemImage>, ino: u32, off: u64, data: &[u8]) {
    v.write_compressed(ino, off, data).unwrap();
    v.sync_data().unwrap();
    v.data_cache().forget_inode(ino);
}

/// # C: O(cluster blocks)
fn addrs(v: &Volume<MemImage>, ino: u32) -> Vec<u32> {
    let inode = v.read_inode(ino).unwrap();
    let g = v.geometry(&inode).unwrap();
    v.cluster_addrs(&inode, ino, &g, 0).unwrap()
}

/// The one block a single-block cluster image is stored in.
///
/// Asserted rather than assumed: a fixture whose image spread over two blocks
/// would make the recycled-address case below read a mixture of two clusters
/// and prove nothing.
/// # C: O(cluster blocks)
fn image_addr(v: &Volume<MemImage>, ino: u32) -> u32 {
    let a = addrs(v, ino);
    assert_eq!(a[0], COMPRESS_ADDR);
    assert_eq!(plan::compressed_extent(&a).unwrap(), 2, "the image must be one block: {a:?}");
    a[1]
}

/// # C: O(file bytes)
fn whole(v: &Volume<MemImage>, ino: u32) -> Result<Vec<u8>, syscall::errno::Errno> {
    let inode = v.read_inode(ino).unwrap();
    v.read_whole(&inode, ino)
}

/// Overwrite the medium under a block address. # C: O(BLKSIZE)
fn poison(v: &Volume<MemImage>, addr: u32) {
    v.source_ref().poke(addr as usize * BLKSIZE, &patterned(BLKSIZE, 0xA5));
}

#[test]
fn a_mount_that_asked_keeps_the_blocks_it_read_and_one_that_did_not_keeps_none() {
    let data = patterned(4 * BLKSIZE, 0x31);
    for cache in [false, true] {
        let (mut v, ino) = volume(cache);
        wrote(&mut v, ino, 0, &data);
        assert_eq!(v.compress_cache.blocks(), 0, "nothing is cached by writing");
        assert_eq!(whole(&v, ino).unwrap(), data);
        assert_eq!(v.compress_cache.enabled(), cache);
        assert_eq!(v.compress_cache.blocks(), if cache { 1 } else { 0 }, "cache {cache}");
    }
}

#[test]
fn a_second_read_of_a_cluster_never_reaches_the_medium() {
    let (mut v, ino) = volume(true);
    let data = patterned(4 * BLKSIZE, 0x42);
    wrote(&mut v, ino, 0, &data);
    let a = image_addr(&v, ino);
    assert_eq!(whole(&v, ino).unwrap(), data);
    assert_eq!(v.compress_cache.hits(), 0, "the first read had nothing to hit");
    // The device now holds bytes that cannot be decompressed. A read that goes
    // back to it fails; a read served from what the mount kept does not — so
    // this distinguishes the two without trusting either counter.
    poison(&v, a);
    assert_eq!(whole(&v, ino).unwrap(), data, "the second read went to the medium");
    assert_eq!(v.compress_cache.hits(), 1);
}

#[test]
fn a_mount_that_did_not_ask_reads_the_medium_every_time() {
    // The control for the case above: the same poisoning, on a mount without
    // the option, must be visible.
    let (mut v, ino) = volume(false);
    let data = patterned(4 * BLKSIZE, 0x42);
    wrote(&mut v, ino, 0, &data);
    let a = image_addr(&v, ino);
    assert_eq!(whole(&v, ino).unwrap(), data);
    poison(&v, a);
    assert!(whole(&v, ino).is_err(), "a mount with no cache cannot have served this");
}

#[test]
fn a_block_that_has_left_the_file_does_not_answer_for_it_afterwards() {
    // The failure this exists to prevent: a cluster is rewritten out of place,
    // the allocator later hands its old block to something else, and a read of
    // that address is served the CONTENTS THE FILE USED TO HAVE — no error
    // anywhere, and the wrong bytes.
    let (mut v, ino) = volume(true);
    let old = patterned(4 * BLKSIZE, 0x11);
    wrote(&mut v, ino, 0, &old);
    let first = image_addr(&v, ino);
    assert_eq!(whole(&v, ino).unwrap(), old);
    assert_eq!(v.compress_cache.blocks(), 1);

    // Rewriting the cluster releases the block it was stored in.
    let new = patterned(4 * BLKSIZE, 0x22);
    wrote(&mut v, ino, 0, &new);
    let second = image_addr(&v, ino);
    assert_ne!(first, second, "the rewrite must land elsewhere or there is nothing to free");
    assert_eq!(v.compress_cache.load(first), None, "the freed block is still cached");

    // Stand in for the allocator handing the block out again: the medium holds
    // something else there, and a cluster points at it.
    poison(&v, first);
    v.set_holder_addr(ino, Holder::Inode, 1, first).unwrap();
    let got = whole(&v, ino);
    assert!(got.is_err(), "served {:?} from a block the file no longer holds", got.map(|b| b[0]));
}

#[test]
fn evicting_the_holder_drops_what_that_file_cached() {
    let (mut v, ino) = volume(true);
    wrote(&mut v, ino, 0, &patterned(4 * BLKSIZE, 0x53));
    assert_eq!(whole(&v, ino).unwrap().len(), 4 * BLKSIZE);
    assert_eq!(v.compress_cache.blocks(), 1);
    v.evict_inode(ino).unwrap();
    assert_eq!(v.compress_cache.blocks(), 0);
}

#[test]
fn one_files_blocks_survive_another_files_eviction() {
    let (mut v, ino) = volume(true);
    wrote(&mut v, ino, 0, &patterned(4 * BLKSIZE, 0x64));
    assert_eq!(whole(&v, ino).unwrap().len(), 4 * BLKSIZE);
    assert_eq!(v.compress_cache.blocks(), 1);
    // An eviction of an inode that cached nothing must not take this one's
    // block with it: the owner is recorded per block precisely so it cannot.
    v.evict_inode(ROOT_INO).unwrap();
    assert_eq!(v.compress_cache.blocks(), 1);
}

#[test]
fn the_status_report_carries_what_is_held_and_what_it_answered() {
    // The line has always been rendered and has always said nothing. A reader
    // matching on it cannot tell "this mount holds none" from "this build does
    // not count", so the figures have to be the cache's own.
    let (mut v, ino) = volume(true);
    wrote(&mut v, ino, 0, &patterned(4 * BLKSIZE, 0x85));
    assert_eq!(whole(&v, ino).unwrap().len(), 4 * BLKSIZE);
    assert_eq!(whole(&v, ino).unwrap().len(), 4 * BLKSIZE);
    let c = crate::stats::counters::Counters::new();
    let g = crate::stats::sample::General::sample(&mut v, &c).unwrap();
    assert_eq!((g.compress_cached, g.compress_hits), (1, 1));
    let text = crate::stats::show::partition(&g, "vda", 0, 0);
    assert!(text.contains("- compress:    1, hit:       1\n"), "{text}");
}

#[test]
fn the_cache_stops_at_its_bound_and_keeps_what_it_already_holds() {
    let (v, _) = volume(true);
    let data = patterned(BLKSIZE, 0x77);
    for i in 0..COMPRESS_CACHE_MAX_BLOCKS as u32 { v.compress_cache.store(i, 4, &data); }
    assert_eq!(v.compress_cache.blocks(), COMPRESS_CACHE_MAX_BLOCKS);
    v.compress_cache.store(COMPRESS_CACHE_MAX_BLOCKS as u32, 4, &data);
    assert_eq!(v.compress_cache.blocks(), COMPRESS_CACHE_MAX_BLOCKS, "the bound is a bound");
    assert!(v.compress_cache.load(0).is_some(), "a full cache declines rather than evicting");
}
