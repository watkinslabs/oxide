//! Shortening a compressed file, proved by remounting.
//!
//! Blocks come off a whole CLUSTER at a time: the cluster the new end falls
//! inside cannot be shortened, only rewritten, because its blocks hold one
//! image rather than one block each. That rewrite makes it plain, since the
//! file's size now stops part way through it.

use alloc::vec::Vec;

use sectors::MemImage;

use crate::compress::algo::COMPRESS_LZ4;
use crate::compress::plan;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{le32, BLKSIZE, I_COMPRESS_ALGORITHM, I_COMPRESS_FLAG, I_FLAGS,
                  I_LOG_CLUSTER_SIZE, NULL_ADDR};
use crate::volume::dnode::{put16, put32};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 7);

/// # C: O(1)
fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// # C: O(1 image)
fn with_compressed(log: u8) -> (Volume<MemImage>, u32) {
    let mut b = test_image::with_root();
    // The volume must carry the feature, or the compression fields in an
    // inode are not compression fields at all and nothing validates them.
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut v = b.mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"c", &spec(), None).unwrap();
    v.stamp_inode(ino, |b| {
        let f = le32(b, I_FLAGS).unwrap_or(0) | crate::flags::F2FS_COMPR_FL;
        put32(b, I_FLAGS, f);
        b[I_COMPRESS_ALGORITHM] = COMPRESS_LZ4;
        b[I_LOG_CLUSTER_SIZE] = log;
        put16(b, I_COMPRESS_FLAG, 0);
    })
    .unwrap();
    (v, ino)
}

/// # C: O(image)
fn remount(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), true)
        .unwrap()
}

/// # C: O(file bytes)
fn whole(v: &Volume<MemImage>, ino: u32) -> Vec<u8> {
    let inode = v.read_inode(ino).unwrap();
    v.read_whole(&inode, ino).unwrap()
}

/// # C: O(cluster blocks)
fn addrs(v: &Volume<MemImage>, ino: u32, first: u64) -> Vec<u32> {
    let inode = v.read_inode(ino).unwrap();
    let g = v.geometry(&inode).unwrap();
    v.cluster_addrs(&inode, ino, &g, first).unwrap()
}

/// # C: O(n)
fn patterned(n: usize) -> Vec<u8> { (0..n).map(|i| ((i / 64) % 11) as u8).collect() }

/// A file of `blocks` compressible blocks, already written. # C: O(bytes)
fn written(log: u8, blocks: usize) -> (Volume<MemImage>, u32, Vec<u8>) {
    let (mut v, ino) = with_compressed(log);
    let data = patterned(blocks * BLKSIZE);
    v.write_compressed(ino, 0, &data).unwrap();
    (v, ino, data)
}

#[test]
fn shortening_to_a_cluster_boundary_releases_the_clusters_past_it() {
    let (mut v, ino, data) = written(2, 8);
    v.truncate_compressed(ino, 4 * BLKSIZE as u64).unwrap();
    let v = remount(v);
    assert_eq!(v.read_inode(ino).unwrap().size, 4 * BLKSIZE as u64);
    assert_eq!(whole(&v, ino), data[..4 * BLKSIZE].to_vec());
    // The released cluster holds nothing at all, not even a reservation.
    assert!(addrs(&v, ino, 4).iter().all(|&a| a == NULL_ADDR));
    // The cluster that stayed is still compressed.
    assert!(plan::compressed_extent(&addrs(&v, ino, 0)).is_some());
}

#[test]
fn shortening_inside_a_cluster_zeroes_its_tail() {
    let (mut v, ino, data) = written(2, 8);
    let len = 5 * BLKSIZE as u64 + 100;
    v.truncate_compressed(ino, len).unwrap();
    let v = remount(v);
    assert_eq!(v.read_inode(ino).unwrap().size, len);
    assert_eq!(whole(&v, ino), data[..len as usize].to_vec());
}

#[test]
fn the_cluster_the_new_end_falls_inside_comes_back_plain() {
    // Its last blocks are past the end of the file now, so an image covering
    // them would be rewritten by the next append.
    let (mut v, ino, _) = written(2, 8);
    assert!(plan::compressed_extent(&addrs(&v, ino, 4)).is_some());
    v.truncate_compressed(ino, 5 * BLKSIZE as u64 + 100).unwrap();
    let v = remount(v);
    let a = addrs(&v, ino, 4);
    assert_eq!(plan::compressed_extent(&a), None, "{a:?}");
    // Only the blocks the file still reaches are kept.
    assert!(a[0] != NULL_ADDR && a[1] != NULL_ADDR, "{a:?}");
    assert_eq!(a[2], NULL_ADDR, "{a:?}");
    assert_eq!(a[3], NULL_ADDR, "{a:?}");
}

#[test]
fn the_bytes_past_the_new_end_are_gone_rather_than_hidden() {
    // Growing the file again must not bring the old tail back: the blocks are
    // whole on the medium and only the size said where to stop.
    let (mut v, ino, _) = written(2, 8);
    let len = 5 * BLKSIZE as u64 + 100;
    v.truncate_compressed(ino, len).unwrap();
    v.truncate_compressed(ino, 6 * BLKSIZE as u64).unwrap();
    let v = remount(v);
    let back = whole(&v, ino);
    assert_eq!(back.len(), 6 * BLKSIZE);
    assert!(back[len as usize..].iter().all(|&b| b == 0), "old bytes showed through");
}

#[test]
fn the_saving_a_released_cluster_recorded_is_given_back() {
    let (mut v, ino, _) = written(2, 8);
    let before = v.compr_blocks(ino).unwrap();
    assert!(before > 0);
    v.truncate_compressed(ino, 4 * BLKSIZE as u64).unwrap();
    let v = remount(v);
    let after = v.compr_blocks(ino).unwrap();
    assert!(after > 0 && after < before, "before {before} after {after}");
}

#[test]
fn shortening_to_nothing_leaves_no_saving_and_no_blocks() {
    let (mut v, ino, _) = written(2, 8);
    v.truncate_compressed(ino, 0).unwrap();
    let v = remount(v);
    assert_eq!(v.read_inode(ino).unwrap().size, 0);
    assert_eq!(v.compr_blocks(ino).unwrap(), 0);
    for first in [0u64, 4] {
        assert!(addrs(&v, ino, first).iter().all(|&a| a == NULL_ADDR), "cluster {first}");
    }
    assert_eq!(whole(&v, ino), Vec::<u8>::new());
}

#[test]
fn the_recorded_saving_never_exceeds_the_blocks_the_file_holds_after_a_truncate() {
    for len in [0u64, 1, 100, BLKSIZE as u64, 5 * BLKSIZE as u64 + 100, 7 * BLKSIZE as u64] {
        let (mut v, ino, _) = written(2, 8);
        v.truncate_compressed(ino, len).unwrap();
        let v = remount(v);
        let saved = v.compr_blocks(ino).unwrap();
        assert!(saved <= v.read_inode(ino).unwrap().blocks, "len {len}: saved {saved}");
    }
}

#[test]
fn extending_allocates_nothing_and_reads_as_zeroes() {
    let (mut v, ino, data) = written(2, 4);
    let len = 12 * BLKSIZE as u64;
    v.truncate_compressed(ino, len).unwrap();
    let v = remount(v);
    assert_eq!(v.read_inode(ino).unwrap().size, len);
    assert!(addrs(&v, ino, 4).iter().all(|&a| a == NULL_ADDR));
    let mut want = data.clone();
    want.resize(len as usize, 0);
    assert_eq!(whole(&v, ino), want);
}

#[test]
fn shortening_then_writing_again_compresses_the_cluster_once_more() {
    let (mut v, ino, data) = written(2, 8);
    v.truncate_compressed(ino, 5 * BLKSIZE as u64).unwrap();
    v.write_compressed(ino, 5 * BLKSIZE as u64, &data[5 * BLKSIZE..8 * BLKSIZE]).unwrap();
    let v = remount(v);
    assert_eq!(whole(&v, ino), data);
    assert!(plan::compressed_extent(&addrs(&v, ino, 4)).is_some());
}

#[test]
fn a_read_only_mount_refuses_to_shorten_a_compressed_file() {
    let (mut v, ino, _) = written(2, 4);
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    let mut ro = Volume::mount_with(
        MemImage::from_bytes(BLKSIZE as u32, bytes),
        Options::defaults(),
        false,
    )
    .unwrap();
    assert_eq!(ro.truncate_compressed(ino, 0), Err(syscall::errno::Errno::Erofs));
}
