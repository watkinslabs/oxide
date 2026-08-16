//! Writing a compressed file, proved by remounting the image and reading the
//! bytes back off it.
//!
//! Reading back from memory would prove only that the writer agrees with
//! itself. Every case here commits, takes the image's bytes, mounts them
//! again, and asks the new mount — so the addresses, the sentinel, the header
//! and the two counts all have to be on the medium and mean what they say.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::compress::algo::{COMPRESS_LZ4, COMPRESS_LZO, COMPRESS_LZORLE};
use crate::compress::plan;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{le32, BLKSIZE, COMPRESS_ADDR, I_COMPRESS_ALGORITHM, I_COMPRESS_FLAG, I_FLAGS,
                  I_LOG_CLUSTER_SIZE, NEW_ADDR, NULL_ADDR};
use crate::volume::dnode::{put16, put32};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 7);
const CHKSUM_FLAG: u16 = 1;
/// Every codec this build writes.
const CODECS: [u8; 3] = [COMPRESS_LZO, COMPRESS_LZ4, COMPRESS_LZORLE];

/// # C: O(1)
fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// A writable volume holding one compressed file, and that file's number.
/// # C: O(1 image)
fn with_compressed(algo: u8, log: u8, flag: u16) -> (Volume<MemImage>, u32) {
    let mut v = test_image::with_root().mount_rw().unwrap();
    let ino = v.create(ROOT_INO, b"c", &spec(), None).unwrap();
    v.stamp_inode(ino, |b| {
        let f = le32(b, I_FLAGS).unwrap_or(0) | crate::flags::F2FS_COMPR_FL;
        put32(b, I_FLAGS, f);
        b[I_COMPRESS_ALGORITHM] = algo;
        b[I_LOG_CLUSTER_SIZE] = log;
        put16(b, I_COMPRESS_FLAG, flag);
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

/// One cluster's stored addresses, as the medium holds them.
/// # C: O(cluster blocks)
fn addrs(v: &Volume<MemImage>, ino: u32, first: u64) -> Vec<u32> {
    let inode = v.read_inode(ino).unwrap();
    let g = v.geometry(&inode).unwrap();
    v.cluster_addrs(&inode, ino, &g, first).unwrap()
}

/// Bytes that compress well. # C: O(n)
fn patterned(n: usize) -> Vec<u8> { (0..n).map(|i| ((i / 64) % 11) as u8).collect() }

/// Bytes with no structure to find. # C: O(n)
fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut s = seed | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 17;
            s ^= s << 5;
            (s >> 11) as u8
        })
        .collect()
}

#[test]
fn a_compressible_cluster_survives_a_remount() {
    for algo in CODECS {
        let (mut v, ino) = with_compressed(algo, 2, 0);
        let data = patterned(4 * BLKSIZE);
        assert_eq!(v.write_compressed(ino, 0, &data).unwrap(), data.len());
        let v = remount(v);
        assert_eq!(v.read_inode(ino).unwrap().size, data.len() as u64);
        assert_eq!(whole(&v, ino), data, "codec {algo}");
    }
}

#[test]
fn the_cluster_is_stored_as_a_sentinel_the_image_and_reservations() {
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    v.write_compressed(ino, 0, &patterned(4 * BLKSIZE)).unwrap();
    let v = remount(v);
    let a = addrs(&v, ino, 0);
    assert_eq!(a[0], COMPRESS_ADDR, "the sentinel marks the head of the run");
    let extent = plan::compressed_extent(&a).unwrap();
    assert!(extent >= 2 && extent < 4, "image extent {extent}");
    // Everything past the image is reserved, not cleared: the file is still
    // charged for the whole cluster.
    assert!(a[extent..].iter().all(|&x| x == NEW_ADDR), "{a:?}");
}

#[test]
fn the_saved_blocks_are_recorded_and_survive_a_remount() {
    for log in 2u8..=4 {
        let cs = 1usize << log;
        let (mut v, ino) = with_compressed(COMPRESS_LZ4, log, 0);
        v.write_compressed(ino, 0, &patterned(cs * BLKSIZE)).unwrap();
        let v = remount(v);
        let a = addrs(&v, ino, 0);
        let extent = plan::compressed_extent(&a).unwrap();
        assert_eq!(v.compr_blocks(ino).unwrap(), (cs - (extent - 1)) as u64, "log {log}");
    }
}

#[test]
fn the_recorded_saving_never_exceeds_the_blocks_the_file_holds() {
    // A count above the block count is what a checker reads as a corrupt
    // inode, and it is exactly what happens if the slots the image does not
    // need are cleared instead of reserved.
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    v.write_compressed(ino, 0, &patterned(16 * BLKSIZE)).unwrap();
    let v = remount(v);
    let saved = v.compr_blocks(ino).unwrap();
    assert!(saved > 0, "nothing was saved, so the case proves nothing");
    assert!(saved <= v.read_inode(ino).unwrap().blocks, "saved {saved}");
}

#[test]
fn a_cluster_that_does_not_compress_is_stored_plain_and_carries_no_sentinel() {
    for algo in CODECS {
        let (mut v, ino) = with_compressed(algo, 2, 0);
        let data = noise(4 * BLKSIZE, algo as u32 + 1);
        v.write_compressed(ino, 0, &data).unwrap();
        let v = remount(v);
        let a = addrs(&v, ino, 0);
        assert_eq!(plan::compressed_extent(&a), None, "codec {algo}: {a:?}");
        assert_eq!(v.compr_blocks(ino).unwrap(), 0, "codec {algo}");
        assert_eq!(whole(&v, ino), data, "codec {algo}");
    }
}

#[test]
fn a_cluster_the_file_stops_part_way_through_is_stored_plain() {
    // Three blocks of a four-block cluster: an image covering the fourth
    // would be rewritten by the very next append.
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    let data = patterned(3 * BLKSIZE);
    v.write_compressed(ino, 0, &data).unwrap();
    let v = remount(v);
    assert_eq!(plan::compressed_extent(&addrs(&v, ino, 0)), None);
    assert_eq!(whole(&v, ino), data);
}

#[test]
fn filling_the_cluster_afterwards_compresses_it() {
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    let head = patterned(3 * BLKSIZE);
    v.write_compressed(ino, 0, &head).unwrap();
    assert_eq!(plan::compressed_extent(&addrs(&v, ino, 0)), None);
    let tail = patterned(BLKSIZE);
    v.write_compressed(ino, 3 * BLKSIZE as u64, &tail).unwrap();
    let v = remount(v);
    assert!(plan::compressed_extent(&addrs(&v, ino, 0)).is_some());
    let mut want = head.clone();
    want.extend_from_slice(&tail);
    assert_eq!(whole(&v, ino), want);
}

#[test]
fn a_write_inside_a_compressed_cluster_keeps_the_rest_of_it() {
    // The cluster is one image, so changing a byte means reading the whole
    // thing back first. A writer that skipped that would leave the untouched
    // blocks as whatever the codec last produced.
    for algo in CODECS {
        let (mut v, ino) = with_compressed(algo, 2, 0);
        let mut want = patterned(4 * BLKSIZE);
        v.write_compressed(ino, 0, &want).unwrap();
        let patch = b"the middle of the cluster";
        let at = BLKSIZE as u64 + 17;
        v.write_compressed(ino, at, patch).unwrap();
        want[at as usize..at as usize + patch.len()].copy_from_slice(patch);
        let v = remount(v);
        assert_eq!(whole(&v, ino), want, "codec {algo}");
    }
}

#[test]
fn a_write_that_straddles_two_clusters_lands_in_both() {
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    let mut want = patterned(8 * BLKSIZE);
    v.write_compressed(ino, 0, &want).unwrap();
    let patch = noise(2 * BLKSIZE, 9);
    let at = 3 * BLKSIZE as u64;
    v.write_compressed(ino, at, &patch).unwrap();
    want[at as usize..at as usize + patch.len()].copy_from_slice(&patch);
    let v = remount(v);
    assert_eq!(whole(&v, ino), want);
}

#[test]
fn a_hole_inside_a_plain_cluster_stays_a_hole() {
    // Only the third block is written and the file stops there, so the
    // cluster is plain and the two blocks before it are never allocated.
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    let data = patterned(BLKSIZE);
    v.write_compressed(ino, 2 * BLKSIZE as u64, &data).unwrap();
    let v = remount(v);
    let a = addrs(&v, ino, 0);
    assert_eq!(a[0], NULL_ADDR, "{a:?}");
    assert_eq!(a[1], NULL_ADDR, "{a:?}");
    assert!(a[2] != NULL_ADDR && a[2] != NEW_ADDR, "{a:?}");
    let mut want = vec![0u8; 2 * BLKSIZE];
    want.extend_from_slice(&data);
    assert_eq!(whole(&v, ino), want);
}

#[test]
fn a_hole_inside_a_cluster_that_gets_compressed_reads_back_as_zeroes() {
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    let data = patterned(BLKSIZE);
    v.write_compressed(ino, 2 * BLKSIZE as u64, &data).unwrap();
    // Now the cluster is whole, so it is compressed — hole included.
    v.write_compressed(ino, 3 * BLKSIZE as u64, &data).unwrap();
    let v = remount(v);
    assert!(plan::compressed_extent(&addrs(&v, ino, 0)).is_some());
    let mut want = vec![0u8; 2 * BLKSIZE];
    want.extend_from_slice(&data);
    want.extend_from_slice(&data);
    assert_eq!(whole(&v, ino), want);
}

#[test]
fn a_checksummed_file_round_trips_and_records_its_checksum() {
    for algo in CODECS {
        let (mut v, ino) = with_compressed(algo, 2, CHKSUM_FLAG);
        let data = patterned(4 * BLKSIZE);
        v.write_compressed(ino, 0, &data).unwrap();
        let v = remount(v);
        let a = addrs(&v, ino, 0);
        let image = v.read_main_block(a[1]).unwrap();
        assert_ne!(le32(&image, 4), Some(0), "codec {algo} wrote no checksum");
        assert_eq!(whole(&v, ino), data, "codec {algo}");
    }
}

#[test]
fn a_damaged_image_is_an_error_rather_than_wrong_bytes() {
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, CHKSUM_FLAG);
    v.write_compressed(ino, 0, &patterned(4 * BLKSIZE)).unwrap();
    let v = remount(v);
    let a = addrs(&v, ino, 0);
    let mut image = v.read_main_block(a[1]).unwrap();
    image[crate::compress::COMPRESS_HEADER_SIZE] ^= 0xff;
    v.write_block(a[1], &image).unwrap();
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; BLKSIZE];
    assert!(v.read_file(&inode, ino, 0, &mut buf).is_err());
}

#[test]
fn every_admitted_cluster_width_writes_and_reads_back() {
    for log in 2u8..=5 {
        let cs = 1usize << log;
        let (mut v, ino) = with_compressed(COMPRESS_LZ4, log, 0);
        let data = patterned(cs * BLKSIZE);
        v.write_compressed(ino, 0, &data).unwrap();
        let v = remount(v);
        assert!(plan::compressed_extent(&addrs(&v, ino, 0)).is_some(), "log {log}");
        assert_eq!(whole(&v, ino), data, "log {log}");
    }
}

#[test]
fn a_read_only_mount_refuses_to_write_a_compressed_file() {
    let (v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    let mut v = remount_ro(v);
    assert_eq!(v.write_compressed(ino, 0, b"x"), Err(syscall::errno::Errno::Erofs));
}

/// The same image mounted without permission to write it. # C: O(image)
fn remount_ro(mut v: Volume<MemImage>) -> Volume<MemImage> {
    v.commit().unwrap();
    let bytes = v.into_source().snapshot();
    Volume::mount_with(MemImage::from_bytes(BLKSIZE as u32, bytes), Options::defaults(), false)
        .unwrap()
}

