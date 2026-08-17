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

use crate::compress::algo::{COMPRESS_LZ4, COMPRESS_LZO, COMPRESS_LZORLE, COMPRESS_ZSTD};
use crate::compress::plan;
use crate::mode::S_IFREG;
use crate::opts::Options;
use crate::test_image::{self, ROOT_INO};
use crate::uapi::{le32, le64, BLKSIZE, COMPRESS_ADDR, I_COMPRESS_ALGORITHM, I_COMPRESS_FLAG, I_FLAGS,
                  I_LOG_CLUSTER_SIZE, NEW_ADDR, NULL_ADDR};
use crate::volume::dnode::{put16, put32};
use crate::volume::{NewInode, Volume};

const NOW: (u64, u32) = (1_800_000_000, 7);
const CHKSUM_FLAG: u16 = 1;
/// Every codec this build writes.
const CODECS: [u8; 4] = [COMPRESS_LZO, COMPRESS_LZ4, COMPRESS_LZORLE, COMPRESS_ZSTD];

/// # C: O(1)
fn spec() -> NewInode {
    NewInode { mode: S_IFREG | 0o644, uid: 0, gid: 0, rdev: 0, now: NOW }
}

/// A writable volume holding one compressed file, and that file's number.
/// # C: O(1 image)
fn with_compressed(algo: u8, log: u8, flag: u16) -> (Volume<MemImage>, u32) {
    let mut b = test_image::with_root();
    // The volume must carry the feature, or the compression fields in an
    // inode are not compression fields at all and nothing validates them.
    b.feature |= crate::flags::FEATURE_COMPRESSION;
    let mut v = b.mount_rw().unwrap();
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


#[test]
fn a_read_that_starts_inside_a_cluster_returns_file_bytes_and_not_the_image() {
    // Only the cluster's FIRST slot carries the sentinel; the slots after it
    // hold the compressed image, which are ordinary addresses. A reader that
    // resolves a block on its own address hands back a block of the IMAGE as
    // if it were the file — the reason every read below starts somewhere
    // other than a cluster boundary.
    for algo in CODECS {
        let (mut v, ino) = with_compressed(algo, 2, 0);
        let data = patterned(8 * BLKSIZE);
        v.write_compressed(ino, 0, &data).unwrap();
        let v = remount(v);
        let inode = v.read_inode(ino).unwrap();
        for off in [BLKSIZE as u64, 2 * BLKSIZE as u64 + 7, 3 * BLKSIZE as u64 - 1,
                    5 * BLKSIZE as u64, 7 * BLKSIZE as u64 + 4095] {
            let mut buf = vec![0u8; 64];
            let n = v.read_file(&inode, ino, off, &mut buf).unwrap();
            assert!(n > 0, "codec {algo} offset {off}");
            assert_eq!(
                &buf[..n],
                &data[off as usize..off as usize + n],
                "codec {algo} offset {off}"
            );
        }
    }
}

#[test]
fn a_read_inside_a_plain_cluster_of_a_compressed_file_still_uses_the_block() {
    // A compressed file's clusters are not all compressed: one the file stops
    // part way through is stored plain, and its blocks must be read as blocks
    // rather than fed to a decoder.
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    let data = patterned(3 * BLKSIZE);
    v.write_compressed(ino, 0, &data).unwrap();
    let v = remount(v);
    assert_eq!(plan::compressed_extent(&addrs(&v, ino, 0)), None);
    let inode = v.read_inode(ino).unwrap();
    let mut buf = vec![0u8; 64];
    let off = BLKSIZE as u64 + 11;
    let n = v.read_file(&inode, ino, off, &mut buf).unwrap();
    assert_eq!(&buf[..n], &data[off as usize..off as usize + n]);
}

#[test]
fn an_inode_whose_compression_settings_are_nonsense_is_refused_at_read() {
    // The volume carries the feature, so those bytes ARE compression settings
    // and an inode that cannot describe a readable file is a corrupt inode.
    for (algo, log, flag) in [(9u8, 2u8, 0u16), (COMPRESS_LZ4, 1, 0), (COMPRESS_LZ4, 9, 0),
                              (COMPRESS_LZ4, 2, 3 << 8)] {
        let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
        v.write_compressed(ino, 0, &patterned(4 * BLKSIZE)).unwrap();
        v.stamp_inode(ino, |b| {
            b[I_COMPRESS_ALGORITHM] = algo;
            b[I_LOG_CLUSTER_SIZE] = log;
            put16(b, I_COMPRESS_FLAG, flag);
        })
        .unwrap();
        assert!(v.read_inode(ino).is_err(), "algo {algo} log {log} flag {flag}");
    }
}

/// Live blocks the segment table itself accounts for.
///
/// A freshly mounted volume has not read the table yet and answers zero for
/// every segment, which reads exactly like a volume that lost its blocks — so
/// it is loaded first.
/// # C: O(main segments)
fn sit_live(v: &mut Volume<MemImage>) -> u64 {
    v.load_segments().unwrap();
    (0..v.sb.segment_count_main).map(|s| v.seg_valid(s) as u64).sum()
}

/// How far the volume's count runs ahead of the segment table.
///
/// A mark — the sentinel or a reservation — occupies a slot and names no
/// block, so it is counted by the volume and not by the table. The gap between
/// the two is therefore the number of marks outstanding, plus whatever fixed
/// offset the volume's own layout contributes; a DIFFERENCE in the gap is the
/// marks alone, which is what makes both a leaked mark and a doubly-released
/// one visible here rather than as free space that never comes back.
/// # C: O(main segments)
fn drift(v: &mut Volume<MemImage>) -> i64 {
    let live = sit_live(v) as i64;
    v.valid_block_count as i64 - live
}

/// The marks a cluster's slots carry. # C: O(cluster blocks)
fn marks(v: &Volume<MemImage>, ino: u32, first: u64) -> i64 {
    addrs(v, ino, first).iter().filter(|&&a| a == NEW_ADDR || a == COMPRESS_ADDR).count() as i64
}

#[test]
fn every_mark_a_compressed_file_carries_is_counted_once_and_given_back_once() {
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    let base = drift(&mut v);
    v.write_compressed(ino, 0, &patterned(8 * BLKSIZE)).unwrap();
    let held = marks(&v, ino, 0) + marks(&v, ino, 4);
    assert!(held > 0, "no marks, so the case proves nothing");
    assert_eq!(drift(&mut v), base + held, "a mark was counted twice or not at all");
    let mut v = remount(v);
    assert_eq!(drift(&mut v), base + held, "the count did not survive the remount");
    // And when the file goes, the marks go with it.
    v.truncate_compressed(ino, 0).unwrap();
    assert_eq!(drift(&mut v), base, "a mark outlived the file that held it");
}

#[test]
fn overwriting_a_compressed_cluster_leaks_no_mark() {
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    let base = drift(&mut v);
    // Compressible, then not, then compressible again: the cluster's slots
    // move between marks and blocks in both directions.
    v.write_compressed(ino, 0, &patterned(4 * BLKSIZE)).unwrap();
    v.write_compressed(ino, 0, &noise(4 * BLKSIZE, 21)).unwrap();
    assert_eq!(drift(&mut v), base, "a plain cluster still carries marks");
    v.write_compressed(ino, 0, &patterned(4 * BLKSIZE)).unwrap();
    let held = marks(&v, ino, 0);
    assert!(held > 0);
    assert_eq!(drift(&mut v), base + held);
}

#[test]
fn the_saving_is_read_back_off_the_inode_rather_than_recomputed() {
    // It is a stored field, so a mount that does not read it reports a file
    // with nothing saved — and the release that would hand those blocks back
    // would find none to hand back.
    let (mut v, ino) = with_compressed(COMPRESS_LZ4, 2, 0);
    v.write_compressed(ino, 0, &patterned(4 * BLKSIZE)).unwrap();
    let v = remount(v);
    let stored = le64(&v.inode_bytes(ino).unwrap(), crate::uapi::I_COMPR_BLOCKS).unwrap();
    assert!(stored > 0);
    assert_eq!(v.read_inode(ino).unwrap().compr_blocks, stored);
    assert_eq!(v.compr_blocks(ino).unwrap(), stored);
}
