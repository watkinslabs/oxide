//! Free-space accounting, the information sector, and the chain cache.
//!
//! Three pieces of machinery that existed with no caller until the write paths
//! arrived. Each of these tests fails if its caller is removed again.

use super::*;

use crate::fsinfo::layout::{self as fsinfo, FSINFO_DEFAULT_SECTOR};

fn writable() -> Volume<Image> {
    let (img, _) = populated();
    Volume::mount(img.image(true)).expect("mount")
}

/// `discard` follows the FAT-free owner and clears every contiguous data run
/// released by unlink. Unsupported media simply skip the request, as Linux
/// does, but the in-memory discard-capable medium proves the request reached
/// the sector layer.
#[test]
fn discard_clears_clusters_released_by_unlink() {
    let (builder, _) = populated();
    let image = sectors::MemImage::from_bytes(SECTOR as u32, builder.bytes);
    let mut opts = crate::opts::Options::vfat();
    opts.discard = true;
    let mut v = Volume::mount_with(image, opts).expect("mount");
    let root = root_of(&v);
    let hit = v.find_entry(&root, "DATA.BIN").expect("file");
    let first = hit.entry.cluster;
    let sector = v.geometry().cluster_sector(first).expect("cluster");
    assert_ne!(v.source_bytes(sector as usize * SECTOR + 1), 0);
    v.unlink(&root, "DATA.BIN", when()).expect("unlink");
    assert_eq!(v.source_bytes(sector as usize * SECTOR + 1), 0, "discarded data");
}

/// The FAT `flush` owner reaches the medium barrier rather than merely
/// rewriting the in-memory table.
#[test]
fn flush_option_reaches_the_medium_barrier() {
    let (builder, _) = populated();
    let image = sectors::MemImage::from_bytes(SECTOR as u32, builder.bytes);
    let mut opts = crate::opts::Options::vfat();
    opts.flush = true;
    let v = Volume::mount_with(image, opts).expect("mount");
    v.flush_device().expect("flush");
    assert!(v.source_commands().iter().any(|cmd| matches!(cmd, sectors::source::Cmd::Flush)));
}

/// The maintained count is the scanned one, and stays that way across
/// allocation and release. A count that drifts makes `df` wrong and makes the
/// fast out-of-space refusal refuse a volume that has room.
#[test]
fn the_maintained_count_tracks_the_scan() {
    let mut v = writable();
    assert_eq!(v.free_clusters_counted(), v.free_clusters());
    let root = root_of(&v);
    let made = v.create_file(&root, "GROW.BIN", when()).expect("create");
    let per = v.geometry().cluster_bytes() as usize;
    v.write_file(root.cluster, &made, 0, &::alloc::vec![7u8; per * 3], when()).expect("write");
    assert_eq!(v.free_clusters_counted(), v.free_clusters(), "after allocating");
    v.unlink(&root, "GROW.BIN", when()).expect("unlink");
    assert_eq!(v.free_clusters_counted(), v.free_clusters(), "and after releasing");
}

/// Allocating really does move the count, so the test above is comparing two
/// numbers that change rather than two constants.
#[test]
fn allocating_moves_the_count() {
    let mut v = writable();
    let before = v.free_clusters_counted();
    let root = root_of(&v);
    let made = v.create_file(&root, "GROW.BIN", when()).expect("create");
    let per = v.geometry().cluster_bytes() as usize;
    v.write_file(root.cluster, &made, 0, &::alloc::vec![7u8; per * 3], when()).expect("write");
    assert_eq!(v.free_clusters_counted(), before - 3);
}

/// A FAT32 volume's information sector is READ at mount and WRITTEN back as
/// the count moves. Left unread, every mount rescans the table; left
/// unwritten, the next mount does too and the stored count stays wrong.
#[test]
fn the_information_sector_is_read_and_written() {
    let mut img = fat32_image();
    // A formatter's sector, claiming a free count this volume can act on.
    let at = FSINFO_DEFAULT_SECTOR as usize * SECTOR;
    let mut sector = ::alloc::vec![0u8; SECTOR];
    fsinfo::encode(&mut sector, Some(4242), Some(17));
    img.bytes[at..at + SECTOR].copy_from_slice(&sector);

    let mut opts = crate::opts::Options::vfat();
    opts.usefree = true;
    let mut v = Volume::mount_with(img.image(true), opts).expect("mount");
    assert_eq!(v.free_clusters_counted(), 4242, "the stored count was believed");

    // Something that moves the count, then the write-back.
    let root = root_of(&v);
    let made = v.create_file(&root, "ONE.BIN", when()).expect("create");
    v.write_file(root.cluster, &made, 0, b"bytes", when()).expect("write");
    v.flush_fsinfo().expect("flush");
    let mut read_back = ::alloc::vec![0u8; SECTOR];
    for i in 0..SECTOR { read_back[i] = v.source_bytes(at + i); }
    let info = fsinfo::parse(&read_back).expect("still a valid sector");
    assert_eq!(info.free_clusters, Some(4241), "one cluster fewer reached the medium");
    assert!(info.next_cluster.is_some(), "and so did the hint");
}

/// Without `usefree` the stored count is not acted on: a volume unmounted
/// uncleanly leaves a count that is merely plausible.
#[test]
fn the_stored_count_is_not_believed_unless_asked() {
    let mut img = fat32_image();
    let at = FSINFO_DEFAULT_SECTOR as usize * SECTOR;
    let mut sector = ::alloc::vec![0u8; SECTOR];
    fsinfo::encode(&mut sector, Some(4242), Some(17));
    img.bytes[at..at + SECTOR].copy_from_slice(&sector);
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let counted = v.free_clusters_counted();
    assert_ne!(counted, 4242);
    assert_eq!(counted, v.free_clusters(), "it was derived by scanning instead");
}

/// A large file reads back correctly through the remembered positions. The
/// cache is what stops a sequential read costing a walk from the first cluster
/// per request; a wrong position would hand back another cluster's bytes.
#[test]
fn a_cached_read_returns_the_same_bytes_as_an_uncached_one() {
    let mut v = writable();
    let root = root_of(&v);
    let made = v.create_file(&root, "BIG.BIN", when()).expect("create");
    let per = v.geometry().cluster_bytes() as usize;
    let payload: Vec<u8> = (0..per * 5).map(|i| (i % 253) as u8).collect();
    v.write_file(root.cluster, &made, 0, &payload, when()).expect("write");
    let hit = v.find_entry(&root, "BIG.BIN").expect("present");

    let mut cache = crate::fatcache::ChainCache::new();
    let mut buf = ::alloc::vec![0u8; 64];
    // Forwards, then backwards: a cache that only ever moves forward is not
    // exercised by a sequential read alone.
    let offsets: Vec<usize> = (0..payload.len() - 64).step_by(per / 3).collect();
    for off in offsets.iter().chain(offsets.iter().rev()) {
        let got = v.read_file_cached(&hit.entry, &mut cache, *off as u64, &mut buf)
            .expect("cached read");
        assert_eq!(&buf[..got], &payload[*off..*off + got], "at offset {off}");
    }
    assert!(!cache.is_empty(), "the walk remembered something");
}

/// Truncating invalidates the remembered positions. A position kept across it
/// names a cluster the file no longer owns, which is a read of whatever took
/// that cluster next.
#[test]
fn truncation_invalidates_the_remembered_positions() {
    let mut v = writable();
    let root = root_of(&v);
    let made = v.create_file(&root, "BIG.BIN", when()).expect("create");
    let per = v.geometry().cluster_bytes() as usize;
    v.write_file(root.cluster, &made, 0, &::alloc::vec![9u8; per * 4], when()).expect("write");
    let hit = v.find_entry(&root, "BIG.BIN").expect("present");

    let mut cache = crate::fatcache::ChainCache::new();
    let mut buf = ::alloc::vec![0u8; 16];
    v.read_file_cached(&hit.entry, &mut cache, (per * 3) as u64, &mut buf).expect("read");
    assert!(!cache.is_empty());
    v.truncate_file_cached(root.cluster, &hit, &mut cache, per as u64, when()).expect("truncate");
    assert!(cache.is_empty(), "nothing remembered about a chain that changed length");
}

/// Growing by truncation ALLOCATES and clears. FAT stores no hole, so a size
/// covering clusters the file does not own reads whatever the medium last
/// held there.
#[test]
fn an_expanding_truncation_allocates_and_reads_back_zero() {
    let mut v = writable();
    let root = root_of(&v);
    let made = v.create_file(&root, "HOLE.BIN", when()).expect("create");
    v.write_file(root.cluster, &made, 0, b"head", when()).expect("write");
    let hit = v.find_entry(&root, "HOLE.BIN").expect("present");
    let per = v.geometry().cluster_bytes();
    v.truncate_file(root.cluster, &hit, per * 2 + 7, when()).expect("expand");
    let after = v.find_entry(&root, "HOLE.BIN").expect("present");
    assert_eq!(after.size(), per * 2 + 7);
    let whole = v.read_whole(&after.entry).expect("read");
    assert_eq!(whole.len() as u64, per * 2 + 7);
    assert_eq!(&whole[..4], b"head");
    assert!(whole[4..].iter().all(|b| *b == 0), "the gap reads as zero, not as stale bytes");
}

/// On FAT32 the root IS an ordinary cluster, and `..` in a directory of it
/// still names ZERO rather than that cluster number.
///
/// The narrower widths cannot show this: their root is a fixed region with no
/// cluster to confuse it with. Here the root's cluster is a real number, and
/// writing it into `..` would give the root a second, different way to be
/// reached — which every checker reports as a cross-linked directory.
#[test]
fn dotdot_in_a_fat32_root_still_names_zero() {
    let img = fat32_image();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    assert_eq!(v.width(), crate::geometry::FatWidth::Fat32);
    let root = root_of(&v);
    assert_eq!(root.cluster, Some(v.geometry().root_cluster));
    assert_ne!(v.geometry().root_cluster, 0, "the root really does have a cluster");
    let made = v.create_dir(&root, "SUB", when()).expect("mkdir");
    let bytes = v.directory_bytes(Some(made.entry.cluster)).expect("read it");
    let at = crate::namei::find_dotdot(&bytes).expect("it has one");
    let r = crate::dirent::Record::parse(
        &bytes[at as usize..at as usize + crate::dirent::ENTRY_BYTES]).unwrap();
    assert_eq!(r.short.cluster, 0);
    // ...and moving it into a real subdirectory DOES write that one's cluster,
    // so the rule is "the root names zero", not "`..` is always zero".
    let sub = DirHandle::child(made.entry.cluster, root.cluster, made.slot);
    let deeper = v.create_dir(&sub, "DEEPER", when()).expect("mkdir");
    let bytes = v.directory_bytes(Some(deeper.entry.cluster)).expect("read it");
    let at = crate::namei::find_dotdot(&bytes).expect("it has one");
    let r = crate::dirent::Record::parse(
        &bytes[at as usize..at as usize + crate::dirent::ENTRY_BYTES]).unwrap();
    assert_eq!(r.short.cluster, made.entry.cluster);
}

/// A FAT32 image, which is the only width with an information sector.
fn fat32_image() -> Builder {
    const F32_SECTORS: usize = 512;
    const F32_TOTAL: usize = 40_000;
    let mut bytes = ::alloc::vec![0u8; F32_TOTAL * SECTOR];
    bytes[0x0b..0x0d].copy_from_slice(&(SECTOR as u16).to_le_bytes());
    bytes[0x0d] = 1;
    bytes[0x0e..0x10].copy_from_slice(&2u16.to_le_bytes());
    bytes[0x10] = 1;
    bytes[0x11..0x13].copy_from_slice(&0u16.to_le_bytes());
    bytes[0x15] = 0xf8;
    bytes[0x16..0x18].copy_from_slice(&0u16.to_le_bytes());
    bytes[0x20..0x24].copy_from_slice(&(F32_TOTAL as u32).to_le_bytes());
    bytes[0x24..0x28].copy_from_slice(&(F32_SECTORS as u32).to_le_bytes());
    bytes[0x2c..0x30].copy_from_slice(&2u32.to_le_bytes());
    bytes[0x30..0x32].copy_from_slice(&(FSINFO_DEFAULT_SECTOR as u16).to_le_bytes());
    let mut img = Builder { bytes, next_free: 2 };
    // The root is cluster 2, ended and left empty.
    let fat = 2 * SECTOR;
    img.bytes[fat..fat + 4].copy_from_slice(&0x0FFF_FFF8u32.to_le_bytes());
    img.bytes[fat + 4..fat + 8].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    img.bytes[fat + 8..fat + 12].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
    img.next_free = 3;
    img
}
