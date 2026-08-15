use super::*;
use crate::dirent::{ATTR_ARCH, ATTR_DIR, ATTR_VOLUME, CHARS_PER_SLOT, DELETED_FLAG,
                    LAST_LONG_ENTRY};
use alloc::vec;

const SECTOR: usize = 512;
const SEC_PER_CLUS: usize = 2;
const RESERVED: usize = 1;
const FATS: usize = 2;
const FAT_SECTORS: usize = 32;
const ROOT_ENTRIES: usize = 32;
/// Large enough that the data-cluster count puts this volume past the FAT12
/// boundary — the image writes 16-bit entries, so it must BE a FAT16 volume.
/// A smaller image silently becomes FAT12 and every entry reads at the wrong
/// bit offset.
const TOTAL_SECTORS: usize = 16384;

/// An image built the way a formatter would: independent of the reader, so a
/// pass proves the two agree rather than that one function is self-consistent.
struct Image {
    bytes: Vec<u8>,
    next_free: u32,
}

impl Image {
    fn new() -> Self {
        let mut bytes = vec![0u8; TOTAL_SECTORS * SECTOR];
        // Boot sector.
        bytes[0x0b..0x0d].copy_from_slice(&(SECTOR as u16).to_le_bytes());
        bytes[0x0d] = SEC_PER_CLUS as u8;
        bytes[0x0e..0x10].copy_from_slice(&(RESERVED as u16).to_le_bytes());
        bytes[0x10] = FATS as u8;
        bytes[0x11..0x13].copy_from_slice(&(ROOT_ENTRIES as u16).to_le_bytes());
        bytes[0x13..0x15].copy_from_slice(&(TOTAL_SECTORS as u16).to_le_bytes());
        bytes[0x15] = 0xf8;
        bytes[0x16..0x18].copy_from_slice(&(FAT_SECTORS as u16).to_le_bytes());
        let mut img = Self { bytes, next_free: 2 };
        // Entries 0 and 1 are reserved and carry the media descriptor.
        img.put_fat(0, 0xFFF8);
        img.put_fat(1, 0xFFFF);
        img
    }

    fn fat_offset(&self) -> usize { RESERVED * SECTOR }
    fn root_offset(&self) -> usize { (RESERVED + FATS * FAT_SECTORS) * SECTOR }
    fn data_offset(&self) -> usize {
        self.root_offset() + ROOT_ENTRIES * dirent::ENTRY_BYTES
    }

    fn put_fat(&mut self, cluster: u32, value: u16) {
        let at = self.fat_offset() + cluster as usize * 2;
        self.bytes[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn cluster_offset(&self, cluster: u32) -> usize {
        self.data_offset() + (cluster as usize - 2) * SEC_PER_CLUS * SECTOR
    }

    /// Allocate a chain long enough for `bytes`, write them, return the first
    /// cluster.
    fn write_chain(&mut self, data: &[u8]) -> u32 {
        let per = SEC_PER_CLUS * SECTOR;
        let count = core::cmp::max(1, data.len().div_ceil(per));
        let first = self.next_free;
        for i in 0..count {
            let cluster = first + i as u32;
            let at = self.cluster_offset(cluster);
            let start = i * per;
            let end = core::cmp::min(start + per, data.len());
            if start < data.len() { self.bytes[at..at + (end - start)].copy_from_slice(&data[start..end]); }
            self.put_fat(cluster, if i + 1 == count { 0xFFFF } else { (cluster + 1) as u16 });
        }
        self.next_free += count as u32;
        first
    }

    /// Write a directory's records at `at`, with long-name slots for any name
    /// that needs them.
    fn write_dir(&mut self, at: usize, files: &[(&str, [u8; 11], u8, u32, u32)]) {
        let mut cursor = at;
        for (long, short, attr, cluster, size) in files {
            let sum = dirent::checksum(short);
            if !long.is_empty() {
                let units: Vec<u16> = long.encode_utf16().collect();
                let slots = units.len().div_ceil(CHARS_PER_SLOT);
                for slot in (0..slots).rev() {
                    let mut r = [0u8; dirent::ENTRY_BYTES];
                    r[0] = (slot + 1) as u8 | if slot + 1 == slots { LAST_LONG_ENTRY } else { 0 };
                    r[11] = dirent::ATTR_EXT;
                    r[13] = sum;
                    let mut chars = [0xFFFFu16; CHARS_PER_SLOT];
                    let base = slot * CHARS_PER_SLOT;
                    for i in 0..CHARS_PER_SLOT {
                        if base + i < units.len() { chars[i] = units[base + i]; }
                        else if base + i == units.len() { chars[i] = 0; }
                    }
                    let mut k = 0;
                    for (start, len) in [(1usize, 10usize), (14, 12), (28, 4)] {
                        for i in (0..len).step_by(2) {
                            r[start + i..start + i + 2].copy_from_slice(&chars[k].to_le_bytes());
                            k += 1;
                        }
                    }
                    self.bytes[cursor..cursor + dirent::ENTRY_BYTES].copy_from_slice(&r);
                    cursor += dirent::ENTRY_BYTES;
                }
            }
            let mut r = [0u8; dirent::ENTRY_BYTES];
            r[..11].copy_from_slice(short);
            r[11] = *attr;
            r[20..22].copy_from_slice(&((*cluster >> 16) as u16).to_le_bytes());
            r[26..28].copy_from_slice(&(*cluster as u16).to_le_bytes());
            r[28..32].copy_from_slice(&size.to_le_bytes());
            self.bytes[cursor..cursor + dirent::ENTRY_BYTES].copy_from_slice(&r);
            cursor += dirent::ENTRY_BYTES;
        }
    }
}

impl SectorSource for Image {
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let at = usize::try_from(sector).map_err(|_| Errno::Eio)? * SECTOR;
        let end = at.checked_add(buf.len()).ok_or(Errno::Eio)?;
        if end > self.bytes.len() { return Err(Errno::Eio); }
        buf.copy_from_slice(&self.bytes[at..end]);
        Ok(())
    }
}

/// A volume with a file in the root, a file with a long name, a subdirectory
/// holding a file, a deleted entry and a volume label.
fn populated() -> (Image, Vec<u8>) {
    let mut img = Image::new();
    let payload: Vec<u8> = (0..3000u32).map(|i| (i % 251) as u8).collect();
    let file_cluster = img.write_chain(&payload);
    let long_cluster = img.write_chain(b"long name contents");

    // The subdirectory's own cluster, written after its contents are known.
    let sub_cluster = img.next_free;
    img.next_free += 1;
    img.put_fat(sub_cluster, 0xFFFF);
    let nested_cluster = img.write_chain(b"nested payload");

    let root = img.root_offset();
    img.write_dir(root, &[
        ("", *b"MYVOLUME   ", ATTR_VOLUME, 0, 0),
        ("", *b"DATA    BIN", ATTR_ARCH, file_cluster, payload.len() as u32),
        ("a long file name.txt", *b"ALONGF~1TXT", ATTR_ARCH, long_cluster, 18),
        ("", *b"SUBDIR     ", ATTR_DIR, sub_cluster, 0),
    ]);
    let sub = img.cluster_offset(sub_cluster);
    img.write_dir(sub, &[
        ("", *b".          ", ATTR_DIR, sub_cluster, 0),
        ("", *b"..         ", ATTR_DIR, 0, 0),
        ("nested.txt", *b"NESTED  TXT", ATTR_ARCH, nested_cluster, 14),
    ]);
    (img, payload)
}

/// Mounting resolves the layout from the image's own boot sector.
#[test]
fn a_volume_mounts_and_reports_its_layout() {
    let (img, _) = populated();
    let v = Volume::mount(img).expect("mount");
    assert_eq!(v.width(), FatWidth::Fat16, "the fixture must be the width it writes");
    assert!(v.geometry().total_clusters > crate::geometry::MAX_FAT12);
    assert_eq!(v.geometry().sector_size, SECTOR as u32);
    assert_eq!(v.geometry().data_start as usize,
               RESERVED + FATS * FAT_SECTORS + ROOT_ENTRIES * dirent::ENTRY_BYTES / SECTOR);
}

/// The root lists its files, hides the volume label, and carries long names
/// where the image wrote them.
#[test]
fn the_root_lists_its_files_and_hides_the_label() {
    let (img, _) = populated();
    let v = Volume::mount(img).expect("mount");
    let names: Vec<String> = v.read_root().expect("read root").into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["DATA.BIN", "a long file name.txt", "SUBDIR"]);
    assert!(!names.iter().any(|n| n.contains("MYVOLUME")), "a label is not a file");
}

/// The whole stack, end to end: a multi-cluster file read back byte for byte.
#[test]
fn a_multi_cluster_file_reads_back_exactly() {
    let (img, payload) = populated();
    let v = Volume::mount(img).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    assert_eq!(hit.size(), payload.len() as u64);
    assert_eq!(v.read_whole(&hit.entry).expect("read"), payload);
    assert!(payload.len() > SEC_PER_CLUS * SECTOR, "the file really does span clusters");
}

/// A read stops at the declared size. The tail of the last cluster is not
/// part of the file, and returning it appends whatever the medium last held.
#[test]
fn a_read_stops_at_the_declared_size() {
    let (img, payload) = populated();
    let v = Volume::mount(img).expect("mount");
    let hit = v.lookup("data.bin").expect("lookup is case-insensitive");
    let mut buf = vec![0xAAu8; 4096];
    let got = v.read_file(&hit.entry, 0, &mut buf).expect("read");
    assert_eq!(got, payload.len(), "not the whole cluster");
    assert_eq!(buf[got], 0xAA, "and nothing past it was written");
    // Reading from the end yields nothing rather than the cluster's tail.
    assert_eq!(v.read_file(&hit.entry, payload.len() as u64, &mut buf), Ok(0));
    assert_eq!(v.read_file(&hit.entry, u64::MAX, &mut buf), Ok(0));
}

/// A read at an offset lands where it should, including across a cluster
/// boundary — the case a per-cluster reader gets wrong by a whole cluster.
#[test]
fn a_read_at_an_offset_crosses_cluster_boundaries_correctly() {
    let (img, payload) = populated();
    let v = Volume::mount(img).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    let per = SEC_PER_CLUS * SECTOR;
    for offset in [0usize, 1, per - 1, per, per + 1, 2 * per - 5] {
        let mut buf = vec![0u8; 64];
        let got = v.read_file(&hit.entry, offset as u64, &mut buf).expect("read");
        assert_eq!(&buf[..got], &payload[offset..offset + got], "offset {offset}");
        assert!(got > 0);
    }
}

/// A path resolves through a subdirectory, and the file there reads back.
#[test]
fn a_path_resolves_through_a_subdirectory() {
    let (img, _) = populated();
    let v = Volume::mount(img).expect("mount");
    let hit = v.lookup("SUBDIR/nested.txt").expect("nested lookup");
    assert_eq!(v.read_whole(&hit.entry).expect("read"), b"nested payload");
    assert_eq!(v.lookup("/SUBDIR/nested.txt").map(|e| e.name), Ok(String::from("nested.txt")),
               "a leading slash is not a component");
    assert_eq!(v.lookup("SUBDIR/./nested.txt").map(|e| e.name), Ok(String::from("nested.txt")));
}

/// A long name resolves by its long form and reads back.
#[test]
fn a_long_name_resolves_and_reads() {
    let (img, _) = populated();
    let v = Volume::mount(img).expect("mount");
    let hit = v.lookup("a long file name.txt").expect("long lookup");
    assert_eq!(v.read_whole(&hit.entry).expect("read"), b"long name contents");
}

/// A missing name is `ENOENT`, and a directory is not readable as a file.
#[test]
fn the_refusals_are_the_ones_a_caller_expects() {
    let (img, _) = populated();
    let v = Volume::mount(img).expect("mount");
    assert_eq!(v.lookup("nope.txt").err(), Some(Errno::Enoent));
    assert_eq!(v.lookup("SUBDIR/nope").err(), Some(Errno::Enoent));
    let dir = v.lookup("SUBDIR").expect("the directory itself resolves");
    assert!(dir.is_dir());
    let mut buf = vec![0u8; 16];
    assert_eq!(v.read_file(&dir.entry, 0, &mut buf), Err(Errno::Eisdir));
}

/// A deleted entry is not listed, and it breaks any long-name run in
/// progress: those slots belonged to the name that was removed.
#[test]
fn a_deleted_entry_is_hidden_and_ends_its_run() {
    let mut img = Image::new();
    let cluster = img.write_chain(b"still here");
    let root = img.root_offset();
    img.write_dir(root, &[
        ("removed name.txt", *b"REMOVE~1TXT", ATTR_ARCH, 9, 5),
        ("", *b"KEPT    TXT", ATTR_ARCH, cluster, 10),
    ]);
    // Mark the short entry of the first file deleted, leaving its long slots.
    let deleted_at = root + 2 * dirent::ENTRY_BYTES; // two long slots precede it
    img.bytes[deleted_at] = DELETED_FLAG;
    let v = Volume::mount(img).expect("mount");
    let entries = v.read_root().expect("read root");
    assert_eq!(entries.len(), 1, "only the surviving file");
    assert_eq!(entries[0].name, "KEPT.TXT",
               "and it did not inherit the removed file's long name");
}

/// A volume whose boot sector is not a FAT volume is refused at mount, not
/// discovered later as unreadable directories.
#[test]
fn a_volume_that_is_not_fat_is_refused_at_mount() {
    let mut img = Image::new();
    img.bytes[0x15] = 0x00; // media descriptor no volume uses
    assert_eq!(Volume::mount(img).err(), Some(Errno::Einval));
}

/// A truncated medium is an error rather than a short read treated as data.
#[test]
fn a_truncated_medium_is_an_error() {
    let mut img = Image::new();
    img.bytes.truncate(SECTOR * 4);
    assert_eq!(Volume::mount(img).err(), Some(Errno::Eio));
}

/// An entry whose size claims more than its chain holds is `EIO`: the entry
/// and the table disagree, and the table owns the data.
#[test]
fn a_size_longer_than_its_chain_is_refused() {
    let mut img = Image::new();
    let cluster = img.write_chain(b"short");
    let root = img.root_offset();
    img.write_dir(root, &[("", *b"LIAR    BIN", ATTR_ARCH, cluster, 100_000)]);
    let v = Volume::mount(img).expect("mount");
    let hit = v.lookup("LIAR.BIN").expect("lookup");
    let mut buf = vec![0u8; 100_000];
    assert_eq!(v.read_file(&hit.entry, 0, &mut buf), Err(Errno::Eio));
}

/// An empty file names no cluster, so reading it must not walk a chain from
/// cluster zero — which is a reserved entry, not data.
#[test]
fn an_empty_file_reads_nothing_without_walking_a_chain() {
    let mut img = Image::new();
    let root = img.root_offset();
    img.write_dir(root, &[("", *b"EMPTY   TXT", ATTR_ARCH, 0, 0)]);
    let v = Volume::mount(img).expect("mount");
    let hit = v.lookup("EMPTY.TXT").expect("lookup");
    assert_eq!(v.read_whole(&hit.entry), Ok(vec![]));
    let mut buf = vec![0u8; 16];
    assert_eq!(v.read_file(&hit.entry, 0, &mut buf), Ok(0));
}

/// The fixed root is a region, not a chain. Walking it as one reads table
/// entry zero — the media descriptor — and follows it somewhere arbitrary.
#[test]
fn the_fixed_root_is_read_as_a_region_not_a_chain() {
    let (img, _) = populated();
    let v = Volume::mount(img).expect("mount");
    assert!(v.geometry().has_fixed_root());
    assert!(v.read_root().is_ok(), "the root reads without consulting the table");
    // Entry 0 holds the media descriptor, which as a link would be an end
    // mark — a root read through it would come back empty.
    assert_eq!(crate::chain::read_entry(FatWidth::Fat16, &v.table, 0),
               Some(crate::chain::Link::End));
    assert!(!v.read_root().unwrap().is_empty());
}
