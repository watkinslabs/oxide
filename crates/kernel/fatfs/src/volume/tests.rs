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
struct Builder {
    bytes: Vec<u8>,
    next_free: u32,
}

impl Builder {
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

/// The medium the volume reads and writes. Separate from the builder so the
/// bytes can be shared under a lock while a `Volume` owns it.
struct Image {
    bytes: sync::Spinlock<Vec<u8>, sync::TaskList>,
    writable: bool,
}

impl Builder {
    /// Freeze this image into a medium, writable or not.
    fn image(self, writable: bool) -> Image {
        Image { bytes: sync::Spinlock::new(self.bytes), writable }
    }
}

impl SectorSource for Image {
    fn read_sectors(&self, sector: u64, buf: &mut [u8]) -> Result<(), Errno> {
        let src = self.bytes.lock();
        let at = usize::try_from(sector).map_err(|_| Errno::Eio)? * SECTOR;
        let end = at.checked_add(buf.len()).ok_or(Errno::Eio)?;
        if end > src.len() { return Err(Errno::Eio); }
        buf.copy_from_slice(&src[at..end]);
        Ok(())
    }

    fn write_sectors(&self, sector: u64, buf: &[u8]) -> Result<(), Errno> {
        if !self.writable { return Err(Errno::Erofs); }
        let mut dst = self.bytes.lock();
        let at = usize::try_from(sector).map_err(|_| Errno::Eio)? * SECTOR;
        let end = at.checked_add(buf.len()).ok_or(Errno::Eio)?;
        if end > dst.len() { return Err(Errno::Eio); }
        dst[at..end].copy_from_slice(buf);
        Ok(())
    }

    fn writable(&self) -> bool { self.writable }
}

/// A volume with a file in the root, a file with a long name, a subdirectory
/// holding a file, a deleted entry and a volume label.
fn populated() -> (Builder, Vec<u8>) {
    let mut img = Builder::new();
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
    let v = Volume::mount(img.image(false)).expect("mount");
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
    let v = Volume::mount(img.image(false)).expect("mount");
    let names: Vec<String> = v.read_root().expect("read root").into_iter().map(|e| e.name).collect();
    assert_eq!(names, vec!["DATA.BIN", "a long file name.txt", "SUBDIR"]);
    assert!(!names.iter().any(|n| n.contains("MYVOLUME")), "a label is not a file");
}

/// The whole stack, end to end: a multi-cluster file read back byte for byte.
#[test]
fn a_multi_cluster_file_reads_back_exactly() {
    let (img, payload) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
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
    let v = Volume::mount(img.image(false)).expect("mount");
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
    let v = Volume::mount(img.image(false)).expect("mount");
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
    let v = Volume::mount(img.image(false)).expect("mount");
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
    let v = Volume::mount(img.image(false)).expect("mount");
    let hit = v.lookup("a long file name.txt").expect("long lookup");
    assert_eq!(v.read_whole(&hit.entry).expect("read"), b"long name contents");
}

/// A missing name is `ENOENT`, and a directory is not readable as a file.
#[test]
fn the_refusals_are_the_ones_a_caller_expects() {
    let (img, _) = populated();
    let v = Volume::mount(img.image(false)).expect("mount");
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
    let mut img = Builder::new();
    let cluster = img.write_chain(b"still here");
    let root = img.root_offset();
    img.write_dir(root, &[
        ("removed name.txt", *b"REMOVE~1TXT", ATTR_ARCH, 9, 5),
        ("", *b"KEPT    TXT", ATTR_ARCH, cluster, 10),
    ]);
    // Mark the short entry of the first file deleted, leaving its long slots.
    let deleted_at = root + 2 * dirent::ENTRY_BYTES; // two long slots precede it
    img.bytes[deleted_at] = DELETED_FLAG;
    let v = Volume::mount(img.image(false)).expect("mount");
    let entries = v.read_root().expect("read root");
    assert_eq!(entries.len(), 1, "only the surviving file");
    assert_eq!(entries[0].name, "KEPT.TXT",
               "and it did not inherit the removed file's long name");
}

/// A volume whose boot sector is not a FAT volume is refused at mount, not
/// discovered later as unreadable directories.
#[test]
fn a_volume_that_is_not_fat_is_refused_at_mount() {
    let mut img = Builder::new();
    img.bytes[0x15] = 0x00; // media descriptor no volume uses
    assert_eq!(Volume::mount(img.image(false)).err(), Some(Errno::Einval));
}

/// A truncated medium is an error rather than a short read treated as data.
#[test]
fn a_truncated_medium_is_an_error() {
    let mut img = Builder::new();
    img.bytes.truncate(SECTOR * 4);
    assert_eq!(Volume::mount(img.image(false)).err(), Some(Errno::Eio));
}

/// An entry whose size claims more than its chain holds is `EIO`: the entry
/// and the table disagree, and the table owns the data.
#[test]
fn a_size_longer_than_its_chain_is_refused() {
    let mut img = Builder::new();
    let cluster = img.write_chain(b"short");
    let root = img.root_offset();
    img.write_dir(root, &[("", *b"LIAR    BIN", ATTR_ARCH, cluster, 100_000)]);
    let v = Volume::mount(img.image(false)).expect("mount");
    let hit = v.lookup("LIAR.BIN").expect("lookup");
    let mut buf = vec![0u8; 100_000];
    assert_eq!(v.read_file(&hit.entry, 0, &mut buf), Err(Errno::Eio));
}

/// An empty file names no cluster, so reading it must not walk a chain from
/// cluster zero — which is a reserved entry, not data.
#[test]
fn an_empty_file_reads_nothing_without_walking_a_chain() {
    let mut img = Builder::new();
    let root = img.root_offset();
    img.write_dir(root, &[("", *b"EMPTY   TXT", ATTR_ARCH, 0, 0)]);
    let v = Volume::mount(img.image(false)).expect("mount");
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
    let v = Volume::mount(img.image(false)).expect("mount");
    assert!(v.geometry().has_fixed_root());
    assert!(v.read_root().is_ok(), "the root reads without consulting the table");
    // Entry 0 holds the media descriptor, which as a link would be an end
    // mark — a root read through it would come back empty.
    assert_eq!(crate::chain::read_entry(FatWidth::Fat16, &v.table, 0),
               Some(crate::chain::Link::End));
    assert!(!v.read_root().unwrap().is_empty());
}

/// A file's bytes reach the medium and read back — the point of the whole
/// write path.
#[test]
fn a_write_reaches_the_medium_and_reads_back() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    assert!(v.writable());
    let hit = v.lookup("DATA.BIN").expect("lookup");
    let payload = alloc::vec![0x77u8; 100];
    let size = v.write_file(None, &hit, 0, &payload).expect("write");
    assert_eq!(size, hit.size(), "an in-place write does not change the size");
    let again = v.lookup("DATA.BIN").expect("lookup");
    let mut buf = alloc::vec![0u8; 100];
    assert_eq!(v.read_file(&again.entry, 0, &mut buf), Ok(100));
    assert_eq!(buf, payload);
}

/// Writing past the end grows the file: the chain is extended, the record's
/// size is updated, and the new bytes read back.
#[test]
fn a_write_past_the_end_grows_the_file_and_its_record() {
    let (img, payload) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    let tail = alloc::vec![0xEEu8; 1000];
    let grown = v.write_file(None, &hit, payload.len() as u64, &tail).expect("write");
    assert_eq!(grown, payload.len() as u64 + 1000);

    let again = v.lookup("DATA.BIN").expect("lookup");
    assert_eq!(again.size(), grown, "the record carries the new size");
    let mut buf = alloc::vec![0u8; 1000];
    assert_eq!(v.read_file(&again.entry, payload.len() as u64, &mut buf), Ok(1000));
    assert_eq!(buf, tail);
    // ...and the bytes that were already there are untouched.
    let mut head = alloc::vec![0u8; payload.len()];
    v.read_file(&again.entry, 0, &mut head).expect("read");
    assert_eq!(head, payload);
}

/// A write that covers part of a cluster keeps the rest of that cluster.
/// Writing the whole cluster from a partial buffer destroys the bytes either
/// side of the range the caller asked for.
#[test]
fn a_partial_cluster_write_keeps_the_bytes_around_it() {
    let (img, payload) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    v.write_file(None, &hit, 700, &[0xAB, 0xCD]).expect("write");
    let again = v.lookup("DATA.BIN").expect("lookup");
    let mut buf = alloc::vec![0u8; 704];
    v.read_file(&again.entry, 0, &mut buf).expect("read");
    assert_eq!(&buf[700..702], &[0xAB, 0xCD]);
    assert_eq!(&buf[..700], &payload[..700], "everything before survived");
    assert_eq!(&buf[702..704], &payload[702..704], "and everything after");
}

/// An empty file names no cluster; writing to it allocates one and records it.
#[test]
fn writing_to_an_empty_file_gives_it_a_chain() {
    let mut img = Builder::new();
    let root = img.root_offset();
    img.write_dir(root, &[("", *b"EMPTY   TXT", ATTR_ARCH, 0, 0)]);
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let hit = v.lookup("EMPTY.TXT").expect("lookup");
    assert_eq!(hit.entry.cluster, 0);
    assert_eq!(v.write_file(None, &hit, 0, b"first bytes"), Ok(11));
    let again = v.lookup("EMPTY.TXT").expect("lookup");
    assert_ne!(again.entry.cluster, 0, "it has a chain now");
    assert_eq!(v.read_whole(&again.entry).as_deref(), Ok(&b"first bytes"[..]));
}

/// EVERY copy of the table is updated. A volume left with two tables that
/// disagree is one every checker elsewhere reports.
#[test]
fn every_copy_of_the_table_is_written() {
    let (img, _) = populated();
    let image = img.image(true);
    let mut v = Volume::mount(image).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    v.write_file(None, &hit, 10_000, b"grow").expect("write past the end allocates");
    let first = (RESERVED) * SECTOR;
    let second = (RESERVED + FAT_SECTORS) * SECTOR;
    for i in 0..FAT_SECTORS * SECTOR {
        assert_eq!(v.source_bytes(first + i), v.source_bytes(second + i),
                   "the two tables differ at byte {i}");
    }
}

/// A read-only medium refuses every write, at the write rather than halfway
/// through one.
#[test]
fn a_read_only_medium_refuses_writes() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(false)).expect("mount");
    assert!(!v.writable());
    let hit = v.lookup("DATA.BIN").expect("lookup");
    assert_eq!(v.write_file(None, &hit, 0, b"nope"), Err(Errno::Erofs));
    assert_eq!(v.truncate_file(None, &hit), Err(Errno::Erofs));
}

/// A volume its last owner left dirty still mounts writable, exactly as the
/// reference does: it warns that a check is due and proceeds. Refusing would
/// leave a user unable to save anything to a stick that was pulled once.
#[test]
fn a_volume_left_dirty_still_mounts_writable() {
    let (mut img, _) = populated();
    crate::volstate::set_dirty(&mut img.bytes, FatWidth::Fat16, true).expect("mark");
    let mut v = Volume::mount(img.image(true)).expect("mount");
    assert!(v.was_dirty(), "the volume admits it, so a caller can warn");
    assert!(v.writable(), "and it is still writable");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    assert!(v.write_file(None, &hit, 0, b"ok").is_ok());
}

/// ...and its flag is left exactly as its last owner set it. Clearing it at
/// this unmount would tell the next reader a check had happened when none has.
#[test]
fn an_already_dirty_flag_is_not_rewritten() {
    let (mut img, _) = populated();
    crate::volstate::set_dirty(&mut img.bytes, FatWidth::Fat16, true).expect("mark");
    let v = Volume::mount(img.image(true)).expect("mount");
    let at = crate::volstate::state_offset(FatWidth::Fat16);
    v.set_dirty(false).expect("unmount tries to clear it");
    assert_ne!(v.source_bytes(at) & crate::volstate::FAT_STATE_DIRTY, 0,
               "the flag its last owner set survives");
}

/// The dirty flag round-trips through the medium, so a volume mounted
/// writable and pulled mid-write tells the next system that read it.
#[test]
fn the_dirty_flag_reaches_the_medium() {
    let (img, _) = populated();
    let v = Volume::mount(img.image(true)).expect("mount");
    let at = crate::volstate::state_offset(FatWidth::Fat16);
    assert_eq!(v.source_bytes(at) & crate::volstate::FAT_STATE_DIRTY, 0);
    v.set_dirty(true).expect("mark dirty");
    assert_ne!(v.source_bytes(at) & crate::volstate::FAT_STATE_DIRTY, 0);
    v.set_dirty(false).expect("mark clean");
    assert_eq!(v.source_bytes(at) & crate::volstate::FAT_STATE_DIRTY, 0);
}

/// Truncation releases the chain and zeroes the record, and the clusters come
/// back for the next file.
#[test]
fn truncation_releases_the_chain_and_zeroes_the_record() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let before = v.free_clusters();
    let hit = v.lookup("DATA.BIN").expect("lookup");
    v.truncate_file(None, &hit).expect("truncate");
    let again = v.lookup("DATA.BIN").expect("lookup");
    assert_eq!(again.size(), 0);
    assert_eq!(again.entry.cluster, 0);
    assert!(v.free_clusters() > before, "its clusters came back");
}

/// A full volume reports ENOSPC and changes nothing, rather than writing a
/// file it cannot hold.
#[test]
fn a_full_volume_reports_enospc_and_keeps_the_file_intact() {
    let (img, payload) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let hit = v.lookup("DATA.BIN").expect("lookup");
    let huge = (u64::from(v.geometry().total_clusters) + 10) * v.geometry().cluster_bytes();
    assert_eq!(v.write_file(None, &hit, huge, b"x").err(), Some(Errno::Enospc));
    let again = v.lookup("DATA.BIN").expect("lookup");
    assert_eq!(again.size(), payload.len() as u64, "the file is as it was");
    let mut buf = alloc::vec![0u8; payload.len()];
    v.read_file(&again.entry, 0, &mut buf).expect("read");
    assert_eq!(buf, payload, "and its bytes are as they were");
}

/// A directory is not writable as a file.
#[test]
fn a_directory_refuses_a_write() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let dir = v.lookup("SUBDIR").expect("lookup");
    assert_eq!(v.write_file(None, &dir, 0, b"x"), Err(Errno::Eisdir));
    assert_eq!(v.truncate_file(None, &dir), Err(Errno::Eisdir));
}

/// A file in a SUBDIRECTORY updates its record where that record lives — in
/// the directory's cluster, not in the root.
#[test]
fn a_subdirectorys_file_updates_its_own_record() {
    let (img, _) = populated();
    let mut v = Volume::mount(img.image(true)).expect("mount");
    let sub = v.lookup("SUBDIR").expect("subdir");
    let entries = v.read_dir(Some(sub.entry.cluster)).expect("read subdir");
    let nested = entries.into_iter().find(|e| e.name == "nested.txt").expect("nested");
    v.write_file(Some(sub.entry.cluster), &nested, 0, b"rewritten!").expect("write");
    let entries = v.read_dir(Some(sub.entry.cluster)).expect("read subdir");
    let again = entries.into_iter().find(|e| e.name == "nested.txt").expect("nested");
    assert_eq!(again.size(), 14, "unchanged: the write fitted inside it");
    let mut buf = alloc::vec![0u8; 10];
    v.read_file(&again.entry, 0, &mut buf).expect("read");
    assert_eq!(&buf, b"rewritten!");
}
