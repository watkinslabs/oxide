use super::*;
use crate::dirent::{ATTR_ARCH, ATTR_DIR, ATTR_VOLUME, CHARS_PER_SLOT, DELETED_FLAG,
                    LAST_LONG_ENTRY};
use alloc::vec;

impl Volume<sectors::MemImage> {
    fn source_commands(&self) -> Vec<sectors::source::Cmd> { self.source.commands() }
}

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

/// Write faults this medium is told to produce.
///
/// A multi-step change to a volume is not atomic and nothing here makes it so,
/// so the only way to test the ORDER of its steps is to stop it between two of
/// them and look at what survived. `fail_at` is the ordinal of the write that
/// fails; every write is counted whether or not it fails.
#[derive(Default)]
pub struct Faults {
    pub seen: usize,
    pub fail_at: Option<usize>,
}

/// The medium the volume reads and writes. Separate from the builder so the
/// bytes can be shared under a lock while a `Volume` owns it.
struct Image {
    bytes: sync::Spinlock<Vec<u8>, sync::TaskList>,
    writable: bool,
    faults: ::alloc::sync::Arc<sync::Spinlock<Faults, sync::TaskList>>,
}

impl Builder {
    /// Freeze this image into a medium, writable or not.
    fn image(self, writable: bool) -> Image {
        self.image_with_faults(writable).0
    }

    /// The same, with a handle that can make a chosen write fail.
    fn image_with_faults(self, writable: bool)
        -> (Image, ::alloc::sync::Arc<sync::Spinlock<Faults, sync::TaskList>>) {
        let faults = ::alloc::sync::Arc::new(sync::Spinlock::new(Faults::default()));
        (Image { bytes: sync::Spinlock::new(self.bytes), writable, faults: faults.clone() },
         faults)
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
        {
            let mut f = self.faults.lock();
            f.seen += 1;
            if f.fail_at == Some(f.seen) { return Err(Errno::Eio); }
        }
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


impl Builder {
    /// Fill every cluster this image has not handed out with a byte pattern
    /// no zeroing could produce.
    ///
    /// Without it a test that a newly claimed directory cluster was CLEARED
    /// proves nothing: a fresh image is already zero everywhere, so the check
    /// passes whether or not anything cleared it.
    fn scribble_free_clusters(&mut self) {
        let from = self.cluster_offset(self.next_free);
        for byte in self.bytes[from..].iter_mut() { *byte = 0xFF; }
    }
}

/// A fixed reading for every stamped operation, with all three fields
/// distinct so a field written from the wrong one shows up.
pub fn when() -> crate::time::FatTime {
    crate::time::FatTime { time: 0x4a3c, date: 0x5123, cs: 137 }
}

/// The root, as an operation on this volume sees it.
pub fn root_of<S: SectorSource>(v: &Volume<S>) -> crate::volume::DirHandle {
    crate::volume::DirHandle::root(v.root_cluster())
}

#[path = "tests/read.rs"] mod read;
#[path = "tests/write.rs"] mod write;
#[path = "tests/namei.rs"] mod namei;
#[path = "tests/rename.rs"] mod rename;
#[path = "tests/space.rs"] mod space;
