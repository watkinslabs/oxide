//! An exFAT volume built the way a formatter would.
//!
//! Independent of the reader: the layout here is written from the format's own
//! rules, so a passing test proves the two AGREE rather than that one function
//! is self-consistent with itself. Every structure a real medium carries is
//! present — both boot regions with their checksums, the table, the allocation
//! bitmap, the up-case table and its entry, and the volume label.

use alloc::vec;
use alloc::vec::Vec;

use sectors::MemImage;

use crate::checksum;
use crate::opts::Options;
use crate::uapi::*;
use crate::upcase;
use crate::volume::Volume;

pub const SECTOR: usize = 512;
pub const SECTOR_BITS: u8 = 9;
pub const SEC_PER_CLUS_BITS: u8 = 3;
pub const CLUSTER: usize = SECTOR << SEC_PER_CLUS_BITS;
/// Sectors of the two boot regions, which occupy the first 24.
pub const FAT_START: u32 = 24;
pub const FAT_SECTORS: u32 = 16;
pub const DATA_START: u32 = FAT_START + FAT_SECTORS;
pub const CLUSTER_COUNT: u32 = 256;
/// The root, the bitmap and the up-case table take the first three clusters.
pub const ROOT_CLUSTER: u32 = 2;
pub const BITMAP_CLUSTER: u32 = 3;
pub const UPCASE_CLUSTER: u32 = 4;
pub const FIRST_FREE: u32 = 5;

/// A volume under construction.
pub struct Builder {
    pub bytes: Vec<u8>,
    /// Directory entries written into the root so far.
    root: Vec<u8>,
    next_free: u32,
}

impl Builder {
    /// An empty formatted volume. # C: O(image bytes)
    pub fn new() -> Self {
        let sectors = DATA_START as usize + CLUSTER_COUNT as usize * (CLUSTER / SECTOR);
        let mut b = Self { bytes: vec![0u8; sectors * SECTOR], root: Vec::new(),
                           next_free: FIRST_FREE };
        b.write_boot_region(0);
        b.write_boot_region(BOOT_REGION_LEN);
        b
    }

    /// Byte offset of a cluster. # C: O(1)
    pub fn cluster_at(&self, cluster: u32) -> usize {
        (DATA_START as usize + (cluster as usize - 2) * (CLUSTER / SECTOR)) * SECTOR
    }

    /// Byte offset of a table entry. # C: O(1)
    fn fat_at(&self, cluster: u32) -> usize {
        FAT_START as usize * SECTOR + cluster as usize * FAT_ENTRY_BYTES
    }

    /// Set one table entry. # C: O(1)
    pub fn put_fat(&mut self, cluster: u32, value: u32) {
        let at = self.fat_at(cluster);
        self.bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
    }

    /// Claim one cluster in the allocation bitmap. # C: O(1)
    pub fn claim(&mut self, cluster: u32) {
        let index = (cluster - RESERVED_CLUSTERS) as usize;
        let at = self.cluster_at(BITMAP_CLUSTER) + index / 8;
        self.bytes[at] |= 1 << (index % 8);
    }

    /// Write the boot sector and its region's checksum at `base`.
    /// # C: O(region bytes)
    fn write_boot_region(&mut self, base: u64) {
        let at = base as usize * SECTOR;
        let b = &mut self.bytes[at..at + SECTOR];
        b[OFF_FS_NAME..OFF_FS_NAME + FS_NAME_LEN].copy_from_slice(FS_NAME.as_slice());
        let total = (DATA_START as u64) + u64::from(CLUSTER_COUNT) * (CLUSTER / SECTOR) as u64;
        b[OFF_VOL_LENGTH..OFF_VOL_LENGTH + 8].copy_from_slice(&total.to_le_bytes());
        b[OFF_FAT_OFFSET..OFF_FAT_OFFSET + 4].copy_from_slice(&FAT_START.to_le_bytes());
        b[OFF_FAT_LENGTH..OFF_FAT_LENGTH + 4].copy_from_slice(&FAT_SECTORS.to_le_bytes());
        b[OFF_CLU_OFFSET..OFF_CLU_OFFSET + 4].copy_from_slice(&DATA_START.to_le_bytes());
        b[OFF_CLU_COUNT..OFF_CLU_COUNT + 4].copy_from_slice(&CLUSTER_COUNT.to_le_bytes());
        b[OFF_ROOT_CLUSTER..OFF_ROOT_CLUSTER + 4].copy_from_slice(&ROOT_CLUSTER.to_le_bytes());
        b[OFF_VOL_SERIAL..OFF_VOL_SERIAL + 4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        b[OFF_FS_REVISION] = 0;
        b[OFF_FS_REVISION + 1] = 1;
        b[OFF_SECT_SIZE_BITS] = SECTOR_BITS;
        b[OFF_SECT_PER_CLUS_BITS] = SEC_PER_CLUS_BITS;
        b[OFF_NUM_FATS] = 1;
        b[OFF_SIGNATURE..OFF_SIGNATURE + 2].copy_from_slice(&BOOT_SIGNATURE.to_le_bytes());
        for sector in 1..BOOT_REGION_SECTORS {
            let at = (base + sector) as usize * SECTOR;
            self.bytes[at + SECTOR - 4..at + SECTOR]
                .copy_from_slice(&EXBOOT_SIGNATURE.to_le_bytes());
        }
        self.seal_boot_region(base);
    }

    /// Recompute a boot region's checksum sector. # C: O(region bytes)
    pub fn seal_boot_region(&mut self, base: u64) {
        let mut sum = 0u32;
        for sector in 0..BOOT_REGION_SECTORS {
            let at = (base + sector) as usize * SECTOR;
            sum = checksum::boot_region(&self.bytes[at..at + SECTOR], sum, sector == 0);
        }
        let at = (base + BOOT_CHECKSUM_SECTOR) as usize * SECTOR;
        for chunk in self.bytes[at..at + SECTOR].chunks_exact_mut(4) {
            chunk.copy_from_slice(&sum.to_le_bytes());
        }
    }

    /// Take the next free cluster. # C: O(1)
    pub fn alloc(&mut self) -> u32 {
        let cluster = self.next_free;
        self.next_free += 1;
        self.claim(cluster);
        cluster
    }

    /// Write `data` into a contiguous run and return its first cluster.
    /// # C: O(data bytes)
    pub fn write_run(&mut self, data: &[u8]) -> u32 {
        let count = core::cmp::max(1, data.len().div_ceil(CLUSTER));
        let first = self.next_free;
        for i in 0..count {
            let cluster = self.alloc();
            let at = self.cluster_at(cluster);
            let start = i * CLUSTER;
            let end = core::cmp::min(start + CLUSTER, data.len());
            if start < data.len() { self.bytes[at..at + (end - start)].copy_from_slice(&data[start..end]); }
        }
        first
    }

    /// Write `data` into a run linked through the table, one cluster at a time
    /// with a gap between each, so the run cannot be read as contiguous.
    /// # C: O(data bytes)
    pub fn write_chained(&mut self, data: &[u8]) -> u32 {
        let count = core::cmp::max(1, data.len().div_ceil(CLUSTER));
        let mut clusters = Vec::new();
        for _ in 0..count {
            clusters.push(self.alloc());
            // Skip one, so the next cluster is not adjacent.
            let skipped = self.alloc();
            self.put_fat(skipped, EOF_CLUSTER);
        }
        for (i, cluster) in clusters.iter().enumerate() {
            let at = self.cluster_at(*cluster);
            let start = i * CLUSTER;
            let end = core::cmp::min(start + CLUSTER, data.len());
            if start < data.len() {
                self.bytes[at..at + (end - start)].copy_from_slice(&data[start..end]);
            }
            let next = clusters.get(i + 1).copied().unwrap_or(EOF_CLUSTER);
            self.put_fat(*cluster, next);
        }
        clusters[0]
    }

    /// Append one raw entry to the root directory. # C: O(1)
    pub fn push_root_entry(&mut self, entry: &[u8]) { self.root.extend_from_slice(entry); }

    /// Append a whole entry set for one name. # C: O(name length)
    pub fn push_name(&mut self, name: &str, is_dir: bool, start: u32, size: u64, flags: u8) {
        self.push_name_sized(name, is_dir, start, size, size, flags);
    }

    /// Append a set whose ALLOCATION and whose written length differ, which is
    /// the case a reader must not confuse: the bytes between the two were
    /// never written by anyone. # C: O(name length)
    pub fn push_name_sized(&mut self, name: &str, is_dir: bool, start: u32, size: u64,
                           valid: u64, flags: u8) {
        let table = upcase::builtin();
        let units: Vec<u16> = name.encode_utf16().collect();
        let hash = checksum::name_hash(&table.fold_name(&units));
        let attrs = crate::dirent::file::new_attrs(is_dir);
        let stamp = crate::time::Stamp { fields: dostime::DosTime { time: 0, date: (1 << 5) | 1, cs: 0 },
                                         tz: TZ_VALID };
        let bytes = crate::dirent::set::build(attrs, &units, hash, start, size, valid, flags,
                                              stamp, stamp, stamp).unwrap();
        self.push_root_entry(&bytes);
    }

    /// Lay the volume's own structures into the root and finish the image.
    /// # C: O(image bytes)
    pub fn finish(mut self) -> MemImage {
        // The root, the bitmap and the up-case table each take one cluster.
        for cluster in [ROOT_CLUSTER, BITMAP_CLUSTER, UPCASE_CLUSTER] {
            self.claim(cluster);
            self.put_fat(cluster, EOF_CLUSTER);
        }
        self.put_fat(0, 0xFFFF_FFF8);
        self.put_fat(1, EOF_CLUSTER);

        let table = upcase::compress(&upcase::builtin());
        let sum = checksum::sum32(&table, 0);
        let at = self.cluster_at(UPCASE_CLUSTER);
        self.bytes[at..at + table.len()].copy_from_slice(&table);

        let mut head = Vec::new();
        let mut label = vec![0u8; DENTRY_BYTES];
        crate::dirent::meta::write_label(&"OXIDE".encode_utf16().collect::<Vec<u16>>(),
                                         &mut label).unwrap();
        head.extend_from_slice(&label);
        let mut bitmap = vec![0u8; DENTRY_BYTES];
        crate::dirent::meta::write_bitmap(&crate::dirent::meta::BitmapEntry {
            flags: 0,
            start_cluster: BITMAP_CLUSTER,
            size: crate::bitmap::bytes_for(CLUSTER_COUNT),
        }, &mut bitmap);
        head.extend_from_slice(&bitmap);
        let mut upc = vec![0u8; DENTRY_BYTES];
        crate::dirent::meta::write_upcase(&crate::dirent::meta::UpcaseEntry {
            checksum: sum,
            start_cluster: UPCASE_CLUSTER,
            size: table.len() as u64,
        }, &mut upc);
        head.extend_from_slice(&upc);
        head.extend_from_slice(&self.root);

        let at = self.cluster_at(ROOT_CLUSTER);
        assert!(head.len() <= CLUSTER, "root fixture does not fit one cluster");
        self.bytes[at..at + head.len()].copy_from_slice(&head);

        MemImage::from_bytes(SECTOR as u32, self.bytes)
    }
}

/// A mounted volume over a freshly built image. # C: O(image bytes)
pub fn mount(builder: Builder) -> Volume<MemImage> {
    let mut opts = Options::defaults();
    opts.settle();
    Volume::mount_with(builder.finish(), opts).expect("fixture must mount")
}

/// A mounted volume with nothing in it but the volume's own structures.
/// # C: O(image bytes)
pub fn empty() -> Volume<MemImage> { mount(Builder::new()) }
