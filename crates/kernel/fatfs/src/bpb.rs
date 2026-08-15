//! The BIOS parameter block, and which of its fields a volume may carry.
//!
//! Every field is read little-endian and unaligned: the block is a byte layout
//! at fixed offsets inside the first sector, not a struct, and two of its
//! 16-bit fields sit at odd offsets.
//!
//! The validation ORDER is contract. A volume wrong in several ways must be
//! refused for the same reason every time, or a caller probing a medium to
//! decide what it is gets a different answer here than elsewhere.

use syscall::errno::Errno;

/// Byte offsets of every field this filesystem reads.
mod off {
    pub const SECTOR_SIZE: usize = 0x0b;
    pub const SEC_PER_CLUS: usize = 0x0d;
    pub const RESERVED: usize = 0x0e;
    pub const FATS: usize = 0x10;
    pub const DIR_ENTRIES: usize = 0x11;
    pub const TOTAL_SECT16: usize = 0x13;
    pub const MEDIA: usize = 0x15;
    pub const FAT_LENGTH16: usize = 0x16;
    pub const TOTAL_SECT32: usize = 0x20;
    pub const FAT_LENGTH32: usize = 0x24;
    pub const ROOT_CLUSTER: usize = 0x2c;
    pub const FSINFO_SECTOR: usize = 0x30;
}

/// Smallest sector a FAT volume may declare, and the largest.
pub const MIN_SECTOR_SIZE: u32 = 512;
pub const MAX_SECTOR_SIZE: u32 = 4096;

/// One directory entry, in bytes. The root directory's size is declared as a
/// count of these, so it converts to sectors through this.
pub const DIR_ENTRY_BYTES: u32 = 32;

/// Why a boot sector is not a FAT volume.
///
/// Distinguished rather than collapsed into one refusal: a caller probing a
/// medium wants to know whether it found a damaged FAT volume or something
/// that was never one.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum BpbError {
    /// The sector handed in is shorter than the block it must contain.
    Short,
    /// Zero reserved sectors — the boot sector itself is reserved, so this
    /// cannot be true of any volume.
    NoReservedSectors,
    /// Zero file-allocation tables.
    NoFats,
    /// A media descriptor no FAT volume uses.
    BadMedia,
    /// A sector size that is not a power of two within the supported range.
    BadSectorSize,
    /// A cluster that is not a power-of-two count of sectors.
    BadClusterSize,
    /// Neither table length is set, so the volume declares no table at all.
    NoFatLength,
}

impl BpbError {
    /// The errno a mount reports. Every malformed-volume case is `EINVAL`;
    /// they are distinguished for diagnosis, not for the caller. # C: O(1)
    pub fn errno(self) -> Errno { Errno::Einval }
}

/// The fields of a boot sector this filesystem reads.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Bpb {
    pub sector_size: u32,
    pub sec_per_clus: u32,
    pub reserved: u32,
    pub fats: u32,
    pub dir_entries: u32,
    pub media: u8,
    /// Table length in sectors from the 16-bit field; zero on FAT32.
    pub fat_length16: u32,
    /// Table length in sectors from the 32-bit field; zero on FAT12/16.
    pub fat_length32: u32,
    /// Total sectors from the 16-bit field; zero when the volume is large.
    pub total_sect16: u32,
    pub total_sect32: u32,
    /// First cluster of the root directory. FAT32 only; FAT12/16 hold the
    /// root at a fixed place instead.
    pub root_cluster: u32,
    pub fsinfo_sector: u32,
}

fn le16(b: &[u8], at: usize) -> u32 { u16::from_le_bytes([b[at], b[at + 1]]) as u32 }
fn le32(b: &[u8], at: usize) -> u32 { u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) }

/// Media descriptors a FAT volume may carry. # C: O(1)
pub fn valid_media(media: u8) -> bool { media >= 0xf8 || media == 0xf0 }

/// Read and validate a boot sector.
///
/// Refusal order, and it is the contract: reserved sectors, table count, media
/// descriptor, sector size, cluster size, table length.
/// # C: O(1)
pub fn parse(sector: &[u8]) -> Result<Bpb, BpbError> {
    if sector.len() < off::FSINFO_SECTOR + 2 { return Err(BpbError::Short); }
    let bpb = Bpb {
        sector_size: le16(sector, off::SECTOR_SIZE),
        sec_per_clus: sector[off::SEC_PER_CLUS] as u32,
        reserved: le16(sector, off::RESERVED),
        fats: sector[off::FATS] as u32,
        dir_entries: le16(sector, off::DIR_ENTRIES),
        media: sector[off::MEDIA],
        fat_length16: le16(sector, off::FAT_LENGTH16),
        fat_length32: le32(sector, off::FAT_LENGTH32),
        total_sect16: le16(sector, off::TOTAL_SECT16),
        total_sect32: le32(sector, off::TOTAL_SECT32),
        root_cluster: le32(sector, off::ROOT_CLUSTER),
        fsinfo_sector: le16(sector, off::FSINFO_SECTOR),
    };
    if bpb.reserved == 0 { return Err(BpbError::NoReservedSectors); }
    if bpb.fats == 0 { return Err(BpbError::NoFats); }
    if !valid_media(bpb.media) { return Err(BpbError::BadMedia); }
    if !bpb.sector_size.is_power_of_two()
        || bpb.sector_size < MIN_SECTOR_SIZE || bpb.sector_size > MAX_SECTOR_SIZE {
        return Err(BpbError::BadSectorSize);
    }
    if !bpb.sec_per_clus.is_power_of_two() { return Err(BpbError::BadClusterSize); }
    if bpb.fat_length16 == 0 && bpb.fat_length32 == 0 { return Err(BpbError::NoFatLength); }
    Ok(bpb)
}

impl Bpb {
    /// Table length in sectors, from whichever field carries it. # C: O(1)
    pub fn fat_length(&self) -> u32 {
        if self.fat_length16 != 0 { self.fat_length16 } else { self.fat_length32 }
    }

    /// Total sectors, from whichever field carries it. The 16-bit field is
    /// zero on a volume too large to express there. # C: O(1)
    pub fn total_sectors(&self) -> u32 {
        if self.total_sect16 != 0 { self.total_sect16 } else { self.total_sect32 }
    }

    /// Whether the 32-bit table-length field is the one in use, which is what
    /// declares a volume FAT32 before any cluster has been counted. # C: O(1)
    pub fn declares_fat32(&self) -> bool { self.fat_length16 == 0 && self.fat_length32 != 0 }

    /// Directory entries per sector. # C: O(1)
    pub fn dir_per_sector(&self) -> u32 { self.sector_size / DIR_ENTRY_BYTES }
}

#[cfg(test)]
#[path = "bpb/tests.rs"]
mod tests;
