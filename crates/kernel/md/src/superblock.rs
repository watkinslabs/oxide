//! MD v1 member-metadata loading and validation.

extern crate alloc;

use alloc::vec::Vec;
use block::{BlockDevice, BlockError, BlockRequest, KResult};

const SECTOR_BYTES: u64 = 512;
const SUPERBLOCK_BYTES: usize = 4096;
const SUPERBLOCK_SECTORS: u64 = SUPERBLOCK_BYTES as u64 / SECTOR_BYTES;
const MAGIC: u32 = 0xa92b_4efc;
const VERSION: u32 = 1;
const HEADER_BYTES: usize = 256;
const MAX_DEVICES: usize = (SUPERBLOCK_BYTES - HEADER_BYTES) / 2;
const FEATURES: u32 = 0x1fff;
const ROLE_SPARE: u16 = 0xffff;
const ROLE_FAULTY: u16 = 0xfffe;

/// On-device placement of a version-1 MD superblock. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MetadataVersion { V1_0, V1_1, V1_2 }

/// Validated v1 metadata for one MD member device. # C: O(max_dev)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Superblock {
    uuid: [u8; 16],
    name: [u8; 32],
    level: i32,
    layout: u32,
    component_sectors: u64,
    chunk_sectors: u32,
    raid_disks: u32,
    data_offset: u64,
    data_sectors: u64,
    events: u64,
    dev_number: u32,
    roles: Vec<u16>,
}

impl Superblock {
    /// Array UUID shared by every member of one MD set. # C: O(1)
    pub const fn uuid(&self) -> [u8; 16] { self.uuid }

    /// Fixed-width user-assigned array name, including any NUL suffix. # C: O(1)
    pub const fn name(&self) -> &[u8; 32] { &self.name }

    /// MD level (`-1` linear, `0` RAID0, `1` RAID1). # C: O(1)
    pub const fn level(&self) -> i32 { self.level }

    /// Personality-specific MD layout value. # C: O(1)
    pub const fn layout(&self) -> u32 { self.layout }

    /// Per-component usable size in 512-byte sectors. # C: O(1)
    pub const fn component_sectors(&self) -> u64 { self.component_sectors }

    /// Striping chunk size in 512-byte sectors. # C: O(1)
    pub const fn chunk_sectors(&self) -> u32 { self.chunk_sectors }

    /// Number of active array roles. # C: O(1)
    pub const fn raid_disks(&self) -> u32 { self.raid_disks }

    /// Start of usable member data in 512-byte sectors. # C: O(1)
    pub const fn data_offset(&self) -> u64 { self.data_offset }

    /// Usable member data length in 512-byte sectors. # C: O(1)
    pub const fn data_sectors(&self) -> u64 { self.data_sectors }

    /// Metadata event counter used to select current members. # C: O(1)
    pub const fn events(&self) -> u64 { self.events }

    /// Persistent member descriptor number. # C: O(1)
    pub const fn dev_number(&self) -> u32 { self.dev_number }

    /// Role table indexed by persistent member number. # C: O(1)
    pub fn roles(&self) -> &[u16] { &self.roles }

    /// Role assigned to this member, if the metadata table contains it. # C: O(1)
    pub fn member_role(&self) -> Option<u16> { self.roles.get(self.dev_number as usize).copied() }

    /// Whether this describes an active array member rather than a spare or
    /// faulty device. # C: O(1)
    pub fn is_active_member(&self) -> bool {
        self.member_role().is_some_and(|role| role != ROLE_SPARE && role != ROLE_FAULTY)
    }

    /// Whether two member records can be assembled into one immutable array.
    /// # C: O(1)
    pub fn same_array(&self, other: &Self) -> bool {
        self.uuid == other.uuid && self.level == other.level && self.layout == other.layout
            && self.component_sectors == other.component_sectors && self.chunk_sectors == other.chunk_sectors
            && self.raid_disks == other.raid_disks
    }
}

/// Read and validate one complete MD v1 superblock from a member. # C: O(4 KiB)
pub fn read_superblock(member: &dyn BlockDevice, version: MetadataVersion) -> KResult<Superblock> {
    let block_size = u64::from(member.block_size());
    if block_size == 0 || SUPERBLOCK_BYTES as u64 % block_size != 0 { return Err(BlockError::Einval); }
    let sectors = member.capacity_blocks().checked_mul(block_size).ok_or(BlockError::Eoverflow)? / SECTOR_BYTES;
    let super_sector = match version {
        MetadataVersion::V1_0 => sectors.checked_sub(SUPERBLOCK_SECTORS * 2).ok_or(BlockError::Einval)? & !(SUPERBLOCK_SECTORS - 1),
        MetadataVersion::V1_1 => 0,
        MetadataVersion::V1_2 => SUPERBLOCK_SECTORS,
    };
    let byte_offset = super_sector.checked_mul(SECTOR_BYTES).ok_or(BlockError::Eoverflow)?;
    if byte_offset % block_size != 0 { return Err(BlockError::Einval); }
    let blocks = (SUPERBLOCK_BYTES as u64 / block_size).try_into().map_err(|_| BlockError::Eoverflow)?;
    let mut request = BlockRequest::new_read(byte_offset / block_size, blocks, member.block_size());
    member.submit_sync(&mut request)?;
    parse(&request.buffer, super_sector)
}

fn parse(bytes: &[u8], super_sector: u64) -> KResult<Superblock> {
    if bytes.len() != SUPERBLOCK_BYTES || le32(bytes, 0)? != MAGIC || le32(bytes, 4)? != VERSION { return Err(BlockError::Einval); }
    let max_dev: usize = le32(bytes, 220)?.try_into().map_err(|_| BlockError::Eoverflow)?;
    let used = HEADER_BYTES.checked_add(max_dev.checked_mul(2).ok_or(BlockError::Eoverflow)?).ok_or(BlockError::Eoverflow)?;
    if max_dev > MAX_DEVICES || le64(bytes, 144)? != super_sector || le32(bytes, 8)? & !FEATURES != 0
        || le64(bytes, 136)? < 10 || bytes[12..16] != [0; 4] || bytes[228..256].iter().any(|byte| *byte != 0)
        || checksum(bytes, used)? != le32(bytes, 216)? { return Err(BlockError::Einval); }
    let mut uuid = [0u8; 16]; uuid.copy_from_slice(&bytes[16..32]);
    let mut name = [0u8; 32]; name.copy_from_slice(&bytes[32..64]);
    let roles = (0..max_dev).map(|index| le16(bytes, HEADER_BYTES + index * 2)).collect::<KResult<Vec<_>>>()?;
    let dev_number = le32(bytes, 160)?;
    if dev_number as usize >= max_dev { return Err(BlockError::Einval); }
    Ok(Superblock { uuid, name, level: le32(bytes, 72)? as i32, layout: le32(bytes, 76)?,
        component_sectors: le64(bytes, 80)?, chunk_sectors: le32(bytes, 88)?, raid_disks: le32(bytes, 92)?,
        data_offset: le64(bytes, 128)?, data_sectors: le64(bytes, 136)?, events: le64(bytes, 200)?, dev_number, roles })
}

/// Calculate the version-1 metadata checksum with its stored field zeroed. # C: O(metadata bytes)
pub(crate) fn checksum(bytes: &[u8], len: usize) -> KResult<u32> {
    if len > bytes.len() || len < HEADER_BYTES || len % 2 != 0 { return Err(BlockError::Einval); }
    let mut sum = 0u64;
    for offset in (0..len).step_by(4) {
        let word = if offset == 216 { 0 } else if offset + 4 <= len { le32(bytes, offset)? } else { u32::from(le16(bytes, offset)?) };
        sum = sum.wrapping_add(u64::from(word));
    }
    Ok((sum as u32).wrapping_add((sum >> 32) as u32))
}

fn le16(bytes: &[u8], offset: usize) -> KResult<u16> {
    Ok(u16::from_le_bytes(bytes.get(offset..offset + 2).ok_or(BlockError::Einval)?.try_into().map_err(|_| BlockError::Einval)?))
}

fn le32(bytes: &[u8], offset: usize) -> KResult<u32> {
    Ok(u32::from_le_bytes(bytes.get(offset..offset + 4).ok_or(BlockError::Einval)?.try_into().map_err(|_| BlockError::Einval)?))
}

fn le64(bytes: &[u8], offset: usize) -> KResult<u64> {
    Ok(u64::from_le_bytes(bytes.get(offset..offset + 8).ok_or(BlockError::Einval)?.try_into().map_err(|_| BlockError::Einval)?))
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::sync::Arc;
    use block::{BlockDevice, BlockRequest};
    use sync::TaskList;

    use super::*;

    fn put32(bytes: &mut [u8], offset: usize, value: u32) { bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) { bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }

    fn image() -> [u8; SUPERBLOCK_BYTES] {
        let mut bytes = [0u8; SUPERBLOCK_BYTES];
        put32(&mut bytes, 0, MAGIC); put32(&mut bytes, 4, VERSION);
        bytes[16..32].copy_from_slice(b"md-v1-fixture-01");
        bytes[32..40].copy_from_slice(b"test:md0");
        put32(&mut bytes, 72, (-1i32) as u32); put64(&mut bytes, 80, 120); put32(&mut bytes, 92, 2);
        put64(&mut bytes, 128, 16); put64(&mut bytes, 136, 120); put64(&mut bytes, 144, 8);
        put32(&mut bytes, 160, 1); put64(&mut bytes, 200, 9); put32(&mut bytes, 220, 2);
        bytes[256..258].copy_from_slice(&0u16.to_le_bytes()); bytes[258..260].copy_from_slice(&1u16.to_le_bytes());
        let csum = checksum(&bytes, 260).expect("checksum");
        put32(&mut bytes, 216, csum);
        bytes
    }

    #[test]
    fn v1_2_metadata_is_read_and_validated_before_assembly() {
        let member: Arc<dyn BlockDevice> = block::MemDisk::<TaskList>::new(512, 256);
        let mut write = BlockRequest::new_write(8, 8, image().to_vec());
        member.submit_sync(&mut write).expect("write metadata");
        let found = read_superblock(member.as_ref(), MetadataVersion::V1_2).expect("read metadata");
        assert_eq!(found.level(), -1); assert_eq!(found.data_offset(), 16); assert_eq!(found.events(), 9);
        assert_eq!(found.member_role(), Some(1)); assert!(found.is_active_member());
    }

    #[test]
    fn corrupt_metadata_checksum_is_rejected() {
        let member: Arc<dyn BlockDevice> = block::MemDisk::<TaskList>::new(512, 256);
        let mut bytes = image(); bytes[72] = 0;
        let mut write = BlockRequest::new_write(8, 8, bytes.to_vec());
        member.submit_sync(&mut write).expect("write metadata");
        assert_eq!(read_superblock(member.as_ref(), MetadataVersion::V1_2), Err(BlockError::Einval));
    }
}
