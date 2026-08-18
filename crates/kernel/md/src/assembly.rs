//! Assemble supported immutable MD personalities from v1 member metadata.

extern crate alloc;

use alloc::sync::Arc;
use alloc::string::String;
use alloc::vec::Vec;
use block::{BlockDevice, BlockError, BlockRequest, KResult, QueueLimits};

use crate::{Array, Level, MetadataVersion, Superblock, read_superblock};
use crate::control::{Member as ControlMember, Metadata as ControlMetadata};

struct Member { inner: Arc<dyn BlockDevice>, claim: Option<MemberClaim>, number_dev: Option<block::registry::DevNum> }

struct MemberClaim { disk: String }

impl Drop for MemberClaim {
    fn drop(&mut self) { let _ = block::registry::release(&self.disk); }
}

struct DataMember { inner: Arc<dyn BlockDevice>, start: u64, capacity: u64, _claim: Option<MemberClaim> }

impl DataMember {
    fn new(member: Member, superblock: &Superblock) -> KResult<Arc<Self>> {
        let sectors_per_block = u64::from(member.inner.block_size()) / 512;
        if sectors_per_block == 0 || superblock.data_offset() % sectors_per_block != 0
            || superblock.data_sectors() % sectors_per_block != 0 { return Err(BlockError::Einval); }
        let start = superblock.data_offset() / sectors_per_block;
        let capacity = superblock.data_sectors() / sectors_per_block;
        if start.checked_add(capacity).ok_or(BlockError::Eoverflow)? > member.inner.capacity_blocks() || capacity == 0 {
            return Err(BlockError::Einval);
        }
        Ok(Arc::new(Self { inner: member.inner, start, capacity, _claim: member.claim }))
    }
}

impl BlockDevice for DataMember {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn queue_limits(&self) -> KResult<QueueLimits> { self.inner.queue_limits() }
    fn capacity_blocks(&self) -> u64 { self.capacity }
    fn submit_sync(&self, request: &mut BlockRequest) -> KResult<()> {
        let end = request.start_block.checked_add(u64::from(request.len_blocks)).ok_or(BlockError::Einval)?;
        if end > self.capacity { return Err(BlockError::Eio); }
        let logical = request.start_block;
        request.start_block = self.start.checked_add(logical).ok_or(BlockError::Eoverflow)?;
        let result = self.inner.submit_sync(request);
        request.start_block = logical;
        result
    }
    fn flush(&self) -> KResult<()> { self.inner.flush() }
}

/// Read v1 member metadata and assemble a complete supported MD array. Every
/// supplied member must describe the same current, non-degraded array. # C: O(members × 4 KiB)
pub fn assemble(members: Vec<Arc<dyn BlockDevice>>, version: MetadataVersion) -> KResult<Arc<Array>> {
    assemble_members(members.into_iter().map(|inner| Member { inner, claim: None, number_dev: None }).collect(), version)
}

/// Assemble registered block components while holding each parent disk against
/// removal until the resulting array is unpublished. # C: O(members × 4 KiB)
pub(crate) fn assemble_registered(members: Vec<(String, block::registry::DevNum, Arc<dyn BlockDevice>)>, version: MetadataVersion) -> KResult<Arc<Array>> {
    let mut claimed = Vec::with_capacity(members.len());
    for (disk, number_dev, inner) in members {
        if !block::registry::claim(&disk) { return Err(BlockError::Ebusy); }
        claimed.push(Member { inner, claim: Some(MemberClaim { disk }), number_dev: Some(number_dev) });
    }
    assemble_members(claimed, version)
}

fn assemble_members(members: Vec<Member>, version: MetadataVersion) -> KResult<Arc<Array>> {
    let mut found: Vec<(Superblock, Member)> = members.into_iter()
        .map(|member| read_superblock(member.inner.as_ref(), version).map(|superblock| (superblock, member)))
        .collect::<KResult<_>>()?;
    let Some((reference, _)) = found.iter().max_by_key(|(superblock, _)| superblock.events()) else { return Err(BlockError::Einval); };
    let reference = reference.clone();
    if reference.features() != 0 || found.iter().any(|(superblock, _)| superblock.features() != 0) { return Err(BlockError::Eopnotsupp); }
    if found.iter().any(|(superblock, _)| !reference.same_array(superblock)
        || superblock.events().saturating_add(1) < reference.events()) { return Err(BlockError::Einval); }
    let roles = reference.raid_disks() as usize;
    if roles == 0 || found.len() != roles { return Err(BlockError::Einval); }
    found.sort_unstable_by_key(|(superblock, _)| reference.roles().get(superblock.dev_number() as usize).copied());
    if found.iter().enumerate().any(|(role, (superblock, _))|
        reference.roles().get(superblock.dev_number() as usize).copied() != Some(role as u16)) { return Err(BlockError::Einval); }
    let block_size = found[0].1.inner.block_size();
    if found.iter().any(|(_, member)| member.inner.block_size() != block_size) { return Err(BlockError::Einval); }
    let control_members = found.iter().map(|(superblock, member)| Some(ControlMember {
        number: superblock.dev_number(), number_dev: member.number_dev?, raid_disk: i32::from(superblock.member_role()?),
    })).collect::<Option<Vec<_>>>();
    let data_members = found.into_iter().map(|(superblock, member)| DataMember::new(member, &superblock).map(|member| member as Arc<dyn BlockDevice>))
        .collect::<KResult<Vec<_>>>()?;
    let metadata = control_members.map(|members| ControlMetadata { minor_version: version.minor_version(), ctime: reference.ctime(), utime: reference.utime(),
        level: reference.level(), layout: reference.layout(), chunk_sectors: reference.chunk_sectors(), raid_disks: reference.raid_disks(), members });
    match reference.level() {
        -1 => match metadata { Some(metadata) => Array::from_metadata(Level::Linear, data_members, metadata), None => Array::linear(data_members) },
        0 => {
            let sectors_per_block = block_size / 512;
            if sectors_per_block == 0 || reference.chunk_sectors() == 0 || reference.chunk_sectors() % sectors_per_block != 0 { return Err(BlockError::Einval); }
            if data_members.iter().any(|member| member.capacity_blocks() != data_members[0].capacity_blocks()) { return Err(BlockError::Eopnotsupp); }
            let level = Level::Raid0 { chunk_blocks: reference.chunk_sectors() / sectors_per_block };
            match metadata { Some(metadata) => Array::from_metadata(level, data_members, metadata), None => Array::raid0(data_members, reference.chunk_sectors() / sectors_per_block) }
        }
        1 => match metadata { Some(metadata) => Array::from_metadata(Level::Raid1, data_members, metadata), None => Array::raid1(data_members) },
        _ => Err(BlockError::Eopnotsupp),
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::sync::Arc;
    use block::{BlockDevice, BlockRequest};
    use sync::TaskList;

    use super::*;

    fn put32(bytes: &mut [u8], offset: usize, value: u32) { bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes()); }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) { bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes()); }

    fn metadata(number: u32) -> Vec<u8> {
        let mut bytes = vec![0u8; 4096];
        put32(&mut bytes, 0, 0xa92b_4efc); put32(&mut bytes, 4, 1);
        bytes[16..32].copy_from_slice(b"md-assemble-test"); put32(&mut bytes, 72, (-1i32) as u32);
        put64(&mut bytes, 80, 128); put32(&mut bytes, 92, 2); put64(&mut bytes, 128, 16); put64(&mut bytes, 136, 128);
        put64(&mut bytes, 144, 8); put32(&mut bytes, 160, number); put64(&mut bytes, 200, 3); put32(&mut bytes, 220, 2);
        bytes[256..258].copy_from_slice(&0u16.to_le_bytes()); bytes[258..260].copy_from_slice(&1u16.to_le_bytes());
        let csum = crate::superblock::checksum(&bytes, 260).expect("checksum"); put32(&mut bytes, 216, csum);
        bytes
    }

    #[test]
    fn v1_metadata_assembles_linear_members_at_their_data_offsets() {
        let first: Arc<dyn BlockDevice> = block::MemDisk::<TaskList>::new(512, 256);
        let second: Arc<dyn BlockDevice> = block::MemDisk::<TaskList>::new(512, 256);
        for (member, number) in [(&first, 0), (&second, 1)] {
            let mut write = BlockRequest::new_write(8, 8, metadata(number));
            member.submit_sync(&mut write).expect("metadata");
        }
        let array = assemble(vec![Arc::clone(&first), Arc::clone(&second)], MetadataVersion::V1_2).expect("assemble");
        let mut write = BlockRequest::new_write(128, 1, vec![0x5a; 512]); array.submit_sync(&mut write).expect("array write");
        let mut read = BlockRequest::new_read(16, 1, 512); second.submit_sync(&mut read).expect("member read");
        assert_eq!(read.buffer, vec![0x5a; 512]);
    }
}
