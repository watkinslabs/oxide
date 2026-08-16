//! The superblock: the fields, and whether they agree with one another.
//!
//! Two copies exist and either may be the good one, so nothing here reads a
//! medium — a copy is a byte slice, and the caller tries the second when the
//! first does not validate. That is the reference's own order and it is what
//! keeps a volume with one damaged copy mountable.
//!
//! Module manifest:
//! - `parse`:  the fields, read out of one copy's bytes.
//! - `sanity`: whether those fields can describe a real volume.

use alloc::string::String;
use alloc::vec::Vec;

pub mod parse;
pub mod sanity;

pub use parse::parse;
pub use sanity::{check, SbError};

/// One superblock copy, resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SuperBlock {
    pub major_ver: u16,
    pub minor_ver: u16,
    pub log_sectorsize: u32,
    pub log_sectors_per_block: u32,
    pub log_blocksize: u32,
    pub log_blocks_per_seg: u32,
    pub segs_per_sec: u32,
    pub secs_per_zone: u32,
    pub checksum_offset: u32,
    pub block_count: u64,
    pub section_count: u32,
    pub segment_count: u32,
    pub segment_count_ckpt: u32,
    pub segment_count_sit: u32,
    pub segment_count_nat: u32,
    pub segment_count_ssa: u32,
    pub segment_count_main: u32,
    pub segment0_blkaddr: u32,
    pub cp_blkaddr: u32,
    pub sit_blkaddr: u32,
    pub nat_blkaddr: u32,
    pub ssa_blkaddr: u32,
    pub main_blkaddr: u32,
    pub root_ino: u32,
    pub node_ino: u32,
    pub meta_ino: u32,
    pub uuid: [u8; crate::uapi::SB_UUID_LEN],
    pub volume_name: String,
    pub extension_count: u32,
    /// The extensions that decide which log a new file's data goes to. Read
    /// because the write path places by them; carried on a read-only mount so
    /// `show_options` and a later remount see the same volume.
    pub extensions: Vec<String>,
    pub hot_ext_count: u8,
    pub cp_payload: u32,
    pub feature: u32,
    pub s_encoding: u16,
    pub s_encoding_flags: u16,
    /// Segments each listed device contributes, empty when the volume is one
    /// device.
    pub device_segments: Vec<u32>,
    pub qf_ino: [u32; crate::uapi::MAX_QUOTAS],
    /// The stored CRC, whether or not the volume claims to maintain one.
    pub crc: u32,
}

impl SuperBlock {
    /// Blocks one segment holds. # C: O(1)
    pub fn blks_per_seg(&self) -> u32 { 1u32 << self.log_blocks_per_seg }

    /// One past the last block address the volume covers. # C: O(1)
    pub fn max_blkaddr(&self) -> u64 {
        u64::from(self.segment0_blkaddr)
            + (u64::from(self.segment_count) << self.log_blocks_per_seg)
    }

    /// Whether `addr` names a block in the main area — the only place file
    /// and node data may live. Every address read out of an inode, a direct
    /// node or a NAT entry goes through here before it is used.
    /// # C: O(1)
    pub fn valid_main_blkaddr(&self, addr: u32) -> bool {
        let end = u64::from(self.main_blkaddr)
            + (u64::from(self.segment_count_main) << self.log_blocks_per_seg);
        u64::from(addr) >= u64::from(self.main_blkaddr) && u64::from(addr) < end
    }

    /// Which segment of the main area `addr` falls in. # C: O(1)
    pub fn segno_of(&self, addr: u32) -> Option<u32> {
        if !self.valid_main_blkaddr(addr) { return None; }
        Some((addr - self.main_blkaddr) >> self.log_blocks_per_seg)
    }

    /// Whether the volume lists more than the device it was mounted from.
    /// # C: O(1)
    pub fn multi_device(&self) -> bool { self.device_segments.len() > 1 }
}
