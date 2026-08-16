//! The member spans, and which member holds a given block address.

use alloc::string::String;
use alloc::vec::Vec;

use crate::sb::SuperBlock;

/// One member as the SUPERBLOCK names it: where to find it, and how many
/// segments of the volume's address space it contributes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevSpec {
    pub path: String,
    pub total_segments: u32,
}

/// One member as the MOUNT uses it: the span of global block addresses that
/// land on it, both ends inclusive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevInfo {
    pub path: String,
    pub total_segments: u32,
    pub start_blk: u32,
    pub end_blk: u32,
}

impl DevInfo {
    /// Whether `addr` lands on this member. # C: O(1)
    pub fn holds(&self, addr: u32) -> bool { addr >= self.start_blk && addr <= self.end_blk }
}

/// Every member, in the order the superblock lists them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevTable {
    devs: Vec<DevInfo>,
}

impl DevTable {
    /// Build the table from a superblock.
    ///
    /// A volume that names no device is still one member: giving it an entry
    /// rather than a special case is what keeps every caller — routing,
    /// discard, flush, the layout report — on one code path, and it is the
    /// shape the reference keeps for a single zoned device too.
    ///
    /// The first member's span is extended by `segment0_blkaddr` because the
    /// segment counts describe segments, and the blocks before segment zero
    /// belong to that member as well.
    /// # C: O(devices)
    pub fn scan(sb: &SuperBlock) -> Self {
        let per_seg = u64::from(sb.blks_per_seg());
        if sb.devices.is_empty() {
            let end = sb.max_blkaddr().saturating_sub(1);
            return Self { devs: alloc::vec![DevInfo {
                path: String::new(),
                total_segments: sb.segment_count_main,
                start_blk: 0,
                end_blk: u32::try_from(end).unwrap_or(u32::MAX),
            }] };
        }
        let mut devs = Vec::with_capacity(sb.devices.len());
        let mut next = 0u64;
        for (i, spec) in sb.devices.iter().enumerate() {
            let start = next;
            let mut end = start + u64::from(spec.total_segments) * per_seg;
            if i == 0 { end += u64::from(sb.segment0_blkaddr); }
            let end = end.saturating_sub(1);
            devs.push(DevInfo {
                path: spec.path.clone(),
                total_segments: spec.total_segments,
                start_blk: u32::try_from(start).unwrap_or(u32::MAX),
                end_blk: u32::try_from(end).unwrap_or(u32::MAX),
            });
            next = end + 1;
        }
        Self { devs }
    }

    /// A table for members already resolved. # C: O(1)
    pub fn from_parts(devs: Vec<DevInfo>) -> Self { Self { devs } }

    /// # C: O(1)
    pub fn devs(&self) -> &[DevInfo] { &self.devs }

    /// # C: O(1)
    pub fn len(&self) -> usize { self.devs.len() }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.devs.is_empty() }

    /// Whether the volume spans more than one member. Every rule the
    /// reference gates on "is this multi-device" gates on exactly this.
    /// # C: O(1)
    pub fn is_multi(&self) -> bool { self.devs.len() > 1 }

    /// # C: O(1)
    pub fn get(&self, i: usize) -> Option<&DevInfo> { self.devs.get(i) }

    /// Which member holds `addr`, and what the address is ON that member.
    ///
    /// A single-member volume answers without consulting a span at all, and
    /// an address no member claims answers member zero UNSHIFTED — both are
    /// the reference's own answers, and the second matters: shifting an
    /// out-of-range address would turn a read that fails into a read of the
    /// wrong block.
    /// # C: O(devices)
    pub fn target(&self, addr: u32) -> (usize, u32) {
        if !self.is_multi() { return (0, addr); }
        for (i, d) in self.devs.iter().enumerate() {
            if d.holds(addr) { return (i, addr - d.start_blk); }
        }
        (0, addr)
    }
}
