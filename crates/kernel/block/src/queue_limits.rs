// Canonical block-queue topology limits per Linux `struct queue_limits`.
//
// Transfer-count and scatter-gather limits deliberately do not live here yet:
// `BlockRequest` is one contiguous Vec and the current `BlockDevice` contract
// has no generic submission gate that can enforce such values. Publishing a
// value before that gate exists would make sysfs lie to callers.

use crate::types::{BlockError, KResult};

/// Linux's fundamental sector unit. Queue block sizes are integral sectors.
pub const LINUX_SECTOR_BYTES: u32 = 512;
/// Linux's largest representable discard request in 512-byte sectors.
pub const MAX_DISCARD_SECTORS: u32 = u32::MAX;

bitflags::bitflags! {
    /// Immutable queue facts corresponding to Linux `BLK_FEAT_*` bits.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct QueueFeatures: u8 {
        const STABLE_WRITES = 1 << 0;
        const SYNCHRONOUS   = 1 << 1;
    }
}

/// Immutable topology portion of Linux `queue_limits`.
///
/// `logical_block_size` is the request-addressing unit. `physical_block_size`
/// and `io_min` are nonzero multiples of it; `io_opt == 0` means no preferred
/// transfer size. The values are device facts, not sysfs formatting state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct QueueLimits {
    logical_block_size:  u32,
    physical_block_size: u32,
    io_min:              u32,
    io_opt:              u32,
    max_write_zeroes_sectors: u32,
    max_write_zeroes_unmap_sectors: u32,
    max_hw_discard_sectors: u32,
    max_discard_sectors: u32,
    discard_granularity: u32,
    features: QueueFeatures,
}

impl QueueLimits {
    /// Construct validated queue topology. # C: O(1)
    pub const fn new(logical_block_size: u32, physical_block_size: u32,
        io_min: u32, io_opt: u32) -> KResult<Self> {
        if !valid_block_size(logical_block_size)
            || !multiple_of(physical_block_size, logical_block_size)
            || !multiple_of(io_min, physical_block_size)
            || (io_opt != 0 && !multiple_of(io_opt, physical_block_size)) {
            return Err(BlockError::Einval);
        }
        Ok(Self {
            logical_block_size, physical_block_size, io_min, io_opt,
            max_write_zeroes_sectors: 0, max_write_zeroes_unmap_sectors: 0,
            max_hw_discard_sectors: 0, max_discard_sectors: 0,
            discard_granularity: 0, features: QueueFeatures::empty(),
        })
    }

    /// Conservative topology for a device that only reports its logical
    /// addressing unit. There is no advertised preferred I/O size.
    /// # C: O(1)
    pub const fn for_logical_block_size(logical_block_size: u32) -> KResult<Self> {
        Self::new(logical_block_size, logical_block_size, logical_block_size, 0)
    }

    /// Logical request-addressing size in bytes. # C: O(1)
    pub const fn logical_block_size(self) -> u32 { self.logical_block_size }
    /// Physical media/allocation unit in bytes. # C: O(1)
    pub const fn physical_block_size(self) -> u32 { self.physical_block_size }
    /// Minimum efficient I/O size in bytes. # C: O(1)
    pub const fn io_min(self) -> u32 { self.io_min }
    /// Preferred I/O size in bytes; zero means unspecified. # C: O(1)
    pub const fn io_opt(self) -> u32 { self.io_opt }

    /// Add native `WRITE_ZEROES` limits expressed in Linux 512-byte sectors.
    /// A zero maximum means the generic layer must use ordinary zero writes.
    /// The unmap-capable maximum cannot exceed the operation's total maximum.
    /// # C: O(1)
    pub const fn with_write_zeroes(mut self, max_sectors: u32,
        max_unmap_sectors: u32) -> KResult<Self> {
        if max_unmap_sectors > max_sectors { return Err(BlockError::Einval); }
        self.max_write_zeroes_sectors = max_sectors;
        self.max_write_zeroes_unmap_sectors = max_unmap_sectors;
        Ok(self)
    }

    /// Native `WRITE_ZEROES` maximum in 512-byte sectors. # C: O(1)
    pub const fn max_write_zeroes_sectors(self) -> u32 { self.max_write_zeroes_sectors }
    /// Native `WRITE_ZEROES` maximum that may deallocate in 512-byte sectors.
    /// # C: O(1)
    pub const fn max_write_zeroes_unmap_sectors(self) -> u32 { self.max_write_zeroes_unmap_sectors }

    /// Add a Linux discard capability. Maxima are 512-byte sectors; the
    /// granularity is bytes and must be one valid physical I/O unit.
    /// # C: O(1)
    pub const fn with_discard(mut self, max_hw_sectors: u32, max_sectors: u32,
        granularity: u32) -> KResult<Self> {
        if max_sectors > max_hw_sectors
            || (max_sectors != 0 && (!multiple_of(granularity, self.physical_block_size))) {
            return Err(BlockError::Einval);
        }
        self.max_hw_discard_sectors = max_hw_sectors;
        self.max_discard_sectors = max_sectors;
        self.discard_granularity = if max_sectors == 0 { 0 } else { granularity };
        Ok(self)
    }

    /// Add immutable Linux queue feature facts. # C: O(1)
    pub const fn with_features(mut self, features: QueueFeatures) -> Self {
        self.features = features;
        self
    }

    /// Hardware discard maximum in Linux 512-byte sectors. # C: O(1)
    pub const fn max_hw_discard_sectors(self) -> u32 { self.max_hw_discard_sectors }
    /// Effective discard maximum in Linux 512-byte sectors. # C: O(1)
    pub const fn max_discard_sectors(self) -> u32 { self.max_discard_sectors }
    /// Discard alignment unit in bytes; zero means discard unsupported. # C: O(1)
    pub const fn discard_granularity(self) -> u32 { self.discard_granularity }
    /// Immutable queue features. # C: O(1)
    pub const fn features(self) -> QueueFeatures { self.features }

    /// Render one supported Linux `/sys/block/<dev>/queue` numeric leaf.
    /// # C: O(1)
    pub fn sysfs_value(self, name: &str) -> Option<u64> {
        match name {
            "logical_block_size" => Some(self.logical_block_size.into()),
            "physical_block_size" => Some(self.physical_block_size.into()),
            "minimum_io_size" => Some(self.io_min.into()),
            "optimal_io_size" => Some(self.io_opt.into()),
            "max_write_zeroes_sectors" => Some(self.max_write_zeroes_sectors.into()),
            "max_write_zeroes_unmap_sectors" => Some(self.max_write_zeroes_unmap_sectors.into()),
            "discard_max_hw_bytes" => Some((self.max_hw_discard_sectors as u64) * LINUX_SECTOR_BYTES as u64),
            "discard_max_bytes" => Some((self.max_discard_sectors as u64) * LINUX_SECTOR_BYTES as u64),
            "discard_granularity" => Some(self.discard_granularity.into()),
            "stable_writes" => Some(self.features.contains(QueueFeatures::STABLE_WRITES) as u64),
            _ => None,
        }
    }
}

const fn valid_block_size(bytes: u32) -> bool {
    bytes >= LINUX_SECTOR_BYTES && bytes.is_power_of_two()
        && bytes % LINUX_SECTOR_BYTES == 0
}

const fn multiple_of(value: u32, unit: u32) -> bool {
    value >= unit && value % unit == 0
}
