//! The sites a failure can be injected at.
//!
//! The ORDER is an ABI, not an implementation detail: `fault_type=` is a
//! bitmask a test writes by hand, one bit per site at the site's index here.
//! Inserting a site in the middle silently re-aims every existing test at a
//! different failure, so new sites go on the end — including the two that are
//! obsolete, whose bits stay reserved rather than being reused.

/// One place a failure can be injected.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Fault {
    Kmalloc = 0,
    Kvmalloc,
    PageAlloc,
    PageGet,
    /// Reserved: the allocation this named cannot fail any more.
    AllocBio,
    AllocNid,
    Orphan,
    Block,
    DirDepth,
    EvictInode,
    Truncate,
    ReadIo,
    Checkpoint,
    /// Reserved: the request this named cannot fail any more.
    Discard,
    WriteIo,
    SlabAlloc,
    DquotInit,
    LockOp,
    BlkaddrValidity,
    BlkaddrConsistence,
    NoSegment,
    InconsistentFooter,
    AtomicTimeout,
    Vmalloc,
    LockTimeout,
    SkipWrite,
}

/// How many sites there are; the bitmask is this wide.
pub const FAULT_MAX: u32 = Fault::SkipWrite as u32 + 1;

/// Every site a bitmask may name, so a caller can ask for all of them.
pub const ALL_TYPES: u32 = (1u32 << FAULT_MAX) - 1;

impl Fault {
    /// The bit this site occupies in a `fault_type=` mask. # C: O(1)
    pub fn bit(self) -> u32 { 1u32 << (self as u32) }

    /// What a report names this site. # C: O(1)
    pub fn name(self) -> &'static str {
        match self {
            Fault::Kmalloc => "kmalloc",
            Fault::Kvmalloc => "kvmalloc",
            Fault::PageAlloc => "page alloc",
            Fault::PageGet => "page get",
            Fault::AllocBio => "alloc bio(obsolete)",
            Fault::AllocNid => "alloc nid",
            Fault::Orphan => "orphan",
            Fault::Block => "no more block",
            Fault::DirDepth => "too big dir depth",
            Fault::EvictInode => "evict_inode fail",
            Fault::Truncate => "truncate fail",
            Fault::ReadIo => "read IO error",
            Fault::Checkpoint => "checkpoint error",
            Fault::Discard => "discard error",
            Fault::WriteIo => "write IO error",
            Fault::SlabAlloc => "slab alloc",
            Fault::DquotInit => "dquot initialize",
            Fault::LockOp => "lock_op",
            Fault::BlkaddrValidity => "invalid blkaddr",
            Fault::BlkaddrConsistence => "inconsistent blkaddr",
            Fault::NoSegment => "no free segment",
            Fault::InconsistentFooter => "inconsistent footer",
            Fault::AtomicTimeout => "atomic timeout",
            Fault::Vmalloc => "vmalloc",
            Fault::LockTimeout => "lock timeout",
            Fault::SkipWrite => "skip write",
        }
    }

    /// The site at `index`, or `None` past the end. # C: O(1)
    pub fn from_index(index: u32) -> Option<Fault> {
        const SITES: [Fault; FAULT_MAX as usize] = [
            Fault::Kmalloc, Fault::Kvmalloc, Fault::PageAlloc, Fault::PageGet,
            Fault::AllocBio, Fault::AllocNid, Fault::Orphan, Fault::Block,
            Fault::DirDepth, Fault::EvictInode, Fault::Truncate, Fault::ReadIo,
            Fault::Checkpoint, Fault::Discard, Fault::WriteIo, Fault::SlabAlloc,
            Fault::DquotInit, Fault::LockOp, Fault::BlkaddrValidity,
            Fault::BlkaddrConsistence, Fault::NoSegment, Fault::InconsistentFooter,
            Fault::AtomicTimeout, Fault::Vmalloc, Fault::LockTimeout, Fault::SkipWrite,
        ];
        SITES.get(index as usize).copied()
    }
}

/// How a lock that was asked to time out does so.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Timeout {
    None = 0,
    /// Spin without yielding.
    Running,
    /// Sleep as a waiting reader or writer of the medium does.
    IoSleep,
    /// Sleep as a waiter on something other than the medium does.
    NonIoSleep,
    /// Yield in a loop, so the task stays runnable throughout.
    Runnable,
}

/// One past the last timeout kind.
pub const TIMEOUT_MAX: u32 = Timeout::Runnable as u32 + 1;

impl Timeout {
    /// The kind at `index`, or `None` past the end. # C: O(1)
    pub fn from_index(index: u32) -> Option<Timeout> {
        match index {
            0 => Some(Timeout::None),
            1 => Some(Timeout::Running),
            2 => Some(Timeout::IoSleep),
            3 => Some(Timeout::NonIoSleep),
            4 => Some(Timeout::Runnable),
            _ => None,
        }
    }
}
