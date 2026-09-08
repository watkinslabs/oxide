/// Authoritative placement mode for one VMA insertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmapPlacement {
    Advisory(Option<hal::UserVirtAddr>),
    /// Advisory placement that must start on a granule the CALLER requires,
    /// coarser than a page. A personality whose own interfaces recover a
    /// region's base by rounding an interior address down to that granule
    /// cannot be given a finer placement: the rounded address would name
    /// memory the allocation never covered.
    AdvisoryAligned { hint: Option<hal::UserVirtAddr>, align: u64 },
    Fixed(hal::UserVirtAddr),
    FixedNoReplace(hal::UserVirtAddr),
}

/// mmap-specific result needed by the syscall ABI without polluting every VMM
/// operation with an `EEXIST`-only error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmapError {
    Vmm(crate::Error),
    Exists,
}

impl From<crate::Error> for MmapError {
    fn from(error: crate::Error) -> Self { Self::Vmm(error) }
}
