/// Authoritative placement mode for one VMA insertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmapPlacement {
    Advisory(Option<hal::UserVirtAddr>),
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
