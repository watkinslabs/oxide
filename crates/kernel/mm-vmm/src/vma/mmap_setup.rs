//! Pre-publication file-mmap callback context.

use hal::UserVirtAddr;

/// Final VMA geometry supplied to a file-backed mapping before publication.
/// # C: O(1)
pub struct FileMmapSetup { start: UserVirtAddr, end: UserVirtAddr, pgoff: u64 }

impl FileMmapSetup {
    pub(crate) fn new(start: UserVirtAddr, end: UserVirtAddr, pgoff: u64) -> Self {
        Self { start, end, pgoff }
    }

    /// Start of the VMA selected by the canonical address-space owner. # C: O(1)
    pub fn start(&self) -> UserVirtAddr { self.start }

    /// Exclusive VMA end selected by the canonical address-space owner. # C: O(1)
    pub fn end(&self) -> UserVirtAddr { self.end }

    /// Page offset into the mapped file object. # C: O(1)
    pub fn pgoff(&self) -> u64 { self.pgoff }
}
