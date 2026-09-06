//! One owner for releasing an NT-managed user range: VMA removal, page-table
//! zap, frame release and TLB flush together, the same work the Linux
//! `munmap` syscall does. NT frees (`NtFreeVirtualMemory`, heap extents,
//! section views, TEBs) all land here; a VMA-only removal leaves the old
//! frames mapped, so a re-allocation at the same address reads the previous
//! occupant's bytes instead of zeros and every freed frame leaks.

use hal::UserVirtAddr;
use vmm::AddressSpace;

#[cfg(target_os = "oxide-kernel")]
mod owner {
    use super::*;
    /// # C: O(pages) page-table walk + O(K log N_vmas)
    /// # Ctx: process; # Sleeps: no
    pub fn unmap_range(as_: &AddressSpace, base: UserVirtAddr, size: usize) -> Result<(), ()> {
        pmm::user_as::munmap_in(as_, base, size)
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
mod owner {
    use super::*;
    /// Hosted address spaces carry no page tables; VMA removal is the whole
    /// operation. # C: O(K log N_vmas)
    pub fn unmap_range(as_: &AddressSpace, base: UserVirtAddr, size: usize) -> Result<(), ()> {
        as_.munmap(base, size).map_err(|_| ())
    }
}

pub use owner::unmap_range;
