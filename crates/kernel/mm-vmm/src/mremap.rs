// `mremap` work fn — split out of address_space.rs to keep both files
// under the 1000-line cap (`docs/08§7`). The mremap surface is one
// pub method on `AddressSpace`; defining it here in a fresh `impl`
// block keeps the call site (`AddressSpace::mremap`) unchanged.

#![cfg(target_os = "oxide-kernel")]

use hal::UserVirtAddr;

use crate::address_space::AddressSpace;
use crate::vma::{VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

impl AddressSpace {
    /// `mremap` per `mremap(2)`. Tier-2 work fn per `docs/53§3`.
    /// Returns the new mapping address. Behaviour:
    ///   new_size < old_size  → shrink in place, drop tail
    ///   new_size == old_size → no-op, return old
    ///   new_size > old_size  → copy to a new region (MAYMOVE/FIXED)
    /// # C: O(VMA-tree ops + min(old,new) byte copy)
    pub fn mremap(
        &self,
        old: UserVirtAddr,
        old_size: usize,
        new_size: usize,
        maymove: bool,
        fixed: bool,
        new_addr: Option<UserVirtAddr>,
    ) -> KResult<UserVirtAddr> {
        self.mremap_full(old, old_size, new_size, maymove, fixed, false, new_addr)
    }

    /// `mremap` with MREMAP_DONTUNMAP support. Linux semantics
    /// (mremap(2), since Linux 5.7):
    ///   * MREMAP_DONTUNMAP requires MREMAP_MAYMOVE.
    ///   * new_size must equal old_size (no resize).
    ///   * Source VMA must be anonymous + PRIVATE.
    ///   * After completion the source range remains mapped (the VMA
    ///     stays) but its PTEs are torn down — subsequent reads
    ///     refault as fresh zero pages. The destination range holds
    ///     the original contents.
    /// Implemented as: alloc fresh anon mapping at new_va → byte copy
    /// → evict pages from the old range. Equivalent contract; trades
    /// a memcpy for the rmap-walking page-table-move primitive that
    /// Linux uses.
    /// # C: O(min(old,new))
    #[allow(clippy::too_many_arguments)]
    pub fn mremap_full(
        &self,
        old: UserVirtAddr,
        old_size: usize,
        new_size: usize,
        maymove: bool,
        fixed: bool,
        dontunmap: bool,
        new_addr: Option<UserVirtAddr>,
    ) -> KResult<UserVirtAddr> {
        if old.as_u64() == 0 || (old.as_u64() & 0xFFF) != 0 || new_size == 0 {
            return Err(Error::Inval);
        }
        if dontunmap {
            // DONTUNMAP requires MAYMOVE, forbids resize, and is
            // anon-only (mmap(2): MAP_PRIVATE | MAP_ANONYMOUS).
            if !maymove || new_size != old_size {
                return Err(Error::Inval);
            }
            let src_vma = self.find_vma(old).ok_or(Error::Inval)?;
            if !matches!(src_vma.backing, VmaBacking::Anonymous) {
                return Err(Error::Inval);
            }
            let hint = if fixed { new_addr } else { None };
            let new_va = self.mmap(
                hint,
                new_size,
                VmaProt::READ | VmaProt::WRITE,
                VmaFlags::ANONYMOUS | VmaFlags::PRIVATE,
                VmaBacking::Anonymous,
                fixed,
            )?;
            let dst = new_va.as_u64();
            // SAFETY: caller's AS is active; both ranges live within it. Old pages fault-in on the read, new pages fault-in on the write; size validated by mmap above.
            unsafe {
                for i in 0..old_size {
                    let v = core::ptr::read_volatile((old.as_u64() + i as u64) as *const u8);
                    core::ptr::write_volatile((dst + i as u64) as *mut u8, v);
                }
            }
            // Source VMA stays. PTE eviction so future reads refault
            // as zero is performed by the syscall-layer caller (it
            // sits in the mm-pmm crate where the PT walker lives).
            return Ok(new_va);
        }
        if new_size < old_size {
            let drop_va = old.as_u64() + new_size as u64;
            if let Some(da) = UserVirtAddr::new(drop_va) {
                let _ = self.munmap(da, old_size - new_size);
            }
            return Ok(old);
        }
        if new_size == old_size && !fixed {
            return Ok(old);
        }
        if !maymove && !fixed {
            return Err(Error::NoMem);
        }
        let hint = if fixed { new_addr.or(Some(old)) } else { None };
        let new_va = self.mmap(
            hint,
            new_size,
            VmaProt::READ | VmaProt::WRITE,
            VmaFlags::ANONYMOUS | VmaFlags::PRIVATE,
            VmaBacking::Anonymous,
            fixed,
        )?;
        let copy_len = core::cmp::min(old_size, new_size);
        let dst = new_va.as_u64();
        // SAFETY: both regions live in the caller's AS, validated by mmap/munmap above; CPL=0 reads/writes through the caller's active PT.
        unsafe {
            for i in 0..copy_len {
                let v = core::ptr::read_volatile((old.as_u64() + i as u64) as *const u8);
                core::ptr::write_volatile((dst + i as u64) as *mut u8, v);
            }
        }
        let _ = self.munmap(old, old_size);
        Ok(new_va)
    }
}
