// `mremap` work fn — split out of address_space.rs to keep both files
// under the 1000-line cap (`docs/08§7`). The mremap surface is one
// pub method on `AddressSpace`; defining it here in a fresh `impl`
// block keeps the call site (`AddressSpace::mremap`) unchanged.

use hal::UserVirtAddr;

use crate::address_space::AddressSpace;
use crate::vma::{VmaBacking, VmaFlags, VmaProt};
use crate::{Error, KResult};

fn rebase_backing(backing: &VmaBacking, delta: u64) -> VmaBacking {
    match backing {
        VmaBacking::File { backing, off } =>
            VmaBacking::File { backing: backing.clone(), off: off + delta },
        VmaBacking::KernelBytes { data, off } =>
            VmaBacking::KernelBytes { data: data.clone(), off: off + delta as usize },
        b => b.clone(),
    }
}

impl AddressSpace {
    /// `mremap` per `mremap(2)`. work fn per `docs/53§3`.
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
    ///   * Source VMA must not be VM_DONTEXPAND/VM_PFNMAP.
    ///   * After completion the source range remains mapped (the VMA
    ///     stays) but its PTEs are torn down — subsequent reads
    ///     refault as fresh zero pages. The destination range holds
    ///     the original contents.
    /// Implemented as: install a destination VMA with the source
    /// prot/flags/backing, byte-copy populated writable private data, then
    /// leave source VMA in place for syscall-layer PTE eviction.
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
        if old.as_u64() & (hal::PAGE_SIZE_BYTES - 1) != 0 || new_size == 0 {
            return Err(Error::Inval);
        }
        let old_end = old.as_u64().checked_add(old_size as u64).ok_or(Error::Inval)?;
        let move_or_expand = fixed || dontunmap || new_size > old_size;
        if dontunmap {
            // DONTUNMAP requires MAYMOVE, forbids resize, and is
            // disallowed for VM_DONTEXPAND/VM_PFNMAP mappings. Oxide
            // currently has no such VMA flags, so the source coverage check
            // below is the Linux-relevant gate here.
            if !maymove || new_size != old_size {
                return Err(Error::Inval);
            }
            let src_vma = self.find_vma(old).ok_or(Error::Fault)?;
            if old_size == 0 || old_end > src_vma.end.as_u64() {
                return Err(Error::Fault);
            }
            let delta = old.as_u64() - src_vma.start.as_u64();
            let moved_backing = rebase_backing(&src_vma.backing, delta);
            let hint = new_addr;
            let new_va = self.mmap(
                hint,
                new_size,
                src_vma.prot,
                src_vma.flags,
                moved_backing,
                fixed,
            )?;
            #[cfg(not(test))]
            {
                let dst = new_va.as_u64();
                // SAFETY: caller's AS is active; both ranges live within it. Old pages fault-in on the read, new pages fault-in on the write; size validated by mmap above.
                unsafe {
                    for i in 0..old_size {
                        let v = core::ptr::read_volatile((old.as_u64() + i as u64) as *const u8);
                        core::ptr::write_volatile((dst + i as u64) as *mut u8, v);
                    }
                }
            }
            // Source VMA stays. PTE eviction so future reads refault
            // as zero is performed by the syscall-layer caller (it
            // sits in the mm-pmm crate where the PT walker lives).
            return Ok(new_va);
        }
        let src_vma = self.find_vma(old).ok_or(Error::Fault)?;
        if move_or_expand {
            let covered_old_len = if new_size < old_size { new_size } else { old_size };
            let covered_end = old.as_u64().checked_add(covered_old_len as u64).ok_or(Error::Inval)?;
            if covered_end > src_vma.end.as_u64() {
                return Err(Error::Fault);
            }
            if old_size == 0
                && !src_vma.flags.intersects(VmaFlags::SHARED) {
                return Err(Error::Inval);
            }
        }
        if new_size < old_size && !fixed {
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
        // Linux mremap MOVES the vma: the destination keeps the SOURCE's
        // prot, flags, and backing (file off shifted by the intra-vma
        // delta). Forcing Anonymous|PRIVATE|RW here (the old behavior)
        // dropped file backing (never-faulted moved pages read ZERO instead
        // of file content), dropped EXEC, and broke MAP_SHARED visibility.
        // Linux requires the moved range to lie within one vma — enforce it.
        let delta = old.as_u64() - src_vma.start.as_u64();
        let moved_backing = rebase_backing(&src_vma.backing, delta);
        let hint = if fixed { new_addr.or(Some(old)) } else { None };
        let new_va = self.mmap(
            hint,
            new_size,
            src_vma.prot,
            src_vma.flags,
            moved_backing,
            fixed,
        )?;
        // Migrate DIRTY private data: the dest's own demand-faults refill
        // clean pages from the (preserved) backing, but pages the process
        // already wrote exist only in the source's private frames. Byte-copy
        // through user VAs — only when the mapping is writable (an RO
        // mapping cannot hold private dirty data; writing the dest would
        // fault a read-only PTE at CPL=0).
        if src_vma.prot.contains(VmaProt::WRITE) {
            #[cfg(not(test))]
            {
                let copy_len = core::cmp::min(old_size, new_size);
                let dst = new_va.as_u64();
                // SAFETY: both regions live in the caller's AS, validated by mmap/munmap above; CPL=0 reads/writes through the caller's active PT.
                unsafe {
                    for i in 0..copy_len {
                        let v = core::ptr::read_volatile((old.as_u64() + i as u64) as *const u8);
                        core::ptr::write_volatile((dst + i as u64) as *mut u8, v);
                    }
                }
            }
        }
        let _ = self.munmap(old, old_size);
        Ok(new_va)
    }
}
