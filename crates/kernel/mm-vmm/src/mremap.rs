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
        if old.as_u64() == 0 || (old.as_u64() & 0xFFF) != 0 || new_size == 0 {
            return Err(Error::Inval);
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
