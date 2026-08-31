use hal::UserVirtAddr;
use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};

const PAGE: usize = hal::PAGE_SIZE_BYTES as usize;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtStatus { Success, InvalidParameter, NoMemory, NotMapped }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtAllocation { pub base: UserVirtAddr, pub size: usize, pub protection: VmaProt }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtMemoryInfo { pub base: UserVirtAddr, pub allocation_base: UserVirtAddr, pub size: usize, pub protection: VmaProt, pub may_protection: VmaProt }

/// Translate the Windows page-protection word at the NT boundary. Modifier
/// bits are rejected until their VMA/PTE semantics exist; the eight base
/// protections map directly to the common three-bit VMA contract.
/// # C: O(1)
pub fn windows_protection(raw: u32) -> Result<VmaProt, NtStatus> {
    if raw & !0xff != 0 { return Err(NtStatus::InvalidParameter); }
    match raw {
        0x01 => Ok(VmaProt::empty()),
        0x02 | 0x04 | 0x08 => Ok(VmaProt::READ | VmaProt::WRITE),
        0x10 => Ok(VmaProt::EXEC),
        0x20 => Ok(VmaProt::READ | VmaProt::EXEC),
        0x40 | 0x80 => Ok(VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC),
        _ => Err(NtStatus::InvalidParameter),
    }
}

/// Allocate private anonymous NT memory through the common VMM.
/// # C: O(log N_vmas)
pub fn allocate(as_: &AddressSpace, base: Option<UserVirtAddr>, size: usize, protection: VmaProt) -> Result<NtAllocation, NtStatus> {
    if size == 0 || size % PAGE != 0 { return Err(NtStatus::InvalidParameter); }
    let base = as_.mmap_with_may_at(match base { Some(base) => MmapPlacement::Advisory(Some(base)), None => MmapPlacement::Advisory(None) }, size, protection, protection, VmaFlags::PRIVATE, VmaBacking::Anonymous).map_err(|_| NtStatus::NoMemory)?;
    Ok(NtAllocation { base, size, protection })
}

/// Release one exact NT allocation.
/// # C: O(log N_vmas)
pub fn free(as_: &AddressSpace, allocation: NtAllocation) -> NtStatus {
    if allocation.size == 0 || allocation.size % PAGE != 0 { return NtStatus::InvalidParameter; }
    let Some(vma) = as_.find_vma(allocation.base) else { return NtStatus::NotMapped };
    if vma.start != allocation.base || (vma.end.as_u64() - vma.start.as_u64()) as usize != allocation.size { return NtStatus::InvalidParameter; }
    if as_.munmap(allocation.base, allocation.size).is_ok() { NtStatus::Success } else { NtStatus::NotMapped }
}

/// Change protection and return the previous protection.
/// # C: O(log N_vmas)
pub fn protect(as_: &AddressSpace, base: UserVirtAddr, size: usize, protection: VmaProt) -> Result<VmaProt, NtStatus> {
    if size == 0 || size % PAGE != 0 { return Err(NtStatus::InvalidParameter); }
    if base.as_u64() as usize % PAGE != 0 { return Err(NtStatus::InvalidParameter); }
    let vma = as_.find_vma(base).ok_or(NtStatus::NotMapped)?;
    let end = base.as_u64().checked_add(size as u64).ok_or(NtStatus::InvalidParameter)?;
    if end > vma.end.as_u64() { return Err(NtStatus::InvalidParameter); }
    let old = vma.prot;
    if as_.mprotect(base, size, protection).is_err() { return Err(NtStatus::InvalidParameter); }
    Ok(old)
}

/// Query the VMA containing an address.
/// # C: O(log N_vmas)
pub fn query(as_: &AddressSpace, address: UserVirtAddr) -> Result<NtMemoryInfo, NtStatus> {
    let vma = as_.find_vma(address).ok_or(NtStatus::NotMapped)?;
    Ok(NtMemoryInfo { base: vma.start, allocation_base: vma.start, size: (vma.end.as_u64() - vma.start.as_u64()) as usize, protection: vma.prot, may_protection: vma.may_prot })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_query_protect_and_exact_free_follow_one_vma() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let a = allocate(&as_, Some(UserVirtAddr::new(0x4000_0000).unwrap()), PAGE * 2, VmaProt::READ | VmaProt::WRITE).unwrap();
        let q = query(&as_, UserVirtAddr::new(0x4000_1000).unwrap()).unwrap();
        assert_eq!(q.base, a.base); assert_eq!(q.size, a.size); assert_eq!(q.may_protection, VmaProt::READ | VmaProt::WRITE);
        assert_eq!(protect(&as_, a.base, a.size, VmaProt::READ).unwrap(), VmaProt::READ | VmaProt::WRITE);
        assert_eq!(free(&as_, a), NtStatus::Success); assert_eq!(query(&as_, a.base), Err(NtStatus::NotMapped));
    }

    #[test]
    fn invalid_and_wx_requests_do_not_change_the_address_space() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        assert_eq!(allocate(&as_, None, 0, VmaProt::READ), Err(NtStatus::InvalidParameter));
        let wx = allocate(&as_, None, PAGE, VmaProt::WRITE | VmaProt::EXEC).unwrap();
        assert_eq!(wx.size, PAGE);
        assert_eq!(as_.vma_count(), 1);
    }

    #[test]
    fn free_rejects_partial_extent_without_removing_the_mapping() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let a = allocate(&as_, None, PAGE * 2, VmaProt::READ).unwrap();
        assert_eq!(free(&as_, NtAllocation { size: PAGE, ..a }), NtStatus::InvalidParameter);
        assert_eq!(query(&as_, a.base).unwrap().size, PAGE * 2);
    }

    #[test]
    fn protect_rejects_unaligned_or_cross_vma_ranges() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let a = allocate(&as_, None, PAGE * 2, VmaProt::READ | VmaProt::WRITE).unwrap();
        assert_eq!(protect(&as_, UserVirtAddr::new(a.base.as_u64() + 1).unwrap(), PAGE, VmaProt::READ), Err(NtStatus::InvalidParameter));
        assert_eq!(protect(&as_, a.base, PAGE * 3, VmaProt::READ), Err(NtStatus::InvalidParameter));
        assert_eq!(query(&as_, a.base).unwrap().protection, VmaProt::READ | VmaProt::WRITE);
    }

    #[test]
    fn windows_page_protections_translate_without_accepting_modifiers() {
        assert_eq!(windows_protection(0x01), Ok(VmaProt::empty()));
        assert_eq!(windows_protection(0x20), Ok(VmaProt::READ | VmaProt::EXEC));
        assert_eq!(windows_protection(0x40), Ok(VmaProt::READ | VmaProt::WRITE | VmaProt::EXEC));
        assert_eq!(windows_protection(0x104), Err(NtStatus::InvalidParameter));
    }
}
