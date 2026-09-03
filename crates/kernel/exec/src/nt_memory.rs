use hal::UserVirtAddr;
use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};

const PAGE: usize = hal::PAGE_SIZE_BYTES as usize;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtStatus { Success, InvalidParameter, NoMemory, ConflictingAddresses, NotMapped }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtAllocation { pub base: UserVirtAddr, pub size: usize, pub protection: VmaProt }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtMemoryInfo { pub base: UserVirtAddr, pub allocation_base: UserVirtAddr, pub size: usize, pub protection: VmaProt, pub may_protection: VmaProt }

/// Normalize an NT protection request to the page range it covers.
/// # C: O(1)
pub fn normalize_protection_range(base: u64, size: u64) -> Result<(UserVirtAddr, usize), NtStatus> {
    if size == 0 { return Err(NtStatus::InvalidParameter); }
    let page = PAGE as u64;
    let start = base & !(page - 1);
    let end = base.checked_add(size).ok_or(NtStatus::InvalidParameter)?;
    let rounded_end = end.checked_add(page - 1).ok_or(NtStatus::InvalidParameter)? & !(page - 1);
    if rounded_end <= start || rounded_end - start > usize::MAX as u64 {
        return Err(NtStatus::InvalidParameter);
    }
    let start = UserVirtAddr::new(start).ok_or(NtStatus::InvalidParameter)?;
    Ok((start, (rounded_end - start.as_u64()) as usize))
}

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
    let placement = match base {
        Some(base) => MmapPlacement::FixedNoReplace(base),
        None => MmapPlacement::Advisory(None),
    };
    let base = as_.mmap_with_may_at(placement, size, protection, protection, VmaFlags::PRIVATE, VmaBacking::Anonymous)
        .map_err(|error| match error {
            vmm::MmapError::Exists => NtStatus::ConflictingAddresses,
            vmm::MmapError::Vmm(_) => NtStatus::NoMemory,
        })?;
    Ok(NtAllocation { base, size, protection })
}

/// Release one NT allocation extent. Compatible adjacent VMAs can be merged
/// by the common VMM, so use the recorded extent rather than the VMA size.
/// # C: O(log N_vmas)
pub fn free(as_: &AddressSpace, allocation: NtAllocation) -> NtStatus {
    if allocation.size == 0 || allocation.size % PAGE != 0 { return NtStatus::InvalidParameter; }
    let Some(vma) = as_.find_vma(allocation.base) else { return NtStatus::NotMapped };
    let Some(end) = allocation.base.as_u64().checked_add(allocation.size as u64) else { return NtStatus::InvalidParameter; };
    if allocation.base.as_u64() < vma.start.as_u64() || end > vma.end.as_u64() { return NtStatus::InvalidParameter; }
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
    let base = UserVirtAddr::new(address.as_u64() & !(PAGE as u64 - 1)).ok_or(NtStatus::InvalidParameter)?;
    let vma = as_.find_vma(base).ok_or(NtStatus::NotMapped)?;
    Ok(NtMemoryInfo { base, allocation_base: vma.start, size: (vma.end.as_u64() - base.as_u64()) as usize, protection: vma.prot, may_protection: vma.may_prot })
}

/// Describe the free region beginning at an unmapped address.
/// # C: O(N_vmas)
pub fn query_free(as_: &AddressSpace, address: UserVirtAddr) -> Result<NtMemoryInfo, NtStatus> {
    let base = UserVirtAddr::new(address.as_u64() & !(PAGE as u64 - 1)).ok_or(NtStatus::InvalidParameter)?;
    let end = as_.snapshot_vmas().into_iter()
        .filter_map(|vma| (vma.start.as_u64() > base.as_u64()).then_some(vma.start.as_u64()))
        .min().unwrap_or(hal::USER_VA_END);
    if end <= base.as_u64() { return Err(NtStatus::InvalidParameter); }
    Ok(NtMemoryInfo { base, allocation_base: UserVirtAddr::new(0).unwrap(), size: (end - base.as_u64()) as usize, protection: VmaProt::empty(), may_protection: VmaProt::empty() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_query_protect_and_exact_free_follow_one_vma() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let a = allocate(&as_, Some(UserVirtAddr::new(0x4000_0000).unwrap()), PAGE * 2, VmaProt::READ | VmaProt::WRITE).unwrap();
        let q = query(&as_, UserVirtAddr::new(0x4000_1000).unwrap()).unwrap();
        assert_eq!(q.base.as_u64(), 0x4000_1000); assert_eq!(q.size, PAGE); assert_eq!(q.may_protection, VmaProt::READ | VmaProt::WRITE);
        assert_eq!(protect(&as_, a.base, a.size, VmaProt::READ).unwrap(), VmaProt::READ | VmaProt::WRITE);
        assert_eq!(free(&as_, a), NtStatus::Success); assert_eq!(query(&as_, a.base), Err(NtStatus::NotMapped));
    }

    #[test]
    fn requested_address_is_fixed_and_conflicts_are_not_relocated() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let first = allocate(&as_, Some(UserVirtAddr::new(0x4000_0000).unwrap()), PAGE, VmaProt::READ).unwrap();
        assert_eq!(allocate(&as_, Some(first.base), PAGE, VmaProt::READ), Err(NtStatus::ConflictingAddresses));
        assert_eq!(query(&as_, first.base).unwrap().base, first.base);
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
    fn free_can_split_a_merged_extent_without_removing_neighbors() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let a = allocate(&as_, None, PAGE * 2, VmaProt::READ).unwrap();
        assert_eq!(free(&as_, NtAllocation { size: PAGE, ..a }), NtStatus::Success);
        assert_eq!(query(&as_, a.base), Err(NtStatus::NotMapped));
        assert_eq!(query(&as_, UserVirtAddr::new(a.base.as_u64() + PAGE as u64).unwrap()).unwrap().size, PAGE);
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

    #[test]
    fn protection_ranges_round_outward_and_reject_overflow() {
        let (base, size) = normalize_protection_range(0x4000_0001, 0x1).unwrap();
        assert_eq!(base.as_u64(), 0x4000_0000);
        assert_eq!(size, PAGE);
        let (base, size) = normalize_protection_range(0x4000_0fff, 2).unwrap();
        assert_eq!(base.as_u64(), 0x4000_0000);
        assert_eq!(size, PAGE * 2);
        assert_eq!(normalize_protection_range(u64::MAX - 1, 2), Err(NtStatus::InvalidParameter));
    }

    #[test]
    fn free_query_stops_at_the_next_mapping() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let _ = allocate(&as_, Some(UserVirtAddr::new(0x4000_2000).unwrap()), PAGE, VmaProt::READ).unwrap();
        let q = query_free(&as_, UserVirtAddr::new(0x4000_0001).unwrap()).unwrap();
        assert_eq!(q.base.as_u64(), 0x4000_0000);
        assert_eq!(q.size, PAGE * 2);
        assert_eq!(q.allocation_base.as_u64(), 0);
    }
}
