use hal::UserVirtAddr;
use vmm::{AddressSpace, MmapPlacement, VmaBacking, VmaFlags, VmaProt};

const PAGE: usize = hal::PAGE_SIZE_BYTES as usize;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NtStatus { Success, InvalidParameter, NoMemory, ConflictingAddresses, NotMapped }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtAllocation { pub base: UserVirtAddr, pub size: usize, pub protection: VmaProt, pub reserved: bool }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtMemoryInfo { pub base: UserVirtAddr, pub allocation_base: UserVirtAddr, pub size: usize, pub protection: VmaProt, pub may_protection: VmaProt, pub committed: bool, pub mapped_view: bool }

/// Result of one native NT process-memory transfer. The destination is
/// validated by the syscall boundary before this owner is called; a failed
/// source or destination copy contributes no bytes for its current chunk.
#[cfg(target_os = "oxide-kernel")]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct NtCopyResult { pub copied: usize }

/// Copy between buffers in the current process address space. This is the
/// transfer owner for both read and write; remote address spaces must acquire
/// their own address-space-aware operation before reaching here.
/// # C: O(size / PAGE)
#[cfg(target_os = "oxide-kernel")]
pub fn copy_current_process(read: bool, source: u64, destination: u64, size: usize) -> NtCopyResult {
    let mut copied = 0usize;
    let mut scratch = [0u8; PAGE];
    while copied < size {
        let count = (size - copied).min(PAGE);
        let Some(src) = source.checked_add(copied as u64) else { break };
        let Some(dst) = destination.checked_add(copied as u64) else { break };
        let result = if read {
            if uaccess::copy_from_user(&mut scratch[..count], src).is_err() { break; }
            uaccess::copy_to_user(dst, &scratch[..count])
        } else {
            if uaccess::copy_from_user(&mut scratch[..count], dst).is_err() { break; }
            uaccess::copy_to_user(src, &scratch[..count])
        };
        if result.is_err() { break; }
        copied += count;
    }
    NtCopyResult { copied }
}

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

/// Normalize an NT allocation request to its page-covered range.
/// # C: O(1)
pub fn normalize_allocation_range(base: Option<u64>, size: u64) -> Result<(Option<UserVirtAddr>, usize), NtStatus> {
    if size == 0 { return Err(NtStatus::InvalidParameter); }
    let page = PAGE as u64;
    let start = match base {
        Some(raw) => raw & !(page - 1),
        None => 0,
    };
    let end = match base {
        Some(raw) => raw.checked_add(size),
        None => Some(size),
    }.ok_or(NtStatus::InvalidParameter)?;
    let rounded_end = end.checked_add(page - 1).ok_or(NtStatus::InvalidParameter)? & !(page - 1);
    if rounded_end <= start || rounded_end - start > usize::MAX as u64 {
        return Err(NtStatus::InvalidParameter);
    }
    let start = if base.is_some() {
        Some(UserVirtAddr::new(start).ok_or(NtStatus::InvalidParameter)?)
    } else { None };
    Ok((start, (rounded_end - start.map_or(0, |v| v.as_u64())) as usize))
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

/// Check that a section view does not request access absent from creation
/// protection. # C: O(1)
pub fn section_view_protection(maximum: VmaProt, requested: VmaProt) -> Result<VmaProt, NtStatus> {
    if requested.difference(maximum).is_empty() { Ok(requested) }
    else { Err(NtStatus::InvalidParameter) }
}

/// Allocate private anonymous NT memory through the common VMM.
/// # C: O(log N_vmas)
pub fn allocate(as_: &AddressSpace, base: Option<UserVirtAddr>, size: usize, protection: VmaProt, committed: bool) -> Result<NtAllocation, NtStatus> {
    allocate_with_write_watch(as_, base, size, protection, committed, false)
}

/// Allocate private anonymous NT memory with optional VMM-owned dirty tracking.
/// # C: O(number of pages) when write-watch is enabled
pub fn allocate_with_write_watch(as_: &AddressSpace, base: Option<UserVirtAddr>, size: usize, protection: VmaProt, committed: bool, write_watch: bool) -> Result<NtAllocation, NtStatus> {
    if size == 0 || size % PAGE != 0 { return Err(NtStatus::InvalidParameter); }
    let placement = match base {
        Some(base) => MmapPlacement::FixedNoReplace(base),
        None => MmapPlacement::Advisory(None),
    };
    let flags = (if committed { VmaFlags::PRIVATE } else { VmaFlags::PRIVATE | VmaFlags::NT_RESERVED })
        | if write_watch { VmaFlags::NT_WRITE_WATCH } else { VmaFlags::empty() };
    let actual = if committed { protection } else { VmaProt::empty() };
    let base = as_.mmap_with_may_at(placement, size, actual, protection, flags, VmaBacking::Anonymous)
        .map_err(|error| match error {
            vmm::MmapError::Exists => NtStatus::ConflictingAddresses,
            vmm::MmapError::Vmm(_) => NtStatus::NoMemory,
        })?;
    if write_watch && as_.register_write_watch(base.as_u64(), size).is_err() {
        let _ = as_.munmap(base, size); return Err(NtStatus::InvalidParameter);
    }
    Ok(NtAllocation { base, size, protection: actual, reserved: !committed })
}

/// Allocate a new committed region for a null base, or commit a range inside
/// an existing NT reservation for a supplied base. The distinction belongs to
/// the VM owner because both paths mutate one VMA transaction.
/// # C: O(log N_vmas)
pub fn allocate_or_commit(as_: &AddressSpace, base: Option<UserVirtAddr>, size: usize,
    protection: VmaProt) -> Result<NtAllocation, NtStatus> {
    let Some(base) = base else { return allocate(as_, None, size, protection, true); };
    if size == 0 || size % PAGE != 0 { return Err(NtStatus::InvalidParameter); }
    let vma = as_.find_vma(base).ok_or(NtStatus::NotMapped)?;
    if !vma.flags.contains(VmaFlags::NT_RESERVED) { return Err(NtStatus::InvalidParameter); }
    let end = base.as_u64().checked_add(size as u64).ok_or(NtStatus::InvalidParameter)?;
    if end > vma.end.as_u64() { return Err(NtStatus::InvalidParameter); }
    as_.mprotect(base, size, protection).map_err(|_| NtStatus::InvalidParameter)?;
    as_.update_flags_range(base, size, VmaFlags::empty(), VmaFlags::NT_RESERVED);
    Ok(NtAllocation { base, size, protection, reserved: false })
}

/// Release one NT allocation extent. Compatible adjacent VMAs can be merged
/// by the common VMM, so use the recorded extent rather than the VMA size.
/// # C: O(log N_vmas)
pub fn free(as_: &AddressSpace, allocation: NtAllocation) -> NtStatus {
    if allocation.size == 0 || allocation.size % PAGE != 0 { return NtStatus::InvalidParameter; }
    let Some(vma) = as_.find_vma(allocation.base) else { return NtStatus::NotMapped };
    if allocation.reserved != vma.flags.contains(VmaFlags::NT_RESERVED) { return NtStatus::InvalidParameter; }
    let Some(end) = allocation.base.as_u64().checked_add(allocation.size as u64) else { return NtStatus::InvalidParameter; };
    if allocation.base.as_u64() < vma.start.as_u64() || end > vma.end.as_u64() { return NtStatus::InvalidParameter; }
    let watched = vma.flags.contains(VmaFlags::NT_WRITE_WATCH);
    if as_.munmap(allocation.base, allocation.size).is_ok() {
        if watched { as_.unregister_write_watch(allocation.base.as_u64(), allocation.size); }
        NtStatus::Success
    } else { NtStatus::NotMapped }
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
    Ok(NtMemoryInfo { base, allocation_base: vma.mapping_origin.unwrap_or(vma.start), size: (vma.end.as_u64() - base.as_u64()) as usize, protection: vma.prot, may_protection: vma.may_prot, committed: !vma.flags.contains(VmaFlags::NT_RESERVED), mapped_view: vma.flags.contains(VmaFlags::NT_SECTION_VIEW) })
}

/// Describe the free region beginning at an unmapped address.
/// # C: O(N_vmas)
pub fn query_free(as_: &AddressSpace, address: UserVirtAddr) -> Result<NtMemoryInfo, NtStatus> {
    let base = UserVirtAddr::new(address.as_u64() & !(PAGE as u64 - 1)).ok_or(NtStatus::InvalidParameter)?;
    let end = as_.snapshot_vmas().into_iter()
        .filter_map(|vma| (vma.start.as_u64() > base.as_u64()).then_some(vma.start.as_u64()))
        .min().unwrap_or(hal::USER_VA_END);
    if end <= base.as_u64() { return Err(NtStatus::InvalidParameter); }
    Ok(NtMemoryInfo { base, allocation_base: UserVirtAddr::new(0).unwrap(), size: (end - base.as_u64()) as usize, protection: VmaProt::empty(), may_protection: VmaProt::empty(), committed: false, mapped_view: false })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_query_protect_and_exact_free_follow_one_vma() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let a = allocate(&as_, Some(UserVirtAddr::new(0x4000_0000).unwrap()), PAGE * 2, VmaProt::READ | VmaProt::WRITE, true).unwrap();
        let q = query(&as_, UserVirtAddr::new(0x4000_1000).unwrap()).unwrap();
        assert_eq!(q.base.as_u64(), 0x4000_1000); assert_eq!(q.size, PAGE); assert_eq!(q.may_protection, VmaProt::READ | VmaProt::WRITE);
        assert_eq!(protect(&as_, a.base, a.size, VmaProt::READ).unwrap(), VmaProt::READ | VmaProt::WRITE);
        assert_eq!(free(&as_, a), NtStatus::Success); assert_eq!(query(&as_, a.base), Err(NtStatus::NotMapped));
    }

    #[test]
    fn requested_address_is_fixed_and_conflicts_are_not_relocated() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let first = allocate(&as_, Some(UserVirtAddr::new(0x4000_0000).unwrap()), PAGE, VmaProt::READ, true).unwrap();
        assert_eq!(allocate(&as_, Some(first.base), PAGE, VmaProt::READ, true), Err(NtStatus::ConflictingAddresses));
        assert_eq!(query(&as_, first.base).unwrap().base, first.base);
    }

    #[test]
    fn invalid_and_wx_requests_do_not_change_the_address_space() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        assert_eq!(allocate(&as_, None, 0, VmaProt::READ, true), Err(NtStatus::InvalidParameter));
        let wx = allocate(&as_, None, PAGE, VmaProt::WRITE | VmaProt::EXEC, true).unwrap();
        assert_eq!(wx.size, PAGE);
        assert_eq!(as_.vma_count(), 1);
    }

    #[test]
    fn free_can_split_a_merged_extent_without_removing_neighbors() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let a = allocate(&as_, None, PAGE * 2, VmaProt::READ, true).unwrap();
        assert_eq!(free(&as_, NtAllocation { size: PAGE, ..a }), NtStatus::Success);
        assert_eq!(query(&as_, a.base), Err(NtStatus::NotMapped));
        assert_eq!(query(&as_, UserVirtAddr::new(a.base.as_u64() + PAGE as u64).unwrap()).unwrap().size, PAGE);
    }

    #[test]
    fn protect_rejects_unaligned_or_cross_vma_ranges() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let a = allocate(&as_, None, PAGE * 2, VmaProt::READ | VmaProt::WRITE, true).unwrap();
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
    fn section_views_cannot_gain_execute_or_write_access() {
        let maximum = VmaProt::READ | VmaProt::EXEC;
        assert_eq!(section_view_protection(maximum, VmaProt::READ), Ok(VmaProt::READ));
        assert_eq!(section_view_protection(maximum, maximum), Ok(maximum));
        assert_eq!(section_view_protection(maximum, VmaProt::READ | VmaProt::WRITE), Err(NtStatus::InvalidParameter));
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
    fn allocation_ranges_round_outward_and_preserve_null_hint() {
        let (base, size) = normalize_allocation_range(Some(0x4000_0001), 1).unwrap();
        assert_eq!(base.unwrap().as_u64(), 0x4000_0000);
        assert_eq!(size, PAGE);
        let (base, size) = normalize_allocation_range(None, 1).unwrap();
        assert_eq!(base, None);
        assert_eq!(size, PAGE);
        assert_eq!(normalize_allocation_range(Some(u64::MAX - 1), 2), Err(NtStatus::InvalidParameter));
    }

    #[test]
    fn free_query_stops_at_the_next_mapping() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let _ = allocate(&as_, Some(UserVirtAddr::new(0x4000_2000).unwrap()), PAGE, VmaProt::READ, true).unwrap();
        let q = query_free(&as_, UserVirtAddr::new(0x4000_0001).unwrap()).unwrap();
        assert_eq!(q.base.as_u64(), 0x4000_0000);
        assert_eq!(q.size, PAGE * 2);
        assert_eq!(q.allocation_base.as_u64(), 0);
    }

    #[test]
    fn reserved_allocation_is_visible_without_being_committed() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let a = allocate(&as_, Some(UserVirtAddr::new(0x4000_0000).unwrap()), PAGE * 2, VmaProt::READ | VmaProt::WRITE, false).unwrap();
        let q = query(&as_, a.base).unwrap();
        assert!(!q.committed);
        assert_eq!(q.protection, VmaProt::empty());
        assert_eq!(q.may_protection, VmaProt::READ | VmaProt::WRITE);
        assert_eq!(free(&as_, a), NtStatus::Success);
    }

    #[test]
    fn null_base_commit_creates_a_committed_region() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let a = allocate_or_commit(&as_, None, PAGE * 2, VmaProt::READ | VmaProt::WRITE).unwrap();
        let q = query(&as_, a.base).unwrap();
        assert_eq!(q.base, a.base);
        assert_eq!(q.size, PAGE * 2);
        assert!(q.committed);
        assert_eq!(q.protection, VmaProt::READ | VmaProt::WRITE);
        assert_eq!(free(&as_, a), NtStatus::Success);
    }

    #[test]
    fn supplied_base_commit_promotes_only_the_requested_reserved_range() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let reserved = allocate(&as_, Some(UserVirtAddr::new(0x4000_0000).unwrap()),
            PAGE * 3, VmaProt::READ | VmaProt::WRITE, false).unwrap();
        let committed = allocate_or_commit(&as_, Some(UserVirtAddr::new(0x4000_1000).unwrap()),
            PAGE, VmaProt::READ).unwrap();
        assert!(query(&as_, committed.base).unwrap().committed);
        assert!(!query(&as_, reserved.base).unwrap().committed);
        assert!(query(&as_, UserVirtAddr::new(0x4000_2000).unwrap()).unwrap().committed == false);
        assert_eq!(free(&as_, committed), NtStatus::Success);
        assert_eq!(free(&as_, NtAllocation { base: reserved.base, size: PAGE,
            protection: VmaProt::empty(), reserved: true }), NtStatus::Success);
        assert_eq!(free(&as_, NtAllocation { base: UserVirtAddr::new(0x4000_2000).unwrap(),
            size: PAGE, protection: VmaProt::empty(), reserved: true }), NtStatus::Success);
    }

    #[test]
    fn query_keeps_section_view_origin_after_protection_split() {
        let as_ = AddressSpace::new(0x20_000).unwrap();
        let origin = UserVirtAddr::new(0x4000_0000).unwrap();
        let a = allocate(&as_, Some(origin), PAGE * 3, VmaProt::READ | VmaProt::WRITE, true).unwrap();
        assert!(as_.set_mapping_origin(a.base));
        let middle = UserVirtAddr::new(origin.as_u64() + PAGE as u64).unwrap();
        assert_eq!(protect(&as_, middle, PAGE, VmaProt::READ).unwrap(), VmaProt::READ | VmaProt::WRITE);
        let q = query(&as_, middle).unwrap();
        assert_eq!(q.allocation_base, origin);
        assert_eq!(q.protection, VmaProt::READ);
    }
}
