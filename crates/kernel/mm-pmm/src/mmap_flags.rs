use syscall::errno::Errno;

pub const MAP_SHARED:  u64 = 0x01;
pub const MAP_PRIVATE: u64 = 0x02;
pub const MAP_SHARED_VALIDATE: u64 = 0x03;
pub const MAP_TYPE:    u64 = 0x0f;
pub const MAP_FIXED:   u64 = 0x10;
pub const MAP_ANON:    u64 = 0x20;
pub const MAP_GROWSDOWN: u64       = 0x100;
pub const MAP_DENYWRITE: u64       = 0x800;
pub const MAP_EXECUTABLE: u64      = 0x1000;
pub const MAP_LOCKED:    u64       = 0x2000;
pub const MAP_NORESERVE: u64       = 0x4000;
pub const MAP_POPULATE:  u64       = 0x8000;
pub const MAP_NONBLOCK:  u64       = 0x10000;
pub const MAP_STACK:     u64       = 0x20000;
pub const MAP_HUGETLB:   u64       = 0x40000;
pub const MAP_SYNC:      u64       = 0x80000;
pub const MAP_FIXED_NOREPLACE: u64 = 0x100000;
const PAGE_MASK: u64 = !(hal::PAGE_SIZE_BYTES - 1);
pub const MAP_UNINITIALIZED: u64   = 0x4000000;

pub const PROT_READ:  u64 = 0x1;
pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC:  u64 = 0x4;
pub const PROT_SEM:   u64 = 0x8;
pub const PROT_GROWSDOWN: u64 = 0x01000000;
pub const PROT_GROWSUP:   u64 = 0x02000000;
pub const PROT_KNOWN: u64 = PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM | PROT_GROWSDOWN | PROT_GROWSUP;

const MAP_KNOWN: u64 = MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANON
    | MAP_GROWSDOWN | MAP_DENYWRITE | MAP_EXECUTABLE | MAP_LOCKED
    | MAP_NORESERVE | MAP_POPULATE | MAP_NONBLOCK | MAP_STACK
    | MAP_HUGETLB | MAP_SYNC | MAP_FIXED_NOREPLACE | MAP_UNINITIALIZED;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MapType {
    Shared,
    Private,
    SharedValidate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GlueAdmission {
    pub is_anon: bool,
    pub is_shared: bool,
    pub len_aligned: usize,
}

/// Decode mmap's raw address argument before entering the typed VMM.
///
/// Linux treats an address without `MAP_FIXED{,_NOREPLACE}` as a hint:
/// page-align a usable value, but discard a value outside the task address
/// space and run the normal unmapped-area search. Exact requests must remain
/// representable and page-aligned or fail instead of silently moving.
/// # C: O(1)
pub fn mmap_address_hint(
    addr: u64,
    len: u64,
    flags: u64,
) -> Result<Option<hal::UserVirtAddr>, i64> {
    let exact = flags & (MAP_FIXED | MAP_FIXED_NOREPLACE) != 0;
    if exact {
        if len >= hal::USER_VA_END || addr >= hal::USER_VA_END.saturating_sub(len) {
            return Err(-(Errno::Enomem.as_i32() as i64));
        }
        if addr & !PAGE_MASK != 0 {
            return Err(-(Errno::Einval.as_i32() as i64));
        }
        if addr < hal::PAGE_SIZE_BYTES {
            return Err(-(Errno::Eperm.as_i32() as i64));
        }
        return hal::UserVirtAddr::new(addr)
            .map(Some)
            .ok_or(-(Errno::Einval.as_i32() as i64));
    }
    if addr == 0 {
        return Ok(None);
    }
    let aligned = (addr & PAGE_MASK).max(hal::PAGE_SIZE_BYTES);
    if len >= hal::USER_VA_END || aligned >= hal::USER_VA_END.saturating_sub(len) {
        return Ok(None);
    }
    Ok(hal::UserVirtAddr::new(aligned))
}

/// # C: O(1)
pub fn validate_prot(prot: u64) -> Result<(), i64> {
    if (prot & !PROT_KNOWN) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    if (prot & (PROT_GROWSDOWN | PROT_GROWSUP)) == (PROT_GROWSDOWN | PROT_GROWSUP) {
        return Err(-(Errno::Einval.as_i32() as i64));
    }
    Ok(())
}

/// Linux `flags & MAP_TYPE` decoding. `MAP_SHARED_VALIDATE` is the value `3`,
/// not `MAP_SHARED | MAP_PRIVATE`.
/// # C: O(1)
pub fn map_type(flags: u64) -> Result<MapType, i64> {
    match flags & MAP_TYPE {
        MAP_SHARED => Ok(MapType::Shared),
        MAP_PRIVATE => Ok(MapType::Private),
        MAP_SHARED_VALIDATE => Ok(MapType::SharedValidate),
        _ => Err(-(Errno::Einval.as_i32() as i64)),
    }
}

/// Bit position and width of the huge-page size-log field `MAP_HUGETLB` reads,
/// shared with `memfd_create` and `shmget` (`pmm::hugetlb`).
pub const MAP_HUGE_SHIFT: u32 = crate::hugetlb::HUGE_FLAG_ENCODE_SHIFT;
pub const MAP_HUGE_MASK:  u32 = crate::hugetlb::HUGE_FLAG_ENCODE_MASK;
/// Size-log encodings for the two granules this kernel serves.
pub const MAP_HUGE_2MB: u64 = 21u64 << MAP_HUGE_SHIFT;
pub const MAP_HUGE_1GB: u64 = 30u64 << MAP_HUGE_SHIFT;
/// The whole size-log field, admitted only alongside `MAP_HUGETLB`.
const MAP_HUGE_FIELD: u64 = (MAP_HUGE_MASK as u64) << MAP_HUGE_SHIFT;

/// Huge-page granule an anonymous `MAP_HUGETLB` request names, or `Err(EINVAL)`
/// when the size-log field names a size this kernel has no pool for. A zero
/// field selects the default granule.
/// # C: O(1)
pub fn huge_size(flags: u64) -> Result<crate::hugetlb::HugePageSize, i64> {
    crate::hugetlb::size_from_flags(flags).ok_or(-(Errno::Einval.as_i32() as i64))
}

/// # C: O(1)
pub fn validate(flags: u64) -> Result<(), i64> {
    // The size-log field overlaps flag bits that mean something else without
    // `MAP_HUGETLB`, so it is admitted only when `MAP_HUGETLB` asks for it.
    let known = if (flags & MAP_HUGETLB) != 0 { MAP_KNOWN | MAP_HUGE_FIELD } else { MAP_KNOWN };
    if (flags & !known) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    if (flags & MAP_HUGETLB) != 0 { huge_size(flags)?; }
    map_type(flags)?;
    Ok(())
}

/// Linux `do_mmap` admission checks that are independent of the live VMA tree.
/// # C: O(1)
pub fn validate_glue_admission(
    flags: u64,
    len: u64,
    file_off: u64,
    has_backing: bool,
    has_phys: bool,
) -> Result<GlueAdmission, i64> {
    validate(flags)?;
    let mt = map_type(flags)?;
    let is_shared = matches!(mt, MapType::Shared | MapType::SharedValidate);
    let is_anon = flags & MAP_ANON != 0;

    if is_anon {
        if matches!(mt, MapType::SharedValidate) { return Err(-(Errno::Einval.as_i32() as i64)); }
        if has_phys { return Err(-(Errno::Einval.as_i32() as i64)); }
        if has_backing && !is_shared { return Err(-(Errno::Einval.as_i32() as i64)); }
    } else if has_phys {
        if (file_off & !PAGE_MASK) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
        if matches!(mt, MapType::SharedValidate) && (flags & MAP_SYNC) != 0 {
            return Err(-(Errno::Eopnotsupp.as_i32() as i64));
        }
    } else {
        if !has_backing { return Err(-(Errno::Ebadf.as_i32() as i64)); }
        if (file_off & !PAGE_MASK) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
        if matches!(mt, MapType::SharedValidate) && (flags & MAP_SYNC) != 0 {
            return Err(-(Errno::Eopnotsupp.as_i32() as i64));
        }
    }
    if len == 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    let len_aligned_u64 = match len.checked_add(hal::PAGE_SIZE_BYTES - 1).map(|v| v & PAGE_MASK) {
        Some(0) | None => return Err(-(Errno::Enomem.as_i32() as i64)),
        Some(v) => v,
    };
    let len_aligned = len_aligned_u64 as usize;
    if (len_aligned as u64) != len_aligned_u64 { return Err(-(Errno::Enomem.as_i32() as i64)); }
    if !is_anon && (file_off / hal::PAGE_SIZE_BYTES).checked_add(len_aligned_u64 / hal::PAGE_SIZE_BYTES).is_none() {
        return Err(-(Errno::Eoverflow.as_i32() as i64));
    }
    Ok(GlueAdmission { is_anon, is_shared, len_aligned })
}

/// Linux `do_mmap` file-branch permission checks, after fd lookup and before
/// VMA insertion. Invalid mapping types are left for `validate()`/`do_mmap`'s
/// default `EINVAL` path so bad live fds still preserve Linux errno ordering.
/// # C: O(1)
pub fn validate_file_access(
    flags: u64,
    prot: u64,
    file_readable: bool,
    file_writable: bool,
    path_noexec: bool,
) -> Result<(), i64> {
    match flags & MAP_TYPE {
        MAP_SHARED | MAP_SHARED_VALIDATE => {
            if (prot & PROT_WRITE) != 0 && !file_writable {
                return Err(-(Errno::Eacces.as_i32() as i64));
            }
            if !file_readable {
                return Err(-(Errno::Eacces.as_i32() as i64));
            }
        }
        MAP_PRIVATE => {
            if !file_readable {
                return Err(-(Errno::Eacces.as_i32() as i64));
            }
        }
        _ => return Ok(()),
    }
    if (prot & PROT_EXEC) != 0 && path_noexec {
        return Err(-(Errno::Eperm.as_i32() as i64));
    }
    Ok(())
}

/// Linux `do_mmap` populate decision: `MAP_NONBLOCK` suppresses
/// `MAP_POPULATE`, while locked mappings are populated regardless.
/// # C: O(1)
pub fn should_populate(flags: u64) -> bool {
    (flags & MAP_LOCKED) != 0 || (flags & (MAP_POPULATE | MAP_NONBLOCK)) == MAP_POPULATE
}

/// Linux `do_mmap`'s mlock gate: an explicit `MAP_LOCKED` first needs
/// `can_do_mlock()` (EPERM), and then ANY mapping that will end up `VM_LOCKED`
/// — whether from `MAP_LOCKED` or from an `mlockall(MCL_FUTURE)` policy folded
/// in through `mm->def_flags` — is charged against RLIMIT_MEMLOCK by
/// `mlock_future_ok`, which reports **EAGAIN**, not the ENOMEM `mlock(2)` uses
/// for the same overrun.
///
/// `vma_locked` is the post-`def_flags` answer, so an `mlockall(MCL_FUTURE)`
/// process is limit-checked on every mmap even when it passes no map flag.
/// Without this, `mlockall(MCL_FUTURE)` is an unbounded lock-everything hole
/// that RLIMIT_MEMLOCK never sees.
/// # C: O(1)
pub fn mmap_lock_admission(map_locked: bool, vma_locked: bool, len: u64, mm_locked: u64,
                           limit: u64, has_ipc_lock: bool) -> Result<(), Errno>
{
    if map_locked && limit == 0 && !has_ipc_lock { return Err(Errno::Eperm); }
    if !vma_locked || has_ipc_lock { return Ok(()); }
    if len.saturating_add(mm_locked) <= limit { Ok(()) } else { Err(Errno::Eagain) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hugetlb_with_no_size_selector_is_admitted_at_the_default_granule() {
        assert_eq!(validate(MAP_PRIVATE | MAP_ANON | MAP_HUGETLB), Ok(()));
        assert_eq!(huge_size(MAP_PRIVATE | MAP_ANON | MAP_HUGETLB),
                   Ok(crate::hugetlb::HugePageSize::Huge2M));
    }

    #[test]
    fn each_supported_huge_size_selector_resolves_to_its_granule() {
        assert_eq!(huge_size(MAP_HUGETLB | MAP_HUGE_2MB), Ok(crate::hugetlb::HugePageSize::Huge2M));
        assert_eq!(huge_size(MAP_HUGETLB | MAP_HUGE_1GB), Ok(crate::hugetlb::HugePageSize::Huge1G));
        assert_eq!(validate(MAP_PRIVATE | MAP_ANON | MAP_HUGETLB | MAP_HUGE_1GB), Ok(()));
    }

    #[test]
    fn an_unserved_huge_size_selector_is_einval_not_a_silent_downgrade() {
        let flags = MAP_PRIVATE | MAP_ANON | MAP_HUGETLB | (16u64 << MAP_HUGE_SHIFT);
        assert_eq!(validate(flags), Err(-(Errno::Einval.as_i32() as i64)));
        assert_eq!(huge_size(flags), Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn the_huge_size_field_is_admitted_only_alongside_hugetlb() {
        // Without MAP_HUGETLB those bits mean nothing and must stay refused.
        assert_eq!(validate(MAP_PRIVATE | MAP_ANON | MAP_HUGE_2MB),
                   Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn unknown_future_bits_are_einval() {
        let r = validate(MAP_PRIVATE | MAP_ANON | 0x8000_0000);
        assert_eq!(r, Err(-(Errno::Einval.as_i32() as i64)));
        // Still refused when MAP_HUGETLB widens the admitted set: only the
        // size-log field opens up, not every high bit.
        assert_eq!(validate(MAP_PRIVATE | MAP_ANON | MAP_HUGETLB | (1u64 << 40)),
                   Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn shared_validate_is_a_mapping_type_not_shared_private_conflict() {
        assert_eq!(map_type(MAP_SHARED_VALIDATE), Ok(MapType::SharedValidate));
        assert_eq!(validate(MAP_SHARED_VALIDATE), Ok(()));
        let r = validate_glue_admission(MAP_SHARED_VALIDATE | MAP_ANON, 0x1000, 0, false, false);
        assert_eq!(r, Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn unusable_nonfixed_hint_falls_back_to_unmapped_area_search() {
        let flags = MAP_PRIVATE | MAP_ANON;
        assert_eq!(mmap_address_hint(0x0000_dff7_6c16_f000, 0x1000, flags), Ok(None));
        assert_eq!(mmap_address_hint(u64::MAX, 0x1000, flags), Ok(None));
        assert_eq!(mmap_address_hint(0, 0x1000, flags), Ok(None));

        let mm = vmm::AddressSpace::new(0).unwrap();
        let address = mm.mmap(
            mmap_address_hint(0x0000_dff7_6c16_f000, 0x1000, flags).unwrap(),
            hal::PAGE_SIZE_BYTES as usize,
            vmm::VmaProt::READ | vmm::VmaProt::WRITE,
            vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS,
            vmm::VmaBacking::Anonymous,
            false,
        ).unwrap();
        assert_eq!(address.as_u64(), vmm::address_space::MMAP_TOP - hal::PAGE_SIZE_BYTES);
    }

    #[test]
    fn usable_nonfixed_hint_is_linux_page_aligned() {
        let flags = MAP_PRIVATE | MAP_ANON;
        let aligned = mmap_address_hint(0x4000_0123, 0x1000, flags).unwrap().unwrap();
        assert_eq!(aligned.as_u64(), 0x4000_0000);
        let low = mmap_address_hint(1, 0x1000, flags).unwrap().unwrap();
        assert_eq!(low.as_u64(), hal::PAGE_SIZE_BYTES);
    }

    #[test]
    fn fixed_and_noreplace_addresses_fail_in_linux_order() {
        let einval = Err(-(Errno::Einval.as_i32() as i64));
        let enomem = Err(-(Errno::Enomem.as_i32() as i64));
        let eperm = Err(-(Errno::Eperm.as_i32() as i64));
        for fixed in [MAP_FIXED, MAP_FIXED_NOREPLACE] {
            let flags = MAP_PRIVATE | MAP_ANON | fixed;
            assert_eq!(mmap_address_hint(0x0000_dff7_6c16_f123, 0x1000, flags), enomem);
            assert_eq!(mmap_address_hint(0x4000_0123, 0x1000, flags), einval);
            assert_eq!(mmap_address_hint(0, 0x1000, flags), eperm);
            let address = mmap_address_hint(0x4000_0000, 0x1000, flags).unwrap().unwrap();
            assert_eq!(address.as_u64(), 0x4000_0000);
        }
    }

    #[test]
    fn missing_mapping_type_is_einval() {
        assert_eq!(validate(MAP_ANON), Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn shared_validate_with_sync_requires_file_sync_support() {
        let r = validate_glue_admission(MAP_SHARED_VALIDATE | MAP_SYNC, 0x1000, 0, true, false);
        assert_eq!(r, Err(-(Errno::Eopnotsupp.as_i32() as i64)));
    }

    #[test]
    fn legacy_shared_ignores_sync_like_linux() {
        let r = validate_glue_admission(MAP_SHARED | MAP_SYNC, 0x1000, 1, true, false);
        assert_eq!(r, Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn private_mapping_rejects_anon_shared_backing() {
        let r = validate_glue_admission(MAP_PRIVATE | MAP_ANON, 0x1000, 0, true, false);
        assert_eq!(r, Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn len_page_align_wrap_is_enomem() {
        let r = validate_glue_admission(MAP_PRIVATE | MAP_ANON, u64::MAX, 0, false, false);
        assert_eq!(r, Err(-(Errno::Enomem.as_i32() as i64)));
    }

    #[test]
    fn max_page_aligned_byte_offset_does_not_false_overflow() {
        let off = u64::MAX & !0xfff;
        let r = validate_glue_admission(MAP_PRIVATE, 0x2000, off, true, false);
        assert_eq!(r, Ok(GlueAdmission { is_anon: false, is_shared: false, len_aligned: 0x2000 }));
    }

    #[test]
    fn file_access_matches_linux_shared_write_then_read_order() {
        let r = validate_file_access(MAP_SHARED, PROT_WRITE | PROT_EXEC, false, false, true);
        assert_eq!(r, Err(-(Errno::Eacces.as_i32() as i64)));

        let r = validate_file_access(MAP_SHARED, PROT_WRITE, true, false, false);
        assert_eq!(r, Err(-(Errno::Eacces.as_i32() as i64)));

        let r = validate_file_access(MAP_SHARED, 0, false, true, false);
        assert_eq!(r, Err(-(Errno::Eacces.as_i32() as i64)));
    }

    #[test]
    fn file_access_private_requires_read_and_noexec_blocks_exec() {
        let r = validate_file_access(MAP_PRIVATE, 0, false, true, false);
        assert_eq!(r, Err(-(Errno::Eacces.as_i32() as i64)));

        let r = validate_file_access(MAP_PRIVATE, PROT_EXEC, true, false, true);
        assert_eq!(r, Err(-(Errno::Eperm.as_i32() as i64)));

        let r = validate_file_access(MAP_PRIVATE, PROT_EXEC, true, false, false);
        assert_eq!(r, Ok(()));
    }

    #[test]
    fn file_access_invalid_map_type_defers_to_flag_validation() {
        let r = validate_file_access(0, PROT_EXEC, false, false, true);
        assert_eq!(r, Ok(()));
        assert_eq!(validate(0), Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn populate_decision_matches_linux_flags() {
        assert!(should_populate(MAP_PRIVATE | MAP_ANON | MAP_POPULATE));
        assert!(!should_populate(MAP_PRIVATE | MAP_ANON | MAP_POPULATE | MAP_NONBLOCK));
        assert!(should_populate(MAP_PRIVATE | MAP_ANON | MAP_LOCKED));
        assert!(!should_populate(MAP_PRIVATE | MAP_ANON));
    }

    #[test]
    fn mprotect_prot_validation_matches_linux_admission() {
        assert_eq!(validate_prot(0), Ok(()));
        assert_eq!(validate_prot(0x1 | PROT_WRITE | PROT_EXEC | PROT_SEM), Ok(()));
        assert_eq!(validate_prot(PROT_GROWSDOWN | PROT_GROWSUP), Err(-(Errno::Einval.as_i32() as i64)));
        assert_eq!(validate_prot(0x8000_0000), Err(-(Errno::Einval.as_i32() as i64)));
    }

    const PAGE: u64 = 4096;

    /// A mapping that will not be locked is never limit-checked, however small
    /// RLIMIT_MEMLOCK is. # C: O(1)
    #[test]
    fn unlocked_mappings_are_not_charged() {
        assert_eq!(mmap_lock_admission(false, false, 1 << 40, 0, 0, false), Ok(()));
    }

    /// `MAP_LOCKED` with a zero RLIMIT_MEMLOCK and no CAP_IPC_LOCK is EPERM —
    /// `can_do_mlock()` — and that answer precedes the size check.
    #[test]
    fn map_locked_without_permission_is_eperm() {
        assert_eq!(mmap_lock_admission(true, true, PAGE, 0, 0, false), Err(Errno::Eperm));
        assert_eq!(mmap_lock_admission(true, true, PAGE, 0, 0, true), Ok(()));
        // No MAP_LOCKED flag: a zero limit is not EPERM here, just a tight
        // limit the mapping happens to fit under (it is unlocked).
        assert_eq!(mmap_lock_admission(false, false, PAGE, 0, 0, false), Ok(()));
    }

    /// Over the limit, mmap reports **EAGAIN** where mlock(2) reports ENOMEM
    /// for the same overrun. Returning ENOMEM here is the easy mistake.
    #[test]
    fn over_the_limit_is_eagain_not_enomem() {
        assert_eq!(mmap_lock_admission(true, true, 2 * PAGE, 0, 2 * PAGE, false), Ok(()));
        assert_eq!(mmap_lock_admission(true, true, 3 * PAGE, 0, 2 * PAGE, false), Err(Errno::Eagain));
        assert_eq!(mmap_lock_admission(true, true, PAGE, 2 * PAGE, 2 * PAGE, false), Err(Errno::Eagain),
            "already-locked bytes count toward the limit");
        assert_eq!(mmap_lock_admission(true, true, 1 << 40, 0, PAGE, true), Ok(()),
            "CAP_IPC_LOCK bypasses the charge");
    }

    /// An `mlockall(MCL_FUTURE)` process is charged on every mmap even though
    /// it passes no map flag — that inherited lock is the whole reason the
    /// check is on the mmap path and not only on mlock(2).
    #[test]
    fn inherited_future_lock_is_charged_without_map_locked() {
        assert_eq!(mmap_lock_admission(false, true, 3 * PAGE, 0, 2 * PAGE, false), Err(Errno::Eagain));
        assert_eq!(mmap_lock_admission(false, true, PAGE, 0, 2 * PAGE, false), Ok(()));
    }
}
