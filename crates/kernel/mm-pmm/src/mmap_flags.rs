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

pub const PROT_WRITE: u64 = 0x2;
pub const PROT_EXEC:  u64 = 0x4;
pub const PROT_SEM:   u64 = 0x8;
pub const PROT_GROWSDOWN: u64 = 0x01000000;
pub const PROT_GROWSUP:   u64 = 0x02000000;
pub const PROT_KNOWN: u64 = 0x1 | PROT_WRITE | PROT_EXEC | PROT_SEM | PROT_GROWSDOWN | PROT_GROWSUP;

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

/// # C: O(1)
pub fn validate(flags: u64) -> Result<(), i64> {
    if (flags & !MAP_KNOWN) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
    if (flags & MAP_HUGETLB) != 0 { return Err(-(Errno::Einval.as_i32() as i64)); }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hugetlb_uses_linux_einval_not_enosys() {
        let r = validate(MAP_PRIVATE | MAP_ANON | MAP_HUGETLB);
        assert_eq!(r, Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn unknown_future_bits_are_einval() {
        let r = validate(MAP_PRIVATE | MAP_ANON | 0x8000_0000);
        assert_eq!(r, Err(-(Errno::Einval.as_i32() as i64)));
    }

    #[test]
    fn shared_validate_is_a_mapping_type_not_shared_private_conflict() {
        assert_eq!(map_type(MAP_SHARED_VALIDATE), Ok(MapType::SharedValidate));
        assert_eq!(validate(MAP_SHARED_VALIDATE), Ok(()));
        let r = validate_glue_admission(MAP_SHARED_VALIDATE | MAP_ANON, 0x1000, 0, false, false);
        assert_eq!(r, Err(-(Errno::Einval.as_i32() as i64)));
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
}
