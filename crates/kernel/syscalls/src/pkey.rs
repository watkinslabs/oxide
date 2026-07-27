// Memory-protection-key UAPI constants and admission logic (Linux
// `include/uapi/asm-generic/mman-common.h`, `mm/mprotect.c`). Shared by slots
// 329/330/331.
//
// The decision functions are deliberately NOT kernel-cfg'd: the syscall files
// are `#![cfg(target_os = "oxide-kernel")]` and so cannot be exercised by the
// hosted suite, which would leave the errno ordering — the whole point of this
// module — untested. Keeping the policy here makes the shims thin (docs/53)
// and the rules testable.

use syscall::errno::Errno;

/// `PKEY_DISABLE_ACCESS`.
pub const PKEY_DISABLE_ACCESS: u64 = 0x1;
/// `PKEY_DISABLE_WRITE`.
pub const PKEY_DISABLE_WRITE: u64 = 0x2;
/// `PKEY_ACCESS_MASK` — the only bits `pkey_alloc`'s `init_val` may carry.
pub const PKEY_ACCESS_MASK: u64 = PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE;

/// Linux `arch_max_pkey()` on a CPU without `X86_FEATURE_OSPKE`: pkey 0 only,
/// and pkey 0 is allocated implicitly with the mm, so no key is ever free.
pub const ARCH_MAX_PKEY_NO_OSPKE: i32 = 1;

/// "Keep the current key" sentinel accepted by `pkey_mprotect`.
pub const PKEY_KEEP: i32 = -1;
/// The implicitly-allocated default key.
pub const PKEY_DEFAULT: i32 = 0;

/// `pkey_alloc` admission, in Linux's order: flags, then init_val, then the
/// allocation attempt. Always `Err` for us — with no OSPKE the allocation map
/// is full at mm creation — but WHICH error, and in what order, is what
/// callers branch on.
/// # C: O(1)
pub fn pkey_alloc_check(flags: u64, init_val: u64) -> Result<i32, Errno> {
    if flags != 0 { return Err(Errno::Einval); }
    if init_val & !PKEY_ACCESS_MASK != 0 { return Err(Errno::Einval); }
    Err(Errno::Enospc)
}

/// True iff `pkey` is allocated for the current mm, per Linux
/// `mm_pkey_is_allocated` with `arch_max_pkey() == 1`.
/// # C: O(1)
pub fn pkey_is_allocated(pkey: i32) -> bool {
    pkey == PKEY_DEFAULT
}

/// `pkey_mprotect` key admission: `-1` keeps the current key, otherwise the
/// key must be allocated (Linux `do_mprotect_pkey`, checked before the VMA
/// walk so a bad key never partially applies).
/// # C: O(1)
pub fn pkey_mprotect_allows(pkey: i32) -> bool {
    pkey == PKEY_KEEP || pkey_is_allocated(pkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_rejects_any_flag_before_looking_at_init_val() {
        // Linux checks flags first, so a call that is wrong in BOTH ways must
        // still report the flags error.
        assert_eq!(pkey_alloc_check(1, !0), Err(Errno::Einval));
        assert_eq!(pkey_alloc_check(0x8000, 0), Err(Errno::Einval));
    }

    #[test]
    fn alloc_rejects_init_val_outside_access_mask() {
        assert_eq!(pkey_alloc_check(0, !PKEY_ACCESS_MASK), Err(Errno::Einval));
        assert_eq!(pkey_alloc_check(0, 0x4), Err(Errno::Einval));
    }

    #[test]
    fn alloc_reports_exhaustion_not_unimplemented() {
        // The whole point: a well-formed request gets ENOSPC ("no keys left"),
        // which is what Linux returns on a CPU without OSPKE. ENOSYS would
        // misreport the reason and skip the validation above.
        for iv in [0, PKEY_DISABLE_ACCESS, PKEY_DISABLE_WRITE, PKEY_ACCESS_MASK] {
            assert_eq!(pkey_alloc_check(0, iv), Err(Errno::Enospc));
        }
    }

    #[test]
    fn only_the_implicit_default_key_is_allocated() {
        assert!(pkey_is_allocated(PKEY_DEFAULT));
        for k in [1, 2, 15, ARCH_MAX_PKEY_NO_OSPKE, 16, i32::MAX] {
            assert!(!pkey_is_allocated(k), "pkey {k} must not be allocated without OSPKE");
        }
    }

    #[test]
    fn mprotect_accepts_keep_and_default_only() {
        assert!(pkey_mprotect_allows(PKEY_KEEP));
        assert!(pkey_mprotect_allows(PKEY_DEFAULT));
        for k in [1, 2, 15, 16, i32::MAX, -2, i32::MIN] {
            assert!(!pkey_mprotect_allows(k), "pkey {k} must be EINVAL");
        }
    }
}
