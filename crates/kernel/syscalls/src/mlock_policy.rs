// mlock/mlock2/mlockall RLIMIT_MEMLOCK admission (Linux `mm/mlock.c`
// `can_do_mlock` + `do_mlock`) and the mlock2(2) flag set.
//
// Every observable rejection of an mlock family call is decided here, so the
// ladder is hosted-testable rather than sealed inside a `#![cfg(target_os =
// "oxide-kernel")]` slot file (CLAUDE.md phantom-test rule, docs/53).
//
//   mlock2:   flags & ~MLOCK_ONFAULT                    -> EINVAL
//   do_mlock: !can_do_mlock()                           -> EPERM
//             locked_pages > lock_limit && !CAP_IPC_LOCK-> ENOMEM
//   after apply: __mm_populate failure is remapped by
//             __mlock_posix_error_return: EFAULT->ENOMEM, ENOMEM->EAGAIN.

use syscall::errno::Errno;

/// `MLOCK_ONFAULT` (`include/uapi/asm-generic/mman-common.h`) — lock pages as
/// they fault in rather than prefaulting the whole range.
pub const MLOCK_ONFAULT: u64 = 0x01;

/// mlock2(2)'s only argument check: `flags & ~MLOCK_ONFAULT` is EINVAL.
/// Returns whether ONFAULT was requested. Runs BEFORE `do_mlock`, so a bad
/// flag is EINVAL even for a caller that would also fail `can_do_mlock`.
/// # C: O(1)
pub fn mlock2_flags_check(flags: u64) -> Result<bool, Errno> {
    if flags & !MLOCK_ONFAULT != 0 { return Err(Errno::Einval); }
    Ok(flags & MLOCK_ONFAULT != 0)
}

/// Linux `can_do_mlock()`: a nonzero RLIMIT_MEMLOCK soft limit OR CAP_IPC_LOCK.
/// A limit of exactly 0 with no capability means the process may not lock ANY
/// memory, which is EPERM — distinct from the ENOMEM a nonzero-but-exceeded
/// limit produces.
/// # C: O(1)
pub fn can_do_mlock(memlock_cur: u64, has_ipc_lock: bool) -> bool {
    memlock_cur != 0 || has_ipc_lock
}

/// Linux `do_mlock`'s RLIMIT_MEMLOCK ladder, in BYTES (the caller converts once
/// rather than every comparison rounding separately).
///
/// * `req` — the page-aligned length being locked.
/// * `mm_locked` — `mm->locked_vm`, already-locked bytes across the whole mm.
/// * `already_in_range` — `count_mm_mlocked_page_nr(mm, start, len)`, the part
///   of `req` that is already locked. Discounted only when the naive total
///   exceeds the limit, exactly as Linux orders it.
/// * `limit` — RLIMIT_MEMLOCK soft limit in bytes.
///
/// `has_ipc_lock` bypasses the limit entirely but NOT `can_do_mlock`, which the
/// capability also satisfies; the two checks are separate in Linux and both are
/// reachable.
/// # C: O(1)
pub fn memlock_admits(req: u64, mm_locked: u64, already_in_range: u64, limit: u64,
                      has_ipc_lock: bool) -> Result<(), Errno>
{
    if has_ipc_lock { return Ok(()); }
    let mut locked = req.saturating_add(mm_locked);
    if locked > limit { locked = locked.saturating_sub(already_in_range); }
    if locked <= limit { Ok(()) } else { Err(Errno::Enomem) }
}

/// Linux `__mlock_posix_error_return`: the population step's errno is remapped
/// on the way out so mlock(2) reports POSIX's codes — EFAULT becomes ENOMEM
/// ("address range not mapped"), and ENOMEM becomes EAGAIN ("could not lock,
/// try again"). Returning the raw ENOMEM would tell a caller its range was
/// unmapped when the range was fine and memory was merely short.
/// # C: O(1)
pub fn posix_error_return(e: Errno) -> Errno {
    match e {
        Errno::Efault => Errno::Enomem,
        Errno::Enomem => Errno::Eagain,
        other         => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ONFAULT is the only accepted flag; every other bit is EINVAL. # C: O(1)
    #[test]
    fn only_onfault_is_a_valid_flag() {
        assert_eq!(mlock2_flags_check(0), Ok(false));
        assert_eq!(mlock2_flags_check(MLOCK_ONFAULT), Ok(true));
        for f in [0x2u64, 0x4, 0x8, 0x100, u64::MAX, MLOCK_ONFAULT | 0x2] {
            assert_eq!(mlock2_flags_check(f), Err(Errno::Einval), "flags {f:#x}");
        }
    }

    /// A zero RLIMIT_MEMLOCK with no CAP_IPC_LOCK is EPERM territory; a nonzero
    /// limit or the capability alone is enough. This is the check that makes
    /// EPERM and ENOMEM mean different things: "may not lock at all" versus
    /// "may lock, but not this much". # C: O(1)
    #[test]
    fn can_do_mlock_is_nonzero_limit_or_capability() {
        assert!(!can_do_mlock(0, false));
        assert!(can_do_mlock(0, true));
        assert!(can_do_mlock(1, false));
        assert!(can_do_mlock(u64::MAX, false));
    }

    /// Within the limit succeeds; over it is ENOMEM, not EPERM. # C: O(1)
    #[test]
    fn limit_exceeded_is_enomem() {
        assert_eq!(memlock_admits(4096, 0, 0, 8192, false), Ok(()));
        assert_eq!(memlock_admits(8192, 0, 0, 8192, false), Ok(()), "equal to the limit is allowed");
        assert_eq!(memlock_admits(8193, 0, 0, 8192, false), Err(Errno::Enomem));
        assert_eq!(memlock_admits(4096, 8192, 0, 8192, false), Err(Errno::Enomem),
            "existing locked_vm counts toward the limit");
    }

    /// Re-locking a range that is ALREADY locked must not be charged twice:
    /// without the `count_mm_mlocked_page_nr` discount, a program that calls
    /// mlock() on the same buffer in a loop hits ENOMEM at the limit even
    /// though it never grew its locked set. # C: O(1)
    #[test]
    fn already_locked_overlap_is_discounted() {
        // 8 KiB limit, 8 KiB already locked mm-wide, re-locking the same 8 KiB.
        assert_eq!(memlock_admits(8192, 8192, 8192, 8192, false), Ok(()));
        // Same, but only half the range was already locked -> still over.
        assert_eq!(memlock_admits(8192, 8192, 4096, 8192, false), Err(Errno::Enomem));
    }

    /// The discount is applied ONLY when the naive total exceeds the limit, so
    /// an under-limit call never goes negative and never changes answer.
    /// # C: O(1)
    #[test]
    fn discount_does_not_apply_under_the_limit() {
        assert_eq!(memlock_admits(4096, 0, 4096, 1 << 30, false), Ok(()));
    }

    /// CAP_IPC_LOCK bypasses the limit outright, including a zero limit.
    /// # C: O(1)
    #[test]
    fn ipc_lock_capability_bypasses_the_limit() {
        assert_eq!(memlock_admits(u64::MAX / 2, 0, 0, 0, true), Ok(()));
        assert_eq!(memlock_admits(u64::MAX / 2, 0, 0, 0, false), Err(Errno::Enomem));
    }

    /// An unlimited RLIMIT_MEMLOCK admits any request without the saturating
    /// add wrapping into a spurious rejection. # C: O(1)
    #[test]
    fn unlimited_memlock_admits_everything() {
        assert_eq!(memlock_admits(u64::MAX, u64::MAX, 0, u64::MAX, false), Ok(()));
    }

    /// POSIX errno remap on the populate failure path. Anything else passes
    /// through unchanged (EINTR from a killable lock must stay EINTR).
    /// # C: O(1)
    #[test]
    fn populate_failure_is_remapped_to_posix_codes() {
        assert_eq!(posix_error_return(Errno::Efault), Errno::Enomem);
        assert_eq!(posix_error_return(Errno::Enomem), Errno::Eagain);
        assert_eq!(posix_error_return(Errno::Eintr),  Errno::Eintr);
        assert_eq!(posix_error_return(Errno::Einval), Errno::Einval);
    }
}
