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

/// mlockall(2) flags (`include/uapi/asm-generic/mman.h`). Identical on x86_64
/// and aarch64.
pub const MCL_CURRENT: u64 = 1;
pub const MCL_FUTURE:  u64 = 2;
pub const MCL_ONFAULT: u64 = 4;

/// The mlock/munlock argument rounding, byte-exact with Linux:
/// `len = PAGE_ALIGN(len + offset_in_page(start)); start &= PAGE_MASK`, both
/// evaluated in wrapping unsigned arithmetic, followed by
/// `apply_vma_lock_flags`' `end < start -> EINVAL`, `end == start -> success`.
///
/// The wrapping is load-bearing, not sloppiness: a length so large that
/// `PAGE_ALIGN` wraps collapses to zero and the call SUCCEEDS having locked
/// nothing, whereas rejecting the overflow with EINVAL would break callers
/// that pass a deliberately huge length. Conversely a `start` near the top of
/// the address space whose `start + len` wraps IS EINVAL.
///
/// Note the offset fold: a non-page-aligned `addr` with `len == 0` rounds up to
/// a full page, so `mlock(addr + 1, 0)` locks one page rather than returning
/// early.
///
/// `Ok(None)` = nothing to do, report success.
/// # C: O(1)
pub fn mlock_range(addr: u64, len: u64, page: u64) -> Result<Option<(u64, u64)>, Errno> {
    let mask = page - 1;
    let len = len.wrapping_add(addr & mask).wrapping_add(mask) & !mask;
    let start = addr & !mask;
    let end = start.wrapping_add(len);
    if end < start { return Err(Errno::Einval); }
    if end == start { return Ok(None); }
    Ok(Some((start, len)))
}

/// mlockall(2)'s flag validation. Zero flags, an unknown bit, or `MCL_ONFAULT`
/// on its own are all EINVAL — ONFAULT only qualifies one of the two actions
/// and means nothing alone. Returns `(current, future, onfault)`.
/// # C: O(1)
pub fn mlockall_flags_check(flags: u64) -> Result<(bool, bool, bool), Errno> {
    let known = MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT;
    if flags == 0 || (flags & !known) != 0 || flags == MCL_ONFAULT { return Err(Errno::Einval); }
    Ok((flags & MCL_CURRENT != 0, flags & MCL_FUTURE != 0, flags & MCL_ONFAULT != 0))
}

/// mlockall(2)'s admission ladder: `can_do_mlock` first (EPERM), then — only
/// when `MCL_CURRENT` is asked for — the whole mapped address space is charged
/// against RLIMIT_MEMLOCK at once, because `MCL_CURRENT` locks all of it.
/// `MCL_FUTURE` alone installs a policy without locking anything now, so it is
/// never charged and can never be ENOMEM.
/// # C: O(1)
pub fn mlockall_admits(current: bool, total_mapped: u64, limit: u64, has_ipc_lock: bool)
    -> Result<(), Errno>
{
    if !can_do_mlock(limit, has_ipc_lock) { return Err(Errno::Eperm); }
    if !current || has_ipc_lock || total_mapped <= limit { return Ok(()); }
    Err(Errno::Enomem)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE: u64 = 4096;

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

    /// The page rounding: `start` rounds DOWN, and the bytes that rounding
    /// dropped are added to `len` before it rounds UP, so the returned range
    /// always covers every byte the caller named. # C: O(1)
    #[test]
    fn range_rounds_start_down_and_folds_the_offset_into_len() {
        assert_eq!(mlock_range(0x1000, PAGE, PAGE), Ok(Some((0x1000, PAGE))));
        // One byte past a page boundary, one byte long: still one page.
        assert_eq!(mlock_range(0x1001, 1, PAGE), Ok(Some((0x1000, PAGE))));
        // Straddling a boundary needs two pages, not one.
        assert_eq!(mlock_range(0x1fff, 2, PAGE), Ok(Some((0x1000, 2 * PAGE))));
        assert_eq!(mlock_range(0x1001, PAGE, PAGE), Ok(Some((0x1000, 2 * PAGE))));
    }

    /// `len == 0` on a page-ALIGNED address is a no-op success, but on an
    /// UNALIGNED address the folded offset rounds up to a whole page and the
    /// call really does lock that page. Returning early on `len == 0` — the
    /// obvious implementation — silently loses that page. # C: O(1)
    #[test]
    fn zero_length_is_a_noop_only_when_the_address_is_aligned() {
        assert_eq!(mlock_range(0x1000, 0, PAGE), Ok(None));
        assert_eq!(mlock_range(0, 0, PAGE), Ok(None));
        assert_eq!(mlock_range(0x1234, 0, PAGE), Ok(Some((0x1000, PAGE))));
        assert_eq!(mlock_range(0x1fff, 0, PAGE), Ok(Some((0x1000, PAGE))));
    }

    /// A length whose page-round wraps collapses to zero and SUCCEEDS locking
    /// nothing — it is not EINVAL. `mlock(addr, ~0UL)` is the shape callers
    /// actually pass, and reporting EINVAL for it is a real divergence.
    /// # C: O(1)
    #[test]
    fn length_that_wraps_the_page_round_succeeds_as_a_noop() {
        assert_eq!(mlock_range(0x1000, u64::MAX, PAGE), Ok(None));
        assert_eq!(mlock_range(0x1000, u64::MAX - (PAGE - 2), PAGE), Ok(None));
    }

    /// A start near the top of the address space whose end wraps IS EINVAL —
    /// the distinct case from the wrapping length above. # C: O(1)
    #[test]
    fn range_whose_end_wraps_past_the_start_is_einval() {
        assert_eq!(mlock_range(u64::MAX & !(PAGE - 1), 2 * PAGE, PAGE), Err(Errno::Einval));
        // The very last page wraps `end` to zero, which is also EINVAL: the
        // comparison is `end < start`, and zero is below every start.
        assert_eq!(mlock_range(u64::MAX - (PAGE - 1), PAGE, PAGE), Err(Errno::Einval));
        // Stopping one page short does not wrap.
        let top = u64::MAX - (2 * PAGE - 1);
        assert_eq!(mlock_range(top, PAGE, PAGE), Ok(Some((top, PAGE))));
    }

    /// mlockall's flag word: something must be requested, unknown bits are
    /// rejected, and ONFAULT alone qualifies nothing so it is EINVAL.
    /// # C: O(1)
    #[test]
    fn mlockall_flags_require_current_or_future() {
        assert_eq!(mlockall_flags_check(0), Err(Errno::Einval));
        assert_eq!(mlockall_flags_check(MCL_ONFAULT), Err(Errno::Einval));
        assert_eq!(mlockall_flags_check(8), Err(Errno::Einval));
        assert_eq!(mlockall_flags_check(MCL_CURRENT | 8), Err(Errno::Einval));
        assert_eq!(mlockall_flags_check(MCL_CURRENT), Ok((true, false, false)));
        assert_eq!(mlockall_flags_check(MCL_FUTURE), Ok((false, true, false)));
        assert_eq!(mlockall_flags_check(MCL_CURRENT | MCL_ONFAULT), Ok((true, false, true)));
        assert_eq!(mlockall_flags_check(MCL_FUTURE | MCL_ONFAULT), Ok((false, true, true)));
        assert_eq!(mlockall_flags_check(MCL_CURRENT | MCL_FUTURE | MCL_ONFAULT),
                   Ok((true, true, true)));
    }

    /// mlockall charges the ENTIRE mapped address space against the limit, and
    /// only when MCL_CURRENT is requested. A pure MCL_FUTURE call locks nothing
    /// now, so an address space far over the limit still installs the policy —
    /// charging it there would break the common
    /// `mlockall(MCL_FUTURE)`-then-allocate idiom. # C: O(1)
    #[test]
    fn mlockall_charges_the_whole_address_space_only_for_mcl_current() {
        assert_eq!(mlockall_admits(true, 8192, 8192, false), Ok(()));
        assert_eq!(mlockall_admits(true, 8193, 8192, false), Err(Errno::Enomem));
        assert_eq!(mlockall_admits(false, u64::MAX, 8192, false), Ok(()));
        assert_eq!(mlockall_admits(true, u64::MAX, 8192, true), Ok(()),
                   "CAP_IPC_LOCK bypasses the address-space charge");
    }

    /// EPERM precedes ENOMEM in mlockall exactly as in mlock: a zero limit
    /// without CAP_IPC_LOCK means "may not lock at all", reported before the
    /// size of the address space is even consulted. # C: O(1)
    #[test]
    fn mlockall_reports_eperm_before_enomem() {
        assert_eq!(mlockall_admits(true, u64::MAX, 0, false), Err(Errno::Eperm));
        assert_eq!(mlockall_admits(false, 0, 0, false), Err(Errno::Eperm));
        assert_eq!(mlockall_admits(true, u64::MAX, 0, true), Ok(()));
    }
}
