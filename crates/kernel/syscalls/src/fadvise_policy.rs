// fadvise64(2) slot 221 — POSIX_FADV_* constants and the `generic_fadvise`
// admission ladder (Linux `mm/fadvise.c`).
//
// Order is the whole observable contract for a hint syscall whose successful
// effect is invisible, so it lives outside the kernel-gated slot file where the
// hosted suite can assert it (CLAUDE.md phantom-test rule, docs/53).
//
//   ksys_fadvise64_64: fd_empty(f)                       -> EBADF
//   generic_fadvise:   S_ISFIFO(inode)                   -> ESPIPE
//                      !mapping || len < 0 || offset < 0 -> EINVAL
//                      advice not in the six             -> EINVAL
//
// ESPIPE precedes the negative-length EINVAL: `fadvise64(pipefd, 0, -1, 0)` is
// ESPIPE on Linux, not EINVAL.

use syscall::errno::Errno;

/// `POSIX_FADV_NORMAL` (`include/uapi/linux/fadvise.h`).
pub const POSIX_FADV_NORMAL:     i32 = 0;
/// `POSIX_FADV_RANDOM`.
pub const POSIX_FADV_RANDOM:     i32 = 1;
/// `POSIX_FADV_SEQUENTIAL`.
pub const POSIX_FADV_SEQUENTIAL: i32 = 2;
/// `POSIX_FADV_WILLNEED`.
pub const POSIX_FADV_WILLNEED:   i32 = 3;
/// `POSIX_FADV_DONTNEED`.
pub const POSIX_FADV_DONTNEED:   i32 = 4;
/// `POSIX_FADV_NOREUSE`.
pub const POSIX_FADV_NOREUSE:    i32 = 5;

/// True for the six advice values `generic_fadvise` accepts. Every other value
/// — including the s390-only `POSIX_FADV_DONTNEED`/`NOREUSE` renumbering, which
/// x86_64 and aarch64 do not use — is EINVAL.
/// # C: O(1)
pub fn advice_known(advice: i32) -> bool {
    matches!(advice, POSIX_FADV_NORMAL | POSIX_FADV_RANDOM | POSIX_FADV_SEQUENTIAL
        | POSIX_FADV_WILLNEED | POSIX_FADV_DONTNEED | POSIX_FADV_NOREUSE)
}

/// True for the advice values that set persistent per-file readahead STATE
/// (`f_ra.ra_pages`, `FMODE_RANDOM`, `FMODE_NOREUSE`) rather than acting on
/// page-cache residency. Separated so the slot file records the state Linux
/// records and treats only the residency hints as advisory.
/// # C: O(1)
pub fn advice_sets_readahead_state(advice: i32) -> bool {
    matches!(advice, POSIX_FADV_NORMAL | POSIX_FADV_RANDOM | POSIX_FADV_SEQUENTIAL | POSIX_FADV_NOREUSE)
}

/// `generic_fadvise` argument admission, once the fd has resolved. `is_fifo`
/// is `S_ISFIFO(file_inode(file)->i_mode)`; `has_mapping` is `file->f_mapping`.
/// # C: O(1)
pub fn fadvise_check(is_fifo: bool, has_mapping: bool, offset: i64, len: i64, advice: i32)
    -> Result<(), Errno>
{
    if is_fifo { return Err(Errno::Espipe); }
    if !has_mapping || len < 0 || offset < 0 { return Err(Errno::Einval); }
    if !advice_known(advice) { return Err(Errno::Einval); }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// All six documented advice values are accepted; the neighbours of the
    /// range are not. A `0..=5` range check written as `0..=6` would let
    /// through a value Linux rejects. # C: O(1)
    #[test]
    fn exactly_six_advice_values() {
        for a in [POSIX_FADV_NORMAL, POSIX_FADV_RANDOM, POSIX_FADV_SEQUENTIAL,
                  POSIX_FADV_WILLNEED, POSIX_FADV_DONTNEED, POSIX_FADV_NOREUSE] {
            assert!(advice_known(a), "advice {a}");
        }
        for a in [i32::MIN, -1, 6, 7, 100, i32::MAX] { assert!(!advice_known(a), "advice {a}"); }
    }

    /// A pipe is ESPIPE BEFORE the negative-length EINVAL — the ordering that
    /// distinguishes "wrong kind of fd" from "wrong arguments", and the one a
    /// naive validate-args-first shim gets backwards. # C: O(1)
    #[test]
    fn fifo_espipe_precedes_argument_einval() {
        assert_eq!(fadvise_check(true, true, 0, -1, POSIX_FADV_NORMAL), Err(Errno::Espipe));
        assert_eq!(fadvise_check(true, true, -1, 0, POSIX_FADV_NORMAL), Err(Errno::Espipe));
        assert_eq!(fadvise_check(true, true, 0, 0, 99),                 Err(Errno::Espipe));
        assert_eq!(fadvise_check(true, false, 0, 0, POSIX_FADV_NORMAL), Err(Errno::Espipe));
    }

    /// Negative offset or length is EINVAL, and it is checked BEFORE the advice
    /// value — so a call that is wrong in both ways reports EINVAL either way,
    /// but a valid-argument call with bad advice still reaches the advice arm.
    /// # C: O(1)
    #[test]
    fn negative_offset_or_len_is_einval() {
        assert_eq!(fadvise_check(false, true, 0, -1, POSIX_FADV_NORMAL), Err(Errno::Einval));
        assert_eq!(fadvise_check(false, true, -1, 0, POSIX_FADV_NORMAL), Err(Errno::Einval));
        assert_eq!(fadvise_check(false, true, i64::MIN, 0, POSIX_FADV_NORMAL), Err(Errno::Einval));
        assert_eq!(fadvise_check(false, false, 0, 0, POSIX_FADV_NORMAL), Err(Errno::Einval));
    }

    /// `len == 0` means "to end of file", not an error, and a huge offset+len
    /// pair is accepted (Linux clamps the endbyte rather than rejecting).
    /// # C: O(1)
    #[test]
    fn zero_len_and_huge_range_are_accepted() {
        assert_eq!(fadvise_check(false, true, 0, 0, POSIX_FADV_DONTNEED), Ok(()));
        assert_eq!(fadvise_check(false, true, i64::MAX, i64::MAX, POSIX_FADV_WILLNEED), Ok(()));
    }

    /// A bad advice value on otherwise-valid arguments is EINVAL. # C: O(1)
    #[test]
    fn unknown_advice_is_einval() {
        assert_eq!(fadvise_check(false, true, 0, 0, 6), Err(Errno::Einval));
        assert_eq!(fadvise_check(false, true, 0, 0, -1), Err(Errno::Einval));
    }

    /// The four state-setting hints are exactly the ones Linux records on the
    /// file; WILLNEED and DONTNEED act on residency instead. # C: O(1)
    #[test]
    fn readahead_state_hints_are_the_four_linux_records() {
        for a in [POSIX_FADV_NORMAL, POSIX_FADV_RANDOM, POSIX_FADV_SEQUENTIAL, POSIX_FADV_NOREUSE] {
            assert!(advice_sets_readahead_state(a), "advice {a}");
        }
        for a in [POSIX_FADV_WILLNEED, POSIX_FADV_DONTNEED] {
            assert!(!advice_sets_readahead_state(a), "advice {a}");
        }
    }
}
