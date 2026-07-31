// `prctl(PR_GET_AUXV, addr, len)` — Linux `kernel/sys.c prctl_get_auxv`.
//
// Reports the auxiliary vector this process was exec'd with, from the copy
// the kernel keeps in the mm (Linux `mm_struct::saved_auxv`), which is also
// what `/proc/<pid>/auxv` serves. CRIU and any runtime that lost its stack
// auxv (a re-exec'd interpreter, a thread with no access to the initial SP)
// reads it this way.
//
// UNGATED: the truncate/return-value rule is the whole contract. Linux
// returns the FULL `sizeof(mm->saved_auxv)` regardless of how much it copied,
// so a caller that passed a short buffer learns the size it needs. Returning
// the copied length instead makes every "probe with len=0, then allocate"
// caller allocate nothing.

use syscall::errno::Errno;

/// The array size is owned by the mm, which is where `saved_auxv` lives and
/// what `PR_SET_MM_AUXV` overwrites; re-deriving it here would be a second
/// source of truth for `PR_GET_AUXV`'s return value.
pub use vmm::SAVED_AUXV_BYTES;

/// How much of the saved vector `PR_GET_AUXV` copies out, and what it
/// returns. `None` means "copy nothing" — a `len` of zero is NOT an error,
/// it is the size probe.
/// # C: O(1)
pub fn copy_plan(len: u64) -> (usize, i64) {
    let size = core::cmp::min(SAVED_AUXV_BYTES as u64, len) as usize;
    (size, SAVED_AUXV_BYTES as i64)
}

/// `if (arg4 || arg5) return -EINVAL;` — the tail rule `kernel/sys.c` applies
/// before calling the helper. arg2 (the buffer) and arg3 (its length) are
/// unrestricted; a bad buffer is EFAULT from the copy, not EINVAL.
/// # C: O(1)
pub fn validate_tail(a4: u64, a5: u64) -> Result<(), Errno> {
    if a4 != 0 || a5 != 0 { Err(Errno::Einval) } else { Ok(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tail_arguments_must_be_zero_but_buffer_and_length_are_free() {
        assert_eq!(validate_tail(0, 0), Ok(()));
        assert_eq!(validate_tail(1, 0), Err(Errno::Einval));
        assert_eq!(validate_tail(0, 1), Err(Errno::Einval));
    }

    #[test]
    fn return_value_is_the_full_size_even_for_a_short_or_empty_buffer() {
        let full = SAVED_AUXV_BYTES as i64;
        assert_eq!(copy_plan(0), (0, full), "len 0 is the size probe, not an error");
        assert_eq!(copy_plan(16), (16, full));
        assert_eq!(copy_plan(SAVED_AUXV_BYTES as u64), (SAVED_AUXV_BYTES, full));
        assert_eq!(copy_plan(u64::MAX), (SAVED_AUXV_BYTES, full),
                   "an oversized request is truncated, never over-copied");
    }

}
