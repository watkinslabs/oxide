// `SECCOMP_SET_MODE_FILTER` flag bits + the validation ladder
// `seccomp_set_mode_filter` (`kernel/seccomp.c`) runs before it touches
// anything else.
//
// UNGATED on purpose (`CLAUDE.md` phantom-test rule): the decision lives
// here so `#[cfg(test)]` below actually compiles and runs.

use syscall::errno::Errno;

/// `include/uapi/linux/seccomp.h`.
pub const SECCOMP_FILTER_FLAG_TSYNC:              u64 = 1 << 0;
pub const SECCOMP_FILTER_FLAG_LOG:                u64 = 1 << 1;
pub const SECCOMP_FILTER_FLAG_SPEC_ALLOW:         u64 = 1 << 2;
pub const SECCOMP_FILTER_FLAG_NEW_LISTENER:       u64 = 1 << 3;
pub const SECCOMP_FILTER_FLAG_TSYNC_ESRCH:        u64 = 1 << 4;
pub const SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV: u64 = 1 << 5;

/// `SECCOMP_FILTER_FLAG_MASK` — every bit outside it is EINVAL.
pub const SECCOMP_FILTER_FLAG_MASK: u64 =
      SECCOMP_FILTER_FLAG_TSYNC
    | SECCOMP_FILTER_FLAG_LOG
    | SECCOMP_FILTER_FLAG_SPEC_ALLOW
    | SECCOMP_FILTER_FLAG_NEW_LISTENER
    | SECCOMP_FILTER_FLAG_TSYNC_ESRCH
    | SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV;

/// The three flag rules at the head of `seccomp_set_mode_filter`, in Linux's
/// order — they run BEFORE the `sock_fprog` is copied in, so a bad flag word
/// reports EINVAL even when the filter pointer is garbage.
///
/// 1. any bit outside `SECCOMP_FILTER_FLAG_MASK`
/// 2. `TSYNC | NEW_LISTENER` without `TSYNC_ESRCH` — the two use the return
///    value for different things and could not be told apart on failure
/// 3. `WAIT_KILLABLE_RECV` without `NEW_LISTENER` — nothing to wait on
/// # C: O(1)
pub fn validate_filter_flags(flags: u64) -> Result<(), Errno> {
    if flags & !SECCOMP_FILTER_FLAG_MASK != 0 { return Err(Errno::Einval); }
    if flags & SECCOMP_FILTER_FLAG_TSYNC != 0
        && flags & SECCOMP_FILTER_FLAG_NEW_LISTENER != 0
        && flags & SECCOMP_FILTER_FLAG_TSYNC_ESRCH == 0 { return Err(Errno::Einval); }
    if flags & SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV != 0
        && flags & SECCOMP_FILTER_FLAG_NEW_LISTENER == 0 { return Err(Errno::Einval); }
    Ok(())
}

/// `do_seccomp`'s per-op flag rule: every op except `SET_MODE_FILTER`
/// requires `flags == 0`, and `SET_MODE_STRICT` additionally requires
/// `uargs == NULL`.
/// # C: O(1)
pub fn validate_op_flags(op: u64, flags: u64, uargs: u64) -> Result<(), Errno> {
    use super::uapi::*;
    match op {
        SECCOMP_SET_MODE_STRICT => {
            if flags != 0 || uargs != 0 { return Err(Errno::Einval); }
            Ok(())
        }
        SECCOMP_SET_MODE_FILTER => validate_filter_flags(flags),
        SECCOMP_GET_ACTION_AVAIL | SECCOMP_GET_NOTIF_SIZES => {
            if flags != 0 { return Err(Errno::Einval); }
            Ok(())
        }
        _ => Err(Errno::Einval),
    }
}
