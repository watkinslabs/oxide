// `sigset_t` ABI size and the `sigsetsize` argument rule every `rt_*` signal
// syscall shares. Owned here, in the ABI crate, so slots 13/14/127/128/130 and
// `ppoll`/`pselect6`/`epoll_pwait` cannot drift apart on it — the check is the
// only thing standing between a mismatched libc's sigset and an out-of-bounds
// user access. Linux: `kernel/signal.c`.

use crate::errno::Errno;

/// `sizeof(sigset_t)` — 8 on x86_64 and aarch64 alike: 64 signals, one bit
/// each, `signal N` at bit `N - 1`.
pub const SIGSET_BYTES: u64 = core::mem::size_of::<u64>() as u64;

/// The rule for syscalls that demand an EXACT match — `rt_sigaction`,
/// `rt_sigprocmask`, `rt_sigtimedwait`, `rt_sigsuspend`, `pselect6`, `ppoll`,
/// `epoll_pwait`: `if (sigsetsize != sizeof(sigset_t)) return -EINVAL;`.
/// # C: O(1)
pub fn check_exact(sigsetsize: u64) -> Result<u64, Errno> {
    if sigsetsize != SIGSET_BYTES { Err(Errno::Einval) } else { Ok(sigsetsize) }
}

/// The rule for `rt_sigpending`, which is deliberately LOOSER:
/// `if (sigsetsize > sizeof(*uset)) return -EINVAL;` — a smaller size is legal
/// and copies out only that many bytes. Using the exact rule here rejects a
/// call Linux accepts.
/// # C: O(1)
pub fn check_max(sigsetsize: u64) -> Result<u64, Errno> {
    if sigsetsize > SIGSET_BYTES { Err(Errno::Einval) } else { Ok(sigsetsize) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sigset_is_eight_bytes_on_every_supported_arch() {
        assert_eq!(SIGSET_BYTES, 8);
    }

    #[test]
    fn exact_rule_accepts_only_the_abi_size() {
        assert_eq!(check_exact(8), Ok(8));
        for bad in [0u64, 1, 4, 7, 9, 16, 128, u64::MAX] {
            assert_eq!(check_exact(bad), Err(Errno::Einval), "sigsetsize={bad}");
        }
    }

    #[test]
    fn max_rule_accepts_shorter_sizes_but_never_longer() {
        for ok in [0u64, 1, 4, 7, 8] { assert_eq!(check_max(ok), Ok(ok), "sigsetsize={ok}"); }
        for bad in [9u64, 16, 128, u64::MAX] {
            assert_eq!(check_max(bad), Err(Errno::Einval), "sigsetsize={bad}");
        }
    }

    #[test]
    fn the_two_rules_differ_exactly_below_the_abi_size() {
        for sz in 0..8u64 {
            assert_eq!(check_exact(sz), Err(Errno::Einval));
            assert_eq!(check_max(sz), Ok(sz));
        }
    }
}
