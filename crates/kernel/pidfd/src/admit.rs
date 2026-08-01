// `pidfd_open(2)` argument admission: the flag mask and the pid screen that
// precede every lookup. Ungated on purpose — `434_pidfd_open.rs` is
// `#![cfg(target_os = "oxide-kernel")]`, so a `#[cfg(test)]` block inside it
// compiles out silently (CLAUDE.md phantom-test rule) and these two decisions
// have never been covered. The slot file keeps only parse/call/encode.

use syscall::errno::Errno;

use crate::open::OpenOptions;

/// `PIDFD_NONBLOCK` — the pidfd UAPI reuses the `O_NONBLOCK` bit, and the value
/// is taken from the typed open-flag set so the descriptor the syscall installs
/// and the flag it admits cannot drift apart.
pub const PIDFD_NONBLOCK: u32 = vfs::OpenFlags::O_NONBLOCK.bits();
/// `PIDFD_THREAD` — the `O_EXCL` bit, likewise retained on the open file
/// description and read back by `waitid(P_PIDFD)` and `pidfd_send_signal`.
pub const PIDFD_THREAD: u32 = vfs::OpenFlags::O_EXCL.bits();
/// Every flag `pidfd_open` accepts.
pub const PIDFD_OPEN_FLAGS: u32 = PIDFD_NONBLOCK | PIDFD_THREAD;

/// `SYSCALL_DEFINE2(pidfd_open, pid_t pid, unsigned int flags)`: an unknown flag
/// bit is EINVAL, then a non-positive pid is EINVAL, and only then does a
/// lookup happen. Both arguments narrow to their declared C widths FIRST — the
/// prototype discards the high half of each register, so a caller that leaves
/// junk above bit 31 gets the same answer as one that zeroes it.
/// # C: O(1)
pub fn admit(pid_arg: u64, flags_arg: u64) -> Result<(u32, OpenOptions), Errno> {
    let flags = flags_arg as u32;
    if flags & !PIDFD_OPEN_FLAGS != 0 { return Err(Errno::Einval); }
    let pid = pid_arg as i32;
    if pid <= 0 { return Err(Errno::Einval); }
    Ok((pid as u32, OpenOptions {
        nonblock: flags & PIDFD_NONBLOCK != 0,
        thread:   flags & PIDFD_THREAD != 0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    // The two bits are UAPI numbers, not merely "whatever the open-flag set
    // happens to hold": pin them so a change to `OpenFlags` cannot silently
    // move the pidfd ABI.
    #[test]
    fn the_two_flag_bits_are_the_published_uapi_values() {
        assert_eq!(PIDFD_NONBLOCK, 0o4000);
        assert_eq!(PIDFD_THREAD, 0o200);
        assert_eq!(PIDFD_OPEN_FLAGS, 0o4200);
    }

    #[test]
    fn unknown_flag_bits_are_einval_and_the_pair_selects_the_open_options() {
        assert_eq!(admit(1, 0), Ok((1, OpenOptions { nonblock: false, thread: false })));
        assert_eq!(admit(1, PIDFD_NONBLOCK as u64),
            Ok((1, OpenOptions { nonblock: true, thread: false })));
        assert_eq!(admit(1, PIDFD_THREAD as u64),
            Ok((1, OpenOptions { nonblock: false, thread: true })));
        assert_eq!(admit(1, PIDFD_OPEN_FLAGS as u64),
            Ok((1, OpenOptions { nonblock: true, thread: true })));
        assert_eq!(admit(1, 1), Err(Errno::Einval));
        assert_eq!(admit(1, (PIDFD_OPEN_FLAGS | 1) as u64), Err(Errno::Einval));
        assert_eq!(admit(1, u32::MAX as u64), Err(Errno::Einval));
    }

    // A pid of 0 or below never reaches a lookup. This is the whole answer to a
    // desktop session in which one authorization daemon re-issued
    // `pidfd_open(0, 0)` hundreds of times: the reference rejects it the same
    // way, and the caller's own fallback path is what the EINVAL selects.
    #[test]
    fn a_non_positive_pid_is_einval_before_any_lookup() {
        assert_eq!(admit(0, 0), Err(Errno::Einval));
        assert_eq!(admit(-1i64 as u64, 0), Err(Errno::Einval));
        assert_eq!(admit(i32::MIN as i64 as u64, 0), Err(Errno::Einval));
        assert_eq!(admit(i32::MAX as u64, 0).unwrap().0, i32::MAX as u32);
    }

    // `pid_t` and `unsigned int` are 32 bits: the high half of either register
    // is discarded before the checks, so a garbage high word neither invents an
    // unknown flag nor turns a valid pid into a rejected one.
    #[test]
    fn both_arguments_narrow_to_their_c_widths_before_the_checks() {
        assert_eq!(admit(1, 1u64 << 32), Ok((1, OpenOptions::default())));
        assert_eq!(admit(1, (1u64 << 32) | PIDFD_THREAD as u64),
            Ok((1, OpenOptions { nonblock: false, thread: true })));
        assert_eq!(admit((1u64 << 32) | 7, 0).unwrap().0, 7);
        // Narrowing can also expose a rejection: a value positive as 64 bits
        // whose low word is negative is a negative `pid_t`.
        assert_eq!(admit(0x8000_0000, 0), Err(Errno::Einval));
        // ...and one that narrows to zero.
        assert_eq!(admit(1u64 << 32, 0), Err(Errno::Einval));
    }
}
