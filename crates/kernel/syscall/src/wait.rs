// wait(2) uapi constants and pure validators.

pub const WNOHANG:    u64 = 0x0000_0001;
pub const WUNTRACED:  u64 = 0x0000_0002;
pub const WSTOPPED:   u64 = WUNTRACED;
pub const WEXITED:    u64 = 0x0000_0004;
pub const WCONTINUED: u64 = 0x0000_0008;
pub const WNOWAIT:    u64 = 0x0100_0000;
pub const __WNOTHREAD:u64 = 0x2000_0000;
pub const __WALL:     u64 = 0x4000_0000;
pub const __WCLONE:   u64 = 0x8000_0000;

pub const P_ALL:   u64 = 0;
pub const P_PID:   u64 = 1;
pub const P_PGID:  u64 = 2;
pub const P_PIDFD: u64 = 3;

pub const CLD_EXITED:    i32 = 1;
pub const CLD_KILLED:    i32 = 2;
pub const CLD_STOPPED:   i32 = 5;
pub const CLD_CONTINUED: i32 = 6;
pub const SIGCONT:       i32 = 18;
pub const WSTAT_CONTINUED: i32 = 0xffff;

const WAIT4_ALLOWED:  u64 = WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL;
const WAITID_ALLOWED: u64 = WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL;

/// Truncate one argument register to the `int` the wait(2) family declares for
/// it (`wait4`'s `int options`, `waitid`'s `int which` / `int options`). Only
/// the low 32 bits carry the ABI value: a caller whose `int` was sign-extended
/// into the 64-bit register — glibc passes `__WCLONE` as a negative `int`, so
/// the register reads `0xffff_ffff_8000_0000` — is passing a valid option set,
/// not an unknown high bit, and must not be rejected for the extension.
/// # C: O(1)
pub const fn int_arg_from_reg(reg: u64) -> u64 { reg as u32 as u64 }

/// # C: O(1)
pub const fn wait4_options_valid(options: u64) -> bool {
    (options & !WAIT4_ALLOWED) == 0
}

/// # C: O(1)
pub const fn waitid_options_valid(options: u64) -> bool {
    (options & !WAITID_ALLOWED) == 0 && (options & (WEXITED | WSTOPPED | WCONTINUED)) != 0
}

/// # C: O(1)
pub const fn waitid_code_status_from_wstat(wstat: i32) -> (i32, i32) {
    if wstat == WSTAT_CONTINUED {
        (CLD_CONTINUED, SIGCONT)
    } else if (wstat & 0x7f) == 0 {
        (CLD_EXITED, (wstat >> 8) & 0xff)
    } else if (wstat & 0xff) == 0x7f {
        (CLD_STOPPED, (wstat >> 8) & 0xff)
    } else {
        (CLD_KILLED, wstat & 0x7f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wait4_rejects_waitid_only_and_unknown_bits() {
        assert!(wait4_options_valid(WNOHANG | WUNTRACED | WCONTINUED | __WALL));
        assert!(!wait4_options_valid(WEXITED));
        assert!(!wait4_options_valid(WNOWAIT));
        assert!(!wait4_options_valid(1u64 << 40));
    }

    #[test]
    fn a_sign_extended_int_option_set_survives_register_truncation() {
        // glibc's `waitpid(pid, &st, __WCLONE)` reaches the kernel as a
        // sign-extended negative int; the high half is not part of the value.
        let reg = 0xffff_ffff_8000_0000u64;
        assert_eq!(int_arg_from_reg(reg), __WCLONE);
        assert!(wait4_options_valid(int_arg_from_reg(reg)));
        assert!(!wait4_options_valid(reg));
        assert!(waitid_options_valid(int_arg_from_reg(reg | WEXITED)));
        assert_eq!(int_arg_from_reg(0xdead_beef_0000_0001), P_PID);
    }

    #[test]
    fn waitid_requires_a_requested_event_class() {
        assert!(waitid_options_valid(WEXITED));
        assert!(waitid_options_valid(WSTOPPED | WNOWAIT | __WNOTHREAD));
        assert!(!waitid_options_valid(0));
        assert!(!waitid_options_valid(WNOHANG));
        assert!(!waitid_options_valid(WEXITED | (1u64 << 40)));
    }

    #[test]
    fn waitid_decodes_continued_separately_from_signaled() {
        assert_eq!(waitid_code_status_from_wstat(WSTAT_CONTINUED), (CLD_CONTINUED, SIGCONT));
        assert_eq!(waitid_code_status_from_wstat(7 << 8), (CLD_EXITED, 7));
        assert_eq!(waitid_code_status_from_wstat((19 << 8) | 0x7f), (CLD_STOPPED, 19));
        assert_eq!(waitid_code_status_from_wstat(9), (CLD_KILLED, 9));
    }
}
