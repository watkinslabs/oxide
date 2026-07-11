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

const WAIT4_ALLOWED:  u64 = WNOHANG | WUNTRACED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL;
const WAITID_ALLOWED: u64 = WNOHANG | WNOWAIT | WEXITED | WSTOPPED | WCONTINUED | __WNOTHREAD | __WCLONE | __WALL;

/// # C: O(1)
pub const fn wait4_options_valid(options: u64) -> bool {
    (options & !WAIT4_ALLOWED) == 0
}

/// # C: O(1)
pub const fn waitid_options_valid(options: u64) -> bool {
    (options & !WAITID_ALLOWED) == 0 && (options & (WEXITED | WSTOPPED | WCONTINUED)) != 0
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
    fn waitid_requires_a_requested_event_class() {
        assert!(waitid_options_valid(WEXITED));
        assert!(waitid_options_valid(WSTOPPED | WNOWAIT | __WNOTHREAD));
        assert!(!waitid_options_valid(0));
        assert!(!waitid_options_valid(WNOHANG));
        assert!(!waitid_options_valid(WEXITED | (1u64 << 40)));
    }
}
