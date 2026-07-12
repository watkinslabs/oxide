// Linux internal syscall-restart return codes. These are not errno values and
// must never escape to userspace.

use crate::Errno;

/// Linux `ERESTARTNOHAND`: restart if no user handler ran; otherwise surface
/// EINTR. Oxide currently normalizes at the syscall boundary because restart-
/// PC rewind is not a userspace-visible ABI value.
pub const ERESTARTNOHAND: i64 = 514;

/// Encode an internal restart code as a negative syscall return.
/// # C: O(1)
pub const fn restart_nohand() -> i64 { -ERESTARTNOHAND }

/// Convert internal restart codes to the userspace-visible Linux errno.
/// # C: O(1)
pub const fn normalize_user_return(rv: i64) -> i64 {
    if rv == restart_nohand() { -(Errno::Eintr.as_i32() as i64) } else { rv }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_nohand_normalizes_to_eintr() {
        assert_eq!(restart_nohand(), -514);
        assert_eq!(normalize_user_return(restart_nohand()), -(Errno::Eintr.as_i32() as i64));
        assert_eq!(normalize_user_return(-22), -22);
        assert_eq!(normalize_user_return(0), 0);
    }
}
