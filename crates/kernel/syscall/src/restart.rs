// Linux internal syscall-restart return codes. These are not errno values and
// must never escape to userspace.

use crate::Errno;

/// Linux `ERESTARTNOHAND`: restart if no user handler ran; otherwise surface
/// EINTR. Oxide currently normalizes at the syscall boundary because restart-
/// PC rewind is not a userspace-visible ABI value.
pub const ERESTARTNOHAND: i64 = 514;
/// Linux `ERESTARTSYS`: restart a signal-interrupted blocking syscall only
/// when the delivered handler opted into `SA_RESTART`; otherwise expose EINTR.
pub const ERESTARTSYS: i64 = 512;
/// Linux `ERESTART_RESTARTBLOCK`: restart through `restart_syscall(2)` when
/// signal handling permits it; otherwise userspace observes `EINTR`.
pub const ERESTART_RESTARTBLOCK: i64 = 516;

/// Encode an internal restart code as a negative syscall return.
/// # C: O(1)
pub const fn restart_nohand() -> i64 { -ERESTARTNOHAND }

/// Encode Linux's handler-controlled restart request. # C: O(1)
pub const fn restart_sys() -> i64 { -ERESTARTSYS }

/// Encode an internal restart-block return.
/// # C: O(1)
pub const fn restart_block() -> i64 { -ERESTART_RESTARTBLOCK }

/// Convert internal restart codes to the userspace-visible Linux errno.
/// # C: O(1)
pub const fn normalize_user_return(rv: i64) -> i64 {
    if rv == restart_sys() || rv == restart_nohand() || rv == restart_block() {
        -(Errno::Eintr.as_i32() as i64)
    } else {
        rv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn restart_nohand_normalizes_to_eintr() {
        assert_eq!(restart_nohand(), -514);
        assert_eq!(restart_sys(), -512);
        assert_eq!(normalize_user_return(restart_sys()), -(Errno::Eintr.as_i32() as i64));
        assert_eq!(normalize_user_return(restart_nohand()), -(Errno::Eintr.as_i32() as i64));
        assert_eq!(restart_block(), -516);
        assert_eq!(normalize_user_return(restart_block()), -(Errno::Eintr.as_i32() as i64));
        assert_eq!(normalize_user_return(-22), -22);
        assert_eq!(normalize_user_return(0), 0);
    }
}
