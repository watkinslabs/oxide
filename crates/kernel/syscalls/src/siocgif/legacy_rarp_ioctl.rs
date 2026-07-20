// Legacy RARP ABI shim — Linux imports native ifreq before its terminal ENOTTY.

use syscall::errno::Errno;

/// Preserve Linux's post-ifreq-import terminal result for unimplemented RARP ioctls. # C: O(1)
pub(super) fn handle(arg: u64) -> i64 {
    if super::read_ifreq(arg).is_none() { return -(Errno::Efault.as_i32() as i64); }
    -(Errno::Enotty.as_i32() as i64)
}
