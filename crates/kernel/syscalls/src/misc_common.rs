// misc_common — shared helpers for the misc per-syscall modules
// (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

/// # C: O(1)
pub(crate) fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

