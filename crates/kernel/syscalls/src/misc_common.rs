// misc_common — shared helpers for the misc per-syscall modules
// (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

pub(crate) const MPOL_DEFAULT:    u32 = 0;
pub(crate) const MPOL_PREFERRED:  u32 = 1;
pub(crate) const MPOL_BIND:       u32 = 2;
pub(crate) const MPOL_INTERLEAVE: u32 = 3;
pub(crate) const MPOL_LOCAL:      u32 = 4;

/// # C: O(1)
pub(crate) fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// Per-process pkey bitmap. Linux MPK has 16 keys; key 0 is the
/// always-permitted default. Allocation tracked as a 16-bit
/// bitmap so glibc/musl probes get unique ids; PKRU enforcement
/// is a follow-up.
pub(crate) static PKEY_BITMAP: core::sync::atomic::AtomicU16
    = core::sync::atomic::AtomicU16::new(1);
