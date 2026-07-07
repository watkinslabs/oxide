// 331 pkey_free — one syscall, one file (docs/53 §0). Moved verbatim from misc.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// `pkey_free(pkey)` — slot 331. No PKU support (see pkey_alloc), so no key was
/// ever allocatable; Linux w/o X86_FEATURE_OSPKE returns ENOSYS.
/// # C: O(1)
pub fn sys_pkey_free(_args: &SyscallArgs) -> i64 { errno(Errno::Enosys) }
