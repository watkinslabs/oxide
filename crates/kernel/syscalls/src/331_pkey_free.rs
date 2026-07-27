// 331 pkey_free — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;

/// `pkey_free(pkey)` — slot 331.
///
/// Linux `mm_pkey_free` rejects any key that is not currently allocated with
/// EINVAL. Without `X86_FEATURE_OSPKE` `arch_max_pkey()` is 1, so no key is
/// ever allocatable through `pkey_alloc` (see slot 330) and every argument —
/// including 0, which is the implicitly-allocated default key and is likewise
/// refused by `mm_pkey_is_allocated` for the user interfaces — is invalid.
/// EINVAL, not ENOSYS: the syscall exists on x86_64 regardless of OSPKE.
/// # C: O(1)
pub fn sys_pkey_free(_args: &SyscallArgs) -> i64 { errno(Errno::Einval) }
