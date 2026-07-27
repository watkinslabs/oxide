// 330 pkey_alloc — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;
use crate::pkey::pkey_alloc_check;

/// `pkey_alloc(flags, access_rights)` — slot 330.
///
/// Linux (`mm/mprotect.c` `SYSCALL_DEFINE2(pkey_alloc)`) validates first and
/// allocates second:
///   1. any non-zero `flags` -> EINVAL (no flags are defined yet)
///   2. `init_val` outside `PKEY_ACCESS_MASK` -> EINVAL
///   3. `mm_pkey_alloc` -> ENOSPC when no key is free
///
/// On x86_64 these syscalls are compiled in unconditionally
/// (`CONFIG_ARCH_HAS_PKEYS`), so a CPU without `X86_FEATURE_OSPKE` does NOT
/// yield ENOSYS: `arch_max_pkey()` is 1, pkey 0 is allocated implicitly when
/// the mm is created, so the allocation map is already full and step 3 gives
/// ENOSPC. We have no PKU/PKRU enforcement (no CR4.PKE, no per-PTE key bits),
/// which is exactly that CPU, so ENOSPC is the truthful answer — handing back
/// a key we cannot enforce would be an in-process isolation lie, and ENOSYS
/// both misreports the reason and skips the argument validation callers rely
/// on to distinguish "bad request" from "no keys available".
/// # C: O(1)
pub fn sys_pkey_alloc(args: &SyscallArgs) -> i64 {
    match pkey_alloc_check(args.a0, args.a1) {
        Ok(key) => key as i64,
        Err(e)  => errno(e),
    }
}
