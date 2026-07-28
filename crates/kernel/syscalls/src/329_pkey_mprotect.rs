// 329 pkey_mprotect — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `pkey_mprotect(addr, len, prot, pkey)` — slot 329 (arm64 288).
///
/// Linux `SYSCALL_DEFINE4(pkey_mprotect)` is `do_mprotect_pkey(start, len,
/// prot, pkey)` verbatim — the SAME body `mprotect` calls with `-1`. Sharing
/// `crate::s010_mprotect::do_mprotect_pkey` keeps the argument-validation
/// ORDER identical for both entry points: address/length/prot first, the
/// `mm_pkey_is_allocated` refusal after. Which keys are allocated is arch- and
/// mm-specific (see `crate::pkey`): arm64 reserves key 0 in every mm, x86
/// without OSPKE does not.
/// # C: O(len / PAGE_SIZE)
pub fn sys_pkey_mprotect(args: &SyscallArgs) -> i64 {
    crate::s010_mprotect::do_mprotect_pkey(args, args.a3 as i32)
}
