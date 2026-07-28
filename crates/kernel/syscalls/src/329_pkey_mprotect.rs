// 329 pkey_mprotect — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;
use crate::pkey;

/// `pkey_mprotect(addr, len, prot, pkey)` — slot 329 (arm64 288).
///
/// Linux `do_mprotect_pkey`: `pkey != -1 && !mm_pkey_is_allocated(mm, pkey)`
/// -> EINVAL, checked before any VMA walk so a bad key never partially
/// applies. Which keys are allocated is arch- and mm-specific (see
/// `crate::pkey`): arm64 reserves key 0 in every mm, x86 without OSPKE does
/// not. `-1` is "keep the current key" and is plain mprotect everywhere.
/// # C: O(1) + mprotect cost
/// # Lk: mm pkey map acquired
pub fn sys_pkey_mprotect(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Einval) };
    // SAFETY: mm slot single-mutator per `13§5`; the Arc clone keeps this mm alive across the pkey-map read below.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return errno(Errno::Einval) };
    let map = mm.pkeys().with_map(|m| *m);
    if pkey::pkey_mprotect_allows(&pkey::ARCH, map, args.a3 as i32) { crate::s010_mprotect::sys_mprotect(args) }
    else { errno(Errno::Einval) }
}
