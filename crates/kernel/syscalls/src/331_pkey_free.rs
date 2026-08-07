// 331 pkey_free — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;
use crate::pkey;

/// `pkey_free(pkey)` — slot 331 (arm64 290).
///
/// Linux `SYSCALL_DEFINE1(pkey_free)` is `mm_pkey_free` and nothing else: any
/// key not currently allocated in this mm is EINVAL. Which keys those are is
/// arch-specific — arm64 reserves key 0 in every mm and so accepts
/// `pkey_free(0)` once, x86 without OSPKE never has key 0 allocated because
/// the uninitialised `execute_only_pkey` is also 0. See `crate::pkey`.
/// # C: O(1)
/// # Lk: mm pkey map acquired
pub fn sys_pkey_free(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Einval) };
    // SAFETY: mm slot single-mutator per `13§5`; the Arc clone keeps this mm alive across the pkey-map update below.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return errno(Errno::Einval) };
    let abi = pkey::with_mm(pkey::ARCH, mm.pkeys().arch());
    let r = mm.pkeys().with_map(|map| pkey::pkey_free(&abi, map, args.a0 as i32));
    match r { Ok(()) => 0, Err(e) => errno(e) }
}
