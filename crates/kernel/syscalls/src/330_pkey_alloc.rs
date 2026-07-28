// 330 pkey_alloc — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::misc::misc_common::errno;
use crate::pkey;

/// `pkey_alloc(flags, access_rights)` — slot 330 (arm64 289).
///
/// Linux `mm/mprotect.c` `SYSCALL_DEFINE2(pkey_alloc)` validates first and
/// allocates second: non-zero `flags` -> EINVAL, `init_val` outside the arch's
/// `PKEY_ACCESS_MASK` -> EINVAL, then `mm_pkey_alloc` -> ENOSPC when no key is
/// free, then `arch_set_user_pkey_access`. The syscalls are compiled in on
/// both arches unconditionally (`X86_INTEL_MEMORY_PROTECTION_KEYS` and
/// `ARM64_POE` are `def_bool y` and both `select ARCH_HAS_PKEYS`), so a CPU
/// without the hardware feature does NOT yield ENOSYS. What it yields differs
/// per arch — see `crate::pkey` for the derivation and the B1434 correction.
/// Handing back a key we cannot enforce (no PKRU, no POR_EL0, no per-PTE key
/// bits) would be an in-process isolation lie.
/// # C: O(1)
/// # Lk: mm pkey map acquired
pub fn sys_pkey_alloc(args: &SyscallArgs) -> i64 {
    let cur = match sched::live::current() { Some(c) => c, None => return errno(Errno::Einval) };
    // SAFETY: mm slot single-mutator per `13§5`; the Arc clone keeps this mm alive across the pkey-map update below.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return errno(Errno::Einval) };
    let r = mm.pkeys().with_map(|map| pkey::pkey_alloc(&pkey::ARCH, map, args.a0, args.a1));
    match r { Ok(key) => key as i64, Err(e) => errno(e) }
}
