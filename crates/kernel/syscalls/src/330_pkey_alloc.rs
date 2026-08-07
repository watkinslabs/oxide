// 330 pkey_alloc — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use core::sync::atomic::Ordering;
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
    let abi = pkey::with_mm(pkey::ARCH, mm.pkeys().arch());
    let r = mm.pkeys().with_map(|map| pkey::pkey_alloc(&abi, map, args.a0, args.a1));
    let key = match r { Ok(key) => key, Err(e) => return errno(e) };
    let rights = pkey_access_rights(key as u16, args.a1);
    cur.pkey_rights.store(rights, Ordering::Relaxed);
    sched::pkey_rights::write_live(rights);
    key as i64
}

/// Apply `pkey_alloc`'s requested initial rights to the current task's live
/// user-writable register. # C: O(1)
#[cfg(target_arch = "x86_64")]
fn pkey_access_rights(pkey: u16, init: u64) -> u64 {
    hal_x86_64::pkru::pkru_set_pkey_access(sched::pkey_rights::read_live() as u32, pkey,
        init & pkey::PKEY_DISABLE_ACCESS != 0, init & pkey::PKEY_DISABLE_WRITE != 0) as u64
}

/// Apply `pkey_alloc`'s requested initial rights to the current task's live
/// user-writable register. # C: O(1)
#[cfg(target_arch = "aarch64")]
fn pkey_access_rights(pkey: u16, init: u64) -> u64 {
    hal_aarch64::por::por_set_pkey_access(sched::pkey_rights::read_live(), pkey,
        init & pkey::PKEY_DISABLE_ACCESS != 0, init & pkey::PKEY_DISABLE_WRITE != 0,
        init & pkey::PKEY_DISABLE_READ != 0, init & pkey::PKEY_DISABLE_EXECUTE != 0)
}
