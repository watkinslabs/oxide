// Memory-protection-key syscall bodies — `mm/mprotect.c`
// `SYSCALL_DEFINE2(pkey_alloc)`, `SYSCALL_DEFINE1(pkey_free)`, and the pkey
// admission clause of `do_mprotect_pkey`. Shared by slots 329/330/331.
//
// The per-mm allocation map and the `mm_pkey_*` helpers live with the mm
// (`vmm::pkeys`, mirroring `asm/pkeys.h`); this module owns only what
// `mm/mprotect.c` owns — the UAPI masks and the validation ORDER.
//
// **B1479 corrects B1434.** B1434 replaced an ENOSYS strawman with a flat
// ENOSPC on both arches, reasoning that "pkey 0 is allocated implicitly when
// the mm is created, so the allocation map is already full". True on arm64,
// false on x86_64: `arch/x86/include/asm/mmu_context.h` `init_new_context`
// sets `pkey_allocation_map = 0x1` *inside*
// `if (cpu_feature_enabled(X86_FEATURE_OSPKE))`, so on a CPU without OSPKE the
// map starts empty, `mm_pkey_alloc` hands out key 0, and the syscall fails one
// step later in `arch_set_user_pkey_access` (`arch/x86/kernel/fpu/xstate.c`,
// `if (!cpu_feature_enabled(X86_FEATURE_OSPKE)) return -EINVAL`). The rollback
// `mm_pkey_free` then fails too — key 0 equals the uninitialised
// `execute_only_pkey`, so `mm_pkey_is_allocated` refuses it — leaving the bit
// set. Hence x86_64: **EINVAL once per mm, ENOSPC forever after**; aarch64:
// ENOSPC from the first call, because its `mm_pkey_alloc` opens with an
// `arch_pkeys_enabled()` guard that x86's lacks.
//
// Ungated on purpose: the slot files are `#![cfg(target_os = "oxide-kernel")]`
// and cannot be exercised hosted, which would leave the errno ordering — the
// whole point of this module — untested.

use syscall::errno::Errno;
use vmm::pkeys::{self, PkeyArch};

/// `PKEY_DISABLE_ACCESS` (`uapi/asm-generic/mman-common.h`), both arches.
pub const PKEY_DISABLE_ACCESS: u64 = 0x1;
/// `PKEY_DISABLE_WRITE`, both arches.
pub const PKEY_DISABLE_WRITE: u64 = 0x2;
/// `PKEY_DISABLE_EXECUTE` — aarch64 only (`arch/arm64/include/uapi/asm/mman.h`).
pub const PKEY_DISABLE_EXECUTE: u64 = 0x4;
/// `PKEY_DISABLE_READ` — aarch64 only. POE can revoke read; PKRU cannot
/// express read-without-access, so x86 defines no such bit and rejects it.
pub const PKEY_DISABLE_READ: u64 = 0x8;

/// "Keep the current key" sentinel accepted by `pkey_mprotect`.
pub const PKEY_KEEP: i32 = -1;

/// The `mm/mprotect.c`-side per-arch facts: the `PKEY_ACCESS_MASK` `init_val`
/// is validated against, and the errno `arch_set_user_pkey_access` returns
/// when the hardware feature is absent.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PkeyAbi {
    /// `PKEY_ACCESS_MASK` — the only bits `init_val` may carry.
    pub access_mask: u64,
    /// `arch_set_user_pkey_access` with the hardware feature off: x86 returns
    /// `-EINVAL`, arm64 (`arch/arm64/mm/mmu.c`) returns `-ENOSPC`.
    pub set_access_err: Errno,
    /// The mm-side descriptor for the same arch.
    pub mm: PkeyArch,
}

/// x86_64 without OSPKE.
pub const X86_64: PkeyAbi = PkeyAbi {
    access_mask: PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE,
    set_access_err: Errno::Einval,
    mm: pkeys::X86_64,
};

/// aarch64 without FEAT_S1POE.
pub const AARCH64: PkeyAbi = PkeyAbi {
    access_mask: PKEY_DISABLE_ACCESS | PKEY_DISABLE_WRITE | PKEY_DISABLE_EXECUTE | PKEY_DISABLE_READ,
    set_access_err: Errno::Enospc,
    mm: pkeys::AARCH64,
};

/// The descriptor for the arch this kernel is built for.
#[cfg(target_arch = "aarch64")]
pub const ARCH: PkeyAbi = AARCH64;
/// The descriptor for the arch this kernel is built for. Hosted tests run on
/// the x86_64 host and must name [`AARCH64`] explicitly rather than rely on it.
#[cfg(not(target_arch = "aarch64"))]
pub const ARCH: PkeyAbi = X86_64;

/// `SYSCALL_DEFINE2(pkey_alloc)` against this mm's allocation `map`.
/// Validation order is Linux's: flags, then `init_val`, then the allocation
/// attempt, then the arch install.
/// # C: O(1)
pub fn pkey_alloc(a: &PkeyAbi, map: &mut u16, flags: u64, init_val: u64) -> Result<i32, Errno> {
    if flags != 0 { return Err(Errno::Einval); }
    if init_val & !a.access_mask != 0 { return Err(Errno::Einval); }
    let pkey = pkeys::mm_pkey_alloc(&a.mm, map);
    if pkey == pkeys::PKEY_ALLOC_FAILED { return Err(Errno::Enospc); }
    // We have no PKU/PKRU and no POE, so `arch_set_user_pkey_access` always
    // takes its feature-absent early return. Linux discards the rollback's own
    // result and reports the install error.
    let _ = pkeys::mm_pkey_free(&a.mm, map, pkey);
    Err(a.set_access_err)
}

/// `SYSCALL_DEFINE1(pkey_free)` — `mm_pkey_free` verbatim.
/// # C: O(1)
pub fn pkey_free(a: &PkeyAbi, map: &mut u16, pkey: i32) -> Result<(), Errno> {
    if pkeys::mm_pkey_free(&a.mm, map, pkey) { Ok(()) } else { Err(Errno::Einval) }
}

/// `do_mprotect_pkey`'s pkey clause: `pkey != -1 && !mm_pkey_is_allocated` is
/// EINVAL, checked after the address/length/prot validation and before the VMA
/// walk so a bad key never partially applies.
/// # C: O(1)
pub fn pkey_mprotect_allows(a: &PkeyAbi, map: u16, pkey: i32) -> bool {
    pkey == PKEY_KEEP || pkeys::mm_pkey_is_allocated(&a.mm, map, pkey)
}

#[cfg(test)]
mod tests;
