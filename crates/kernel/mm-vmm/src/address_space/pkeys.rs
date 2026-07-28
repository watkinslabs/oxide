// Linux `mm_context_t::pkey_allocation_map` — the per-mm protection-key
// allocation bitmap, plus the `mm_pkey_*` helpers that read and mutate it.
//
// Mirrors `arch/x86/include/asm/pkeys.h` and `arch/arm64/include/asm/pkeys.h`
// (`mm_pkey_is_allocated`, `mm_pkey_alloc`, `mm_pkey_free`) together with the
// initial value each arch's `init_new_context` installs
// (`arch/{x86,arm64}/include/asm/mmu_context.h`) and the fork copy
// (`arch_dup_pkeys`).
//
// The two arches genuinely differ, and the difference is NOT cosmetic — see
// [`PkeyArch`]. The syscall-level ordering that consumes these helpers lives
// in `syscalls::pkey` (`mm/mprotect.c` `SYSCALL_DEFINE2(pkey_alloc)` etc.).
//
// Deliberately free of any `target_os` gate so the hosted suite can exercise
// BOTH arch descriptors regardless of host arch.

use sync::{AddressSpace as AddressSpaceClass, Spinlock};

/// Per-arch facts about protection keys **on a CPU without the hardware
/// feature** (x86 `X86_FEATURE_OSPKE`, arm64 `system_supports_poe()`), which
/// is what we are on both arches: no CR4.PKE / PKRU, no POR_EL0, no per-PTE
/// key bits. Both arches compile the syscalls in unconditionally
/// (`X86_INTEL_MEMORY_PROTECTION_KEYS` and `ARM64_POE` are both `def_bool y`
/// and both `select ARCH_HAS_PKEYS`), so neither ENOSYSes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PkeyArch {
    /// `arch_max_pkey()`. x86: `OSPKE ? 16 : 1`, so 1 for us. arm64: 8,
    /// unconditionally — it does not consult the hardware feature here.
    pub max_pkey: i32,
    /// `mm->context.pkey_allocation_map` in a freshly-created mm.
    ///
    /// x86 sets it to `0x1` ("pkey 0 allocated implicitly") **inside**
    /// `if (cpu_feature_enabled(X86_FEATURE_OSPKE))`, so without OSPKE the
    /// field is left at the zeroed value — 0, not 1. arm64 sets `BIT(0)`
    /// unconditionally. This single line is what makes the first
    /// `pkey_alloc` behave differently on the two arches.
    pub init_map: u16,
    /// arm64 `mm_pkey_alloc` opens with `if (!arch_pkeys_enabled()) return
    /// -1;`. x86's has no such guard — it relies on the allocation map
    /// already being full, which without OSPKE it is not (see `init_map`).
    pub alloc_checks_hw: bool,
    /// x86 `mm_pkey_is_allocated` additionally refuses
    /// `mm->context.execute_only_pkey`. That field is likewise only
    /// initialised (to -1) under OSPKE, so without OSPKE it is 0 and key 0
    /// reads as *not* allocated. arm64 has no execute-only key (EPAN handles
    /// execute-only mappings) and no such clause.
    pub execute_only_pkey: Option<i32>,
}

/// x86_64 without OSPKE.
pub const X86_64: PkeyArch = PkeyArch {
    max_pkey: 1,
    init_map: 0,
    alloc_checks_hw: false,
    execute_only_pkey: Some(0),
};

/// aarch64 without FEAT_S1POE.
pub const AARCH64: PkeyArch = PkeyArch {
    max_pkey: 8,
    init_map: 1,
    alloc_checks_hw: true,
    execute_only_pkey: None,
};

/// The descriptor for the arch this kernel is built for.
#[cfg(target_arch = "aarch64")]
pub const ARCH: PkeyArch = AARCH64;
/// The descriptor for the arch this kernel is built for. Hosted tests run on
/// the x86_64 host and must therefore name [`AARCH64`] explicitly rather than
/// relying on this.
#[cfg(not(target_arch = "aarch64"))]
pub const ARCH: PkeyArch = X86_64;

/// Sentinel `mm_pkey_alloc` returns when no key could be allocated.
pub const PKEY_ALLOC_FAILED: i32 = -1;

impl PkeyArch {
    /// `all_pkeys_mask` — `(1U << arch_max_pkey()) - 1` (x86) /
    /// `GENMASK(arch_max_pkey() - 1, 0)` (arm64).
    /// # C: O(1)
    pub const fn all_pkeys_mask(&self) -> u16 { ((1u32 << self.max_pkey) - 1) as u16 }
}

/// `mm_pkey_is_allocated(mm, pkey)`.
/// # C: O(1)
pub fn mm_pkey_is_allocated(a: &PkeyArch, map: u16, pkey: i32) -> bool {
    if pkey < 0 { return false; }
    if pkey >= a.max_pkey { return false; }
    if a.execute_only_pkey == Some(pkey) { return false; }
    map & (1u16 << pkey) != 0
}

/// `mm_pkey_alloc(mm)` — returns the key, or [`PKEY_ALLOC_FAILED`].
/// Mutates `map` on success, exactly like `mm_set_pkey_allocated`.
/// # C: O(1)
pub fn mm_pkey_alloc(a: &PkeyArch, map: &mut u16) -> i32 {
    if a.alloc_checks_hw { return PKEY_ALLOC_FAILED; }
    if *map == a.all_pkeys_mask() { return PKEY_ALLOC_FAILED; }
    let ret = (!*map).trailing_zeros() as i32; // ffz()
    *map |= 1u16 << ret;
    ret
}

/// `mm_pkey_free(mm, pkey)` — `false` is Linux's `-EINVAL`. The bit is left
/// alone when the key was not allocated, which is load-bearing: `pkey_alloc`'s
/// rollback on x86 hits exactly that case and so leaks key 0 into the map.
/// # C: O(1)
pub fn mm_pkey_free(a: &PkeyArch, map: &mut u16, pkey: i32) -> bool {
    if !mm_pkey_is_allocated(a, *map, pkey) { return false; }
    *map &= !(1u16 << pkey);
    true
}

/// `mm_context_t`'s pkey slice of an [`AddressSpace`](super::AddressSpace).
/// Held behind a lock rather than an atomic because `pkey_alloc`'s
/// find-set-then-maybe-clear sequence is not a single RMW; Linux serialises
/// the same sequence under `mmap_write_lock`.
pub struct PkeyContext {
    map: Spinlock<u16, AddressSpaceClass>,
}

impl PkeyContext {
    /// `init_new_context`'s pkey initialisation for a brand-new mm.
    /// # C: O(1)
    pub(super) fn new() -> Self { Self { map: Spinlock::new(ARCH.init_map) } }

    /// `arch_dup_pkeys` — the child mm inherits the parent's map verbatim.
    /// # C: O(1)
    pub(super) fn forked(src: &Self) -> Self { Self { map: Spinlock::new(*src.map.lock()) } }

    /// Run one `mm_pkey_*` sequence with the map locked, the way Linux runs
    /// them under `mmap_write_lock`.
    /// # C: O(1) plus `f`
    /// # Lk: AddressSpace acquired
    pub fn with_map<R>(&self, f: impl FnOnce(&mut u16) -> R) -> R {
        let mut g = self.map.lock();
        f(&mut g)
    }
}

impl super::AddressSpace {
    /// This mm's protection-key allocation map.
    /// # C: O(1)
    pub fn pkeys(&self) -> &PkeyContext { &self.pkeys }
}

#[cfg(test)]
mod tests;
