// The per-mm protection-key allocation bitmap, plus the helpers that read
// and mutate it, together with the initial value each arch installs at mm
// creation and the fork copy.
//
// The two arches genuinely differ, and the difference is NOT cosmetic — see
// [`PkeyArch`]. The syscall-level ordering that consumes these helpers lives
// in `syscalls::pkey` (pkey_alloc(2) etc.).
//
// Deliberately free of any `target_os` gate so the hosted suite can exercise
// BOTH arch descriptors regardless of host arch.

use sync::{AddressSpace as AddressSpaceClass, Spinlock};

/// Per-arch facts protection-key helpers need for one particular boot-time
/// hardware decision. The architecture enables the register before any user
/// mm exists, so a newly-created mm captures one immutable descriptor and
/// neither its allocation map nor its fork child can disagree with it.
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
    /// execute-only mappings) and no such clause — `None` says the field does
    /// not exist on this arch, which is NOT the same as "it holds -1".
    ///
    /// This is the value a freshly-created mm starts with; the live value is
    /// [`PkeyState::execute_only`], because a PROT_EXEC-only `mprotect`
    /// allocates the key lazily and stores it back in the mm.
    pub execute_only_init: Option<i32>,
    /// Do instruction fetches bypass the key check?
    ///
    /// x86's rights register has no execute bit, so an instruction fetch is
    /// never denied by a key and the check returns early. arm64's overlay has
    /// one, so an execute access is checked against it like any other. Folding
    /// the two into one answer would either let arm64 execute from a
    /// key-denied mapping or make x86 refuse a legal instruction fetch.
    pub exec_ignores_keys: bool,
}

/// x86_64 without OSPKE.
pub const X86_64: PkeyArch = PkeyArch {
    max_pkey: 1,
    init_map: 0,
    alloc_checks_hw: false,
    execute_only_init: Some(0),
    exec_ignores_keys: true,
};

/// aarch64 without FEAT_S1POE.
pub const AARCH64: PkeyArch = PkeyArch {
    max_pkey: 8,
    init_map: 1,
    alloc_checks_hw: true,
    execute_only_init: None,
    exec_ignores_keys: false,
};

/// The descriptor the running kernel's architecture enabled on this boot.
/// # C: O(1)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub fn runtime_arch() -> PkeyArch {
    if hal_x86_64::ospke_enabled() {
        PkeyArch { max_pkey: hal_x86_64::pkru::MAX_PKEY_OSPKE as i32, init_map: 1,
            alloc_checks_hw: false, execute_only_init: Some(EXEC_ONLY_UNSET), exec_ignores_keys: true }
    } else { X86_64 }
}

/// The descriptor the running kernel's architecture enabled on this boot.
/// # C: O(1)
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub fn runtime_arch() -> PkeyArch {
    PkeyArch { max_pkey: if hal_aarch64::poe_enabled() { hal_aarch64::por::MAX_PKEY as i32 } else { 1 }, init_map: 1,
        alloc_checks_hw: !hal_aarch64::poe_enabled(), execute_only_init: None, exec_ignores_keys: false }
}

/// Hosted builds model the x86 hardware-absent descriptor.
/// # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn runtime_arch() -> PkeyArch { ARCH }

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

/// "Keep the current key" sentinel `pkey_mprotect` accepts and plain
/// `mprotect` always passes.
pub const PKEY_KEEP: i32 = -1;

/// `ARCH_DEFAULT_PKEY` — the key every mapping carries until something moves
/// it.
pub const PKEY_DEFAULT: i32 = 0;

/// The value an OSPKE-capable mm's execute-only slot starts at: no key has
/// been dedicated yet, and the first PROT_EXEC-only `mprotect` allocates one.
pub const EXEC_ONLY_UNSET: i32 = -1;

/// The live, per-mm protection-key state — `mm->context`'s two pkey fields.
///
/// They travel together because they are read together: whether a key counts
/// as allocated depends on which key (if any) this mm dedicated to
/// execute-only mappings, and that dedication happens lazily, long after the
/// mm was created.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PkeyState {
    /// `pkey_allocation_map`.
    pub map: u16,
    /// `execute_only_pkey`. Meaningless on an arch whose
    /// [`PkeyArch::execute_only_init`] is `None`.
    pub execute_only: i32,
}

impl PkeyState {
    /// `init_new_context`'s pkey initialisation. # C: O(1)
    pub const fn new(a: &PkeyArch) -> Self {
        Self { map: a.init_map, execute_only: match a.execute_only_init { Some(v) => v, None => EXEC_ONLY_UNSET } }
    }
}

impl PkeyArch {
    /// `all_pkeys_mask` — `(1U << arch_max_pkey()) - 1` (x86) /
    /// `GENMASK(arch_max_pkey() - 1, 0)` (arm64).
    /// # C: O(1)
    pub const fn all_pkeys_mask(&self) -> u16 { ((1u32 << self.max_pkey) - 1) as u16 }

    /// `arch_pkeys_enabled()` — is a rights register live on this boot?
    ///
    /// The two arches say it differently and both must be honoured: arm64
    /// guards its allocator with the hardware test and keeps `arch_max_pkey()`
    /// at 8 either way, while x86 has no such guard and instead collapses
    /// `arch_max_pkey()` to 1 when the feature is off.
    /// # C: O(1)
    pub const fn pkeys_enabled(&self) -> bool { !self.alloc_checks_hw && self.max_pkey > 1 }
}

/// `mm_pkey_is_allocated(mm, pkey)`. The execute-only key is set in the
/// allocation map but is deliberately invisible to every user interface, so a
/// program cannot `pkey_free` or `pkey_mprotect` the key its own execute-only
/// mappings depend on.
/// # C: O(1)
pub fn mm_pkey_is_allocated(a: &PkeyArch, st: &PkeyState, pkey: i32) -> bool {
    if pkey < 0 { return false; }
    if pkey >= a.max_pkey { return false; }
    if a.execute_only_init.is_some() && st.execute_only == pkey { return false; }
    st.map & (1u16 << pkey) != 0
}

/// `mm_pkey_alloc(mm)` — returns the key, or [`PKEY_ALLOC_FAILED`].
/// Mutates the map on success, exactly like `mm_set_pkey_allocated`.
/// # C: O(1)
pub fn mm_pkey_alloc(a: &PkeyArch, st: &mut PkeyState) -> i32 {
    if a.alloc_checks_hw { return PKEY_ALLOC_FAILED; }
    if st.map == a.all_pkeys_mask() { return PKEY_ALLOC_FAILED; }
    let ret = (!st.map).trailing_zeros() as i32; // ffz()
    st.map |= 1u16 << ret;
    ret
}

/// `mm_set_pkey_free` — the raw bit clear, with none of `mm_pkey_free`'s
/// admission. The execute-only rollback needs it: the key it is releasing is
/// by construction one `mm_pkey_is_allocated` hides.
/// # C: O(1)
pub fn mm_set_pkey_free(st: &mut PkeyState, pkey: i32) {
    if (0..16).contains(&pkey) { st.map &= !(1u16 << pkey); }
}

/// `mm_pkey_free(mm, pkey)` — `false` is Linux's `-EINVAL`. The bit is left
/// alone when the key was not allocated, which is load-bearing: `pkey_alloc`'s
/// rollback on x86 hits exactly that case and so leaks key 0 into the map.
/// # C: O(1)
pub fn mm_pkey_free(a: &PkeyArch, st: &mut PkeyState, pkey: i32) -> bool {
    if !mm_pkey_is_allocated(a, st, pkey) { return false; }
    st.map &= !(1u16 << pkey);
    true
}

/// `mm_context_t`'s pkey slice of an [`AddressSpace`](super::AddressSpace).
/// Held behind a lock rather than an atomic because `pkey_alloc`'s
/// find-set-then-maybe-clear sequence is not a single RMW; Linux serialises
/// the same sequence under `mmap_write_lock`.
pub struct PkeyContext {
    st: Spinlock<PkeyState, AddressSpaceClass>,
    arch: Spinlock<PkeyArch, AddressSpaceClass>,
}

impl PkeyContext {
    /// `init_new_context`'s pkey initialisation for a brand-new mm.
    /// # C: O(1)
    pub(super) fn new() -> Self {
        let arch = runtime_arch();
        Self { st: Spinlock::new(PkeyState::new(&arch)), arch: Spinlock::new(arch) }
    }

    /// `arch_dup_pkeys` — the child mm inherits the parent's allocation map
    /// and its execute-only dedication verbatim, because the child inherits
    /// the mappings those keys protect.
    /// # C: O(1)
    pub(super) fn forked(src: &Self) -> Self {
        Self { st: Spinlock::new(*src.st.lock()), arch: Spinlock::new(*src.arch.lock()) }
    }

    /// The hardware shape captured when this mm was created. # C: O(1)
    pub fn arch(&self) -> PkeyArch { *self.arch.lock() }

    /// Model a boot on which the rights register IS live. The hosted build
    /// has no such register, so every consumer of the key ladder would
    /// otherwise be reachable only from a running kernel.
    /// # C: O(1)
    #[cfg(test)]
    pub fn force_arch_for_test(&self, a: PkeyArch) {
        *self.arch.lock() = a;
        *self.st.lock() = PkeyState::new(&a);
    }

    /// Run one `mm_pkey_*` sequence with the state locked, the way Linux runs
    /// them under `mmap_write_lock`.
    /// # C: O(1) plus `f`
    /// # Lk: AddressSpace acquired
    pub fn with_state<R>(&self, f: impl FnOnce(&mut PkeyState) -> R) -> R {
        let mut g = self.st.lock();
        f(&mut g)
    }
}

impl super::AddressSpace {
    /// This mm's protection-key allocation map.
    /// # C: O(1)
    pub fn pkeys(&self) -> &PkeyContext { &self.pkeys }
}

mod access;
mod exec_only;
pub use access::vma_access_permitted;
pub use exec_only::{ExecOnlyRights, VmaKeyView, arch_override_mprotect_pkey, execute_only_pkey};

#[cfg(test)]
mod tests;
