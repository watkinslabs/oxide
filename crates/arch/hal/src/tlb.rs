// Cross-CPU TLB shootdown hook (`20§5` SMP coherence).
//
// x86 `invlpg` and CR3 reload only flush the LOCAL CPU's TLB; there is
// no hardware broadcast. When one CPU downgrades a user PTE (fork COW
// write-protect, mprotect, munmap, COW copy-split) the other CPUs that
// have the SAME mm active keep using the stale translation — a peer
// thread writes through a now-COW-shared frame (write-while-shared
// corruption) or reads a freed/realloc'd frame. Linux closes this with
// `flush_tlb_others` (an IPI to the mm's cpumask, synchronous).
//
// aarch64 does NOT need this: `tlbi vae1is` is inner-shareable and the
// hardware broadcasts the invalidate to every CPU, so the per-arch
// `MmuOps::flush_va` already covers SMP there. The hook stays unset on
// aarch64 (a no-op) and the mm layer's local flush is sufficient.
//
// The mm crates (`mm-vmm`, `mm-pmm`) call `shootdown_others_*` AFTER
// their local flush; the arch layer (`arch-irq`, x86 only) installs the
// real IPI implementation at boot via `set_shootdown_hook`. Before
// install (and in the hosted unit-test harness, which is single-CPU and
// never installs a hook) the calls are no-ops, so the harness stays
// green and boot before SMP bring-up is unaffected.

use core::sync::atomic::{AtomicUsize, Ordering};

/// `fn(va_or_sentinel: u64)`: invalidate `va` on every OTHER online CPU
/// and wait for completion. `va == ALL` ⇒ full remote TLB flush. Stored
/// as `usize` (fn pointer) because `AtomicPtr<fn(u64)>` isn't a stable
/// atomic form; the transmute back is sound — only `set_shootdown_hook`
/// writes it and only with a `fn(u64)` value.
static HOOK: AtomicUsize = AtomicUsize::new(0);

/// Sentinel passed as the VA to request a full remote TLB flush rather
/// than a single-page invalidate. `u64::MAX` is never a valid user VA.
pub const ALL: u64 = u64::MAX;

/// Install the arch shootdown implementation. Called once at boot by the
/// x86 IPI layer, AFTER AP bring-up + the TLB-shootdown IDT vector is
/// live. aarch64 never calls this (hardware-broadcast TLBI suffices).
/// # SAFETY: caller is the boot path; `f` lives for the kernel lifetime;
/// single-CPU at install time (no concurrent shootdown caller yet).
/// # C: O(1)
pub unsafe fn set_shootdown_hook(f: fn(u64)) {
    HOOK.store(f as usize, Ordering::Release);
}

/// Invalidate `va` on every other online CPU and wait for completion.
/// No-op until `set_shootdown_hook` runs (UP boot / hosted harness) and
/// on aarch64. The CALLER must already have flushed its OWN TLB for
/// `va` (the mm sites do, via `MmuOps::flush_va`).
/// # C: O(online_cpus) + IPI round-trip
#[inline]
pub fn shootdown_others_va(va: u64) {
    let p = HOOK.load(Ordering::Acquire);
    if p == 0 { return; }
    // SAFETY: only `set_shootdown_hook` writes HOOK, and only with a
    // `fn(u64)`; the transmute back to the same type is sound.
    let f: fn(u64) = unsafe { core::mem::transmute(p) };
    f(va);
}

/// Full remote TLB flush on every other online CPU (used by batched
/// PTE rewrites — fork COW W-strip, mprotect a range — where a per-page
/// IPI would be far costlier than one broadcast full flush). No-op
/// until installed / on aarch64.
/// # C: O(online_cpus) + IPI round-trip
#[inline]
pub fn shootdown_others_all() {
    shootdown_others_va(ALL);
}
