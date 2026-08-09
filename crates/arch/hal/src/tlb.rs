// Cross-CPU TLB shootdown (`20§5` SMP coherence) — a CALLER of the generic
// cross-CPU call in `smp_call`, not a mechanism of its own.
//
// x86 `invlpg` and CR3 reload only flush the LOCAL CPU's TLB; there is no
// hardware broadcast. When one CPU downgrades a user PTE (fork COW
// write-protect, mprotect, munmap, COW copy-split) the other CPUs with the
// SAME mm active keep using the stale translation — a peer thread writes
// through a now-COW-shared frame (write-while-shared corruption) or reads a
// freed/realloc'd frame. The reference closes this by calling its TLB flush
// function on the mm's cpumask through the ordinary call-function queue; so
// does this, via `smp_call::call_function_many(.., CallKind::TlbFlush, ..)`.
//
// aarch64 does NOT need this: `tlbi vae1is` is inner-shareable and the
// hardware broadcasts the invalidate, so the per-arch `MmuOps::flush_va`
// already covers SMP there. The call hook stays unset on aarch64 (a no-op)
// and the mm layer's local flush is sufficient.
//
// The mm crates (`mm-vmm`, `mm-pmm`) call `shootdown_others_*` AFTER their
// local flush. Before the arch layer installs the call hook (early boot,
// and in the hosted harness, which is single-CPU) these are no-ops.

use crate::smp_call::{self, CallKind};

/// Sentinel passed as the VA to request a full remote TLB flush rather than
/// a single-page invalidate. `u64::MAX` is never a valid user VA.
pub const ALL: u64 = smp_call::ALL;

/// Invalidate `va` on the CPUs in `targets` (minus this CPU, excluded by the
/// arch impl) and wait for completion. `targets` is the owning mm's `cpumask`
/// (Linux `mm_cpumask`): a `0` mask — the common single-CPU-runs-this-mm case
/// — means there is no peer to flush, so the arch impl short-circuits to zero
/// IPIs. The CALLER must already have flushed its OWN TLB for `va` (the mm
/// sites do, via `MmuOps::flush_va`).
///
/// The wait is not optional: the callers free frames on return, and a target
/// that has not yet invalidated still holds a live writable translation into
/// a page the buddy is about to recycle.
/// # C: O(popcount(targets)) + IPI round-trip
#[inline]
pub fn shootdown_others_va(va: u64, targets: u64) {
    smp_call::call_function_many(targets, CallKind::TlbFlush, va, true);
}

/// Full remote TLB flush on the CPUs in `targets` (used by batched PTE
/// rewrites — fork COW W-strip, mprotect a range — where a per-page IPI would
/// cost far more than one broadcast full flush).
/// # C: O(popcount(targets)) + IPI round-trip
#[inline]
pub fn shootdown_others_all(targets: u64) {
    shootdown_others_va(ALL, targets);
}
