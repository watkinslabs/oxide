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

/// Number of payload bits reserved for a gathered page count. User virtual
/// addresses use the lower 52 bits on the supported architectures, leaving
/// the upper twelve bits for the bounded count used by the unmap gather.
const RANGE_COUNT_SHIFT: u32 = 52;
const RANGE_COUNT_MASK: u64 = 0xfff;

/// Pack an aligned half-open page range into one call-function argument.
/// # C: O(1)
fn encode_range(start: u64, end: u64) -> Option<u64> {
    if start >= end || start % crate::PAGE_SIZE_BYTES != 0 || end % crate::PAGE_SIZE_BYTES != 0 { return None; }
    let pages = (end - start) / crate::PAGE_SIZE_BYTES;
    if pages == 0 || pages > RANGE_COUNT_MASK { return None; }
    Some((pages << RANGE_COUNT_SHIFT) | (start / crate::PAGE_SIZE_BYTES))
}

/// Unpack an encoded range for the architecture's local invalidation handler.
/// # C: O(1)
pub fn decode_range(arg: u64) -> Option<(u64, u64)> {
    let pages = (arg >> RANGE_COUNT_SHIFT) & RANGE_COUNT_MASK;
    if pages == 0 { return None; }
    let start_page = arg & ((1u64 << RANGE_COUNT_SHIFT) - 1);
    let start = start_page.checked_mul(crate::PAGE_SIZE_BYTES)?;
    let end = start.checked_add(pages.checked_mul(crate::PAGE_SIZE_BYTES)?)?;
    Some((start, end))
}

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
pub fn shootdown_others_va(va: u64, targets: &[u64]) {
    smp_call::call_function_many(targets, CallKind::TlbFlush, va, true);
}

/// Full remote TLB flush on the CPUs in `targets` (used by batched PTE
/// rewrites — fork COW W-strip, mprotect a range — where a per-page IPI would
/// cost far more than one broadcast full flush).
/// # C: O(popcount(targets)) + IPI round-trip
#[inline]
pub fn shootdown_others_all(targets: &[u64]) {
    shootdown_others_va(ALL, targets);
}

/// Invalidate one gathered page range on every peer CPU and wait for the
/// remote handlers. This is the small-range counterpart to the full flush;
/// it keeps the one-IPI-per-gather shape while avoiding a full-TLB flush.
/// # C: O(popcount(targets) × pages) + IPI round-trip
#[inline]
pub fn shootdown_others_range(start: u64, end: u64, targets: &[u64]) {
    if let Some(arg) = encode_range(start, end) {
        smp_call::call_function_many(targets, CallKind::TlbFlushRange, arg, true);
    } else {
        shootdown_others_all(targets);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_payload_round_trips() {
        let start = 0x7fff_0000_0000;
        let end = start + 16 * crate::PAGE_SIZE_BYTES;
        let encoded = encode_range(start, end).expect("valid range");
        assert_eq!(decode_range(encoded), Some((start, end)));
    }

    #[test]
    fn range_payload_rejects_unaligned_and_empty_ranges() {
        assert!(encode_range(1, crate::PAGE_SIZE_BYTES).is_none());
        assert!(encode_range(0, 0).is_none());
        assert!(encode_range(0, (RANGE_COUNT_MASK + 1) * crate::PAGE_SIZE_BYTES).is_none());
    }
}
