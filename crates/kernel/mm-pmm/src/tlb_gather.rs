// Deferred-free TLB gather for user page teardown — Linux `mm/mmu_gather.c`.
//
// Tearing a user PTE down and handing its frame back to the allocator is a
// two-party operation: the page tables say the mapping is gone, but every CPU
// that ran this mm still caches the old translation in its TLB. Freeing the
// frame while any such entry survives is a use-after-free — the frame is
// recycled into an unrelated allocation and the stale (writable) TLB entry
// scribbles over it.
//
// Linux states the required order verbatim in `include/asm-generic/tlb.h`
// (the `mmu_gather` header comment):
//     1) unhook page  2) TLB invalidate page  3) free page
//     "we must never free a page before we have ensured there are no live
//      translations left to it. Otherwise it might be possible to observe
//      (or worse, change) the page content after it has been reused."
// and enforces it structurally in `mm/mmu_gather.c` `tlb_flush_mmu()`, which
// is exactly `tlb_flush_mmu_tlbonly()` (invalidate everywhere) followed by
// `tlb_flush_mmu_free()` (release the batched pages). `tlb_remove_page` only
// ever queues a page into the batch — it never frees inline, so a frame
// cannot outlive its own invalidation.
//
// This module owns that ordering as pure, target-independent logic so it is
// unit-testable on the host: `user_as` (where the real PTE walkers live) is
// `#[cfg(target_os = "oxide-kernel")]`, so decision logic placed there would
// compile out of `cargo test` silently (`docs/08`, phantom-test rule). The
// effectful half — tear a leaf, invalidate, shoot down, release a frame — is
// the `GatherOps` trait, implemented for real by the kernel and by a
// recording fake in `tests`.
//
// Per-arch invalidation (`20§5`). The two arches differ fundamentally:
//   x86_64: `invlpg` acts only on the CPU that executes it and only on the
//           currently-loaded CR3; there is no hardware broadcast. Reaching a
//           peer CPU REQUIRES a synchronous IPI — Linux `flush_tlb_mm_range`
//           -> `flush_tlb_multi(mm_cpumask(mm))` -> `on_each_cpu_cond_mask`
//           with `wait = 1` (`arch/x86/mm/tlb.c`, `kernel/smp.c`), which does
//           not return until every target has run the flush.
//   aarch64: `tlbi vae1is` is inner-shareable — hardware broadcasts the
//           invalidate to every PE in the domain and `dsb ish` waits for
//           completion, so the "local" invalidate already covers peers.
//           arm64 Linux has NO TLB-shootdown IPI at all (its IPI enum in
//           `arch/arm64/kernel/smp.c` has no TLB entry); our shootdown hook
//           is correspondingly never installed there and is a no-op.
//           Linux supplies the target ASID as an explicit TLBI operand
//           (`__TLBI_VADDR(addr, ASID(mm))`) so a non-current mm can be
//           invalidated; oxide runs every address space at ASID 0
//           (`hal-aarch64` `mmu_ops`), so the same instruction covers a
//           foreign root without an ASID switch.
// Both arches drive the same two calls; the arch decides which one carries
// the weight, so neither can be silently left out.

/// Frames batched before a flush+free cycle is forced. Bounds the stack
/// footprint of the batch array (`GATHER_BATCH_PAGES * 8` bytes) the way
/// Linux bounds `MAX_GATHER_BATCH_COUNT`; larger batches mean fewer remote
/// flushes per torn-down range.
pub const GATHER_BATCH_PAGES: usize = 64;

/// Effectful half of a page-range teardown. Split out so the flush-before-free
/// ordering in [`TlbGather`] can be exercised against a recording fake.
pub trait GatherOps {
    /// Clear the leaf mapping `va` in the target root, returning the physical
    /// frame it mapped, or `None` if `va` was not present. Must NOT flush any
    /// TLB — the gather owns invalidation.
    fn tear_leaf(&mut self, va: u64) -> Option<u64>;
    /// Invalidate `va` in this CPU's TLB. On aarch64 this is the
    /// inner-shareable broadcast that also covers peer CPUs.
    fn invalidate_local(&mut self, va: u64);
    /// Invalidate on the CPUs named in `targets` (the owning mm's cpumask)
    /// and wait for completion. No-op on aarch64 (hardware broadcast).
    fn shootdown_others(&mut self, targets: u64);
    /// Release one frame's mapping reference, freeing it only if this was the
    /// last one. Called strictly after the invalidation that covers it.
    fn free_frame(&mut self, pa: u64);
}

/// Batching page-teardown gather enforcing Linux's flush-before-free rule.
pub struct TlbGather {
    pas: [u64; GATHER_BATCH_PAGES],
    n: usize,
    cpumask: u64,
    tlb_dirty: bool,
}

impl TlbGather {
    /// Open a gather against the mm whose `cpumask` (Linux `mm_cpumask`) names
    /// the CPUs that may hold its user TLB entries.
    /// # C: O(1)
    pub fn new(cpumask: u64) -> Self {
        Self { pas: [0; GATHER_BATCH_PAGES], n: 0, cpumask, tlb_dirty: false }
    }

    /// Tear `va` out of the target root and queue its frame for release.
    /// Linux `zap_pte_range` + `tlb_remove_page`: the frame is NOT freed here,
    /// only batched, so no frame can outlive its invalidation. Returns whether
    /// a present leaf was torn.
    /// # C: O(1) amortised; a full batch costs one flush cycle
    pub fn unmap_one<O: GatherOps>(&mut self, ops: &mut O, va: u64) -> bool {
        let pa = match ops.tear_leaf(va) { Some(p) => p, None => return false };
        // Local invalidate immediately after the PTE write, before the frame
        // can be released by any later flush cycle.
        ops.invalidate_local(va);
        self.tlb_dirty = true;
        self.pas[self.n] = pa;
        self.n += 1;
        if self.n == GATHER_BATCH_PAGES { self.flush(ops); }
        true
    }

    /// One flush cycle: Linux `tlb_flush_mmu` = `tlb_flush_mmu_tlbonly()` then
    /// `tlb_flush_mmu_free()`. The remote shootdown is issued FIRST and waits
    /// for completion; only then are the batched frames released.
    /// # C: O(popcount(cpumask)) IPI round-trip + O(batch) frame releases
    pub fn flush<O: GatherOps>(&mut self, ops: &mut O) {
        if self.tlb_dirty {
            ops.shootdown_others(self.cpumask);
            self.tlb_dirty = false;
        }
        for i in 0..self.n {
            ops.free_frame(self.pas[i]);
        }
        self.n = 0;
    }

    /// Close the gather, flushing any partial batch. Linux `tlb_finish_mmu`.
    /// # C: same as [`TlbGather::flush`]
    pub fn finish<O: GatherOps>(mut self, ops: &mut O) {
        self.flush(ops);
    }

    /// Frames currently queued for release (awaiting the next flush).
    /// # C: O(1)
    pub fn pending(&self) -> usize { self.n }
}

#[cfg(test)]
mod tests;
