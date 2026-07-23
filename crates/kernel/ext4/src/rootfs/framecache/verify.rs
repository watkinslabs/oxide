// Feature-gated stale-`pa` detector for `writeback_idxs`'s plan-then-touch
// pattern (B1257 corruption hunt). `writeback_idxs` snapshots `(idx, pa)`
// from `pages` under one lock (`framecache.rs` plan block), drops that lock,
// then later dereferences `pa` through the HHDM mirror with no pin and no
// PMM page lock held across the gap. The global PMM file shrinker
// (`dirty::scan_clean_pages`) runs on any CPU and is free to isolate, lock,
// evict, and free that exact page in between — `writeback`/`writeback_range`
// already cleared its dirty tag before planning (`take_dirty_all` /
// `take_dirty_range` run before the plan lock), so the shrinker's
// clean-and-unmapped test can pass on it mid-flight. This check catches the
// resulting stale-frame touch AT THE READ instead of surfacing three
// allocations later as an unrelated kalloc-corruption panic.

/// Verify `pa` (captured earlier in a `writeback_idxs` plan without a pin)
/// still has a live PMM reference immediately before `writeback_idxs`
/// dereferences it through the HHDM mirror. `refcount == 0` proves the frame
/// was freed since the plan was built — an unconditional stale-`pa` touch.
/// A nonzero refcount is consistent with (not proof of) the frame still
/// belonging to this store: PMM exposes no per-frame owner/generation query,
/// only a bare refcount (`pmm::setup::frame_refcount`), so a frame freed AND
/// already reallocated to a NEW owner before this check runs is not caught
/// here — that gap is a PMM-API limitation, not a fix this check can make.
/// # C: O(1)
#[cfg(feature = "debug-framecache-verify")]
pub(super) fn verify_pa_live(ino: u32, idx: u64, pa: u64, site: &'static str) {
    if pmm::setup::frame_refcount(pa) != 0 { return; }
    klog::write_raw(b"[FRAME-STALE-PA] site=");
    klog::write_raw(site.as_bytes());
    klog::write_raw(b" ino=");
    klog::write_dec_u64(ino as u64);
    klog::write_raw(b" idx=");
    klog::write_dec_u64(idx);
    klog::write_raw(b" pa=");
    klog::write_hex_u64(pa);
    klog::write_raw(b" refcount=0 (frame freed since the writeback plan captured it; unpinned touch)\n");
    pmm::kassert!(false, "framecache writeback_idxs touched a freed frame (stale pa, no pin)");
}
