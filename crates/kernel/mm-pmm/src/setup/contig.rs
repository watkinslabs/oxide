use super::*;
const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;
const PAGE_BYTES_USIZE: usize = hal::PAGE_SIZE_BYTES as usize;
#[cfg(feature = "debug-cow")]
use super::metadata::{cow_dbg_rmap_report, cow_dbg_who};

pub fn alloc_contig(order: crate::Order) -> Option<u64> {
    let p = pmm_static()?;
    p.alloc(order).ok().map(|pfn| pfn.0 * PAGE_BYTES)
}

/// Allocate a contiguous physical run owned by a kernel object. Each page in
/// the run starts with one non-PTE object reference and zero mapcount, so user
/// mappings can safely call `inc_ref` per installed PTE and object teardown can
/// call `dec_object_ref_and_maybe_free_frame` per page.
/// # C: O(2^order)
pub fn alloc_contig_object(order: crate::Order) -> Option<u64> {
    let p = pmm_static()?;
    let pa = p.alloc(order).ok().map(|pfn| pfn.0 * PAGE_BYTES)?;
    if let Some(meta) = page_meta() {
        let frames = 1u64 << order.0;
        for i in 0..frames {
            let pfn = hal::Pfn((pa / PAGE_BYTES) + i);
            if let Some(m) = meta.get(pfn) {
                m.refcount.store(1, Ordering::Release);
                m.mapcount.store(0, Ordering::Release);
            }
        }
    }
    Some(pa)
}

/// Free a contiguous physical region previously returned by `alloc_contig`
/// with the same `order`.
///
/// # SAFETY: `pa` must be page-aligned, aligned to `2^order` pages, originally
/// returned by `alloc_contig(order)`, and no longer reachable by any CPU or
/// device DMA engine. The caller owns quiesce/reset before returning the run.
/// # C: O(MAX_ORDER)
#[track_caller]
pub unsafe fn free_contig(pa: u64, order: crate::Order) {
    let p = match pmm_static() { Some(p) => p, None => return };
    let pfn = hal::Pfn(pa / PAGE_BYTES);
    unsafe { p.free(pfn, order); }
}

/// Free a single 4 KiB frame back to the kernel-owned PMM. Pair of
/// `alloc_one_frame`; the PA must originally have come from a PMM
/// alloc and not be currently mapped in any live page table (caller's
/// responsibility — `vmm::munmap` walks PTs first, then frees here).
/// # SAFETY: `pa` is a page-aligned PA originally returned by
/// `alloc_one_frame` (or huge-leaf split that wasn't promoted), no
/// longer reachable via any live PTE; single-CPU pre-userspace v1.
/// # C: O(1) amortised (PMM buddy free).
#[track_caller]
pub unsafe fn free_one_frame(pa: u64) {
    // debug-zerotrap: an armed sentinel frame being FREED while its owning
    // process still maps it is itself the bug — disarm (the poison/realloc
    // zeroing that follows is then legit) but leave a trace via trap(0-len).
    hal::zerotrap::disarm(pa);
    let p = match pmm_static() { Some(p) => p, None => return };
    let pfn = hal::Pfn(pa / PAGE_BYTES);
    // Defense in depth: once PageMeta is installed, a pfn with no slot is
    // outside PMM-managed RAM (device/MMIO PhysRange) and must never reach the
    // buddy — returning it would corrupt the allocator and alias live device
    // memory. `dec_and_maybe_free_frame` already filters these, but a stray
    // direct caller must not slip one through.
    if let Some(meta) = page_meta() {
        if meta.get(pfn).is_none() { return; }
    }
    // This is the sole terminal transition into the buddy allocator.  An
    // anonymous resident page must lose its exact LRU membership here, after
    // its last PTE/rmap reference is gone and before a recycled frame can
    // acquire a different owner.  An isolated page instead belongs to an
    // in-flight reclaim transaction and is a hard ownership violation.
    if let Err(err) = unlink_lru_for_final_free(pa) {
        match err {
            crate::reclaim::ReclaimError::State => kassert!(false, "isolated page reached final free"),
            _ => kassert!(false, "lru membership corrupt at final free"),
        }
    }
    // Page-table pages are not leaf mappings and never pass through the
    // rmap release path.  Their typed PMM ownership therefore ends here,
    // immediately before the single buddy transition.  This is the matching
    // release for `alloc_page_table_frame`; no procfs/VMM view reconstructs
    // the charge from mappings.
    let _was_page_table = super::page_tables::release_page_table_frame(pa);
    // Reset struct-page refcount to 0 before the frame re-enters the free
    // list, so the buddy free-list and per-page refcount stay in sync and
    // the alloc-side `check_new_page` invariant (free frame ⇒ refcount 0)
    // holds for frames freed directly (PT tables, AS root) as well as via
    // dec_and_maybe_free. Mirrors Linux `free_pages_prepare` zeroing.
    if let Some(meta) = page_meta() {
        if let Some(m) = meta.get(pfn) {
            // LOUD free-while-referenced: a RAW free (PT table / AS root / direct
            // caller) of a frame whose refcount is still >1 means it's freed
            // while another reference (PTE) maps it → free-while-mapped aliasing.
            #[cfg(feature = "debug-watchdog")]
            {
                let rc = m.refcount.load(core::sync::atomic::Ordering::Acquire);
                if rc > 1 {
                    klog::write_raw(b"[REFBUG] free-while-ref pa="); klog::write_hex_u64(pa);
                    klog::write_raw(b" rc="); klog::write_dec_u64(rc as u64);
                    klog::write_raw(b"\n");
                }
            }
            // debug-cow item 1: re-verify the RO-shared anon checksum before
            // the frame is recycled (a peer may have written it after the last
            // mapper's view was taken). item 2: refcount==live-PTE assert —
            // mapcount MUST be 0 at free; a non-zero mapcount means a live PTE
            // still points here (free-while-mapped, the inverse RANK-1 bug).
            #[cfg(feature = "debug-cow")]
            {
                let (tid, cpu) = cow_dbg_who();
                vmm::debug_cow::check_free(pa, crate::user_as::hhdm_offset(), tid, cpu);
                let mc = m.mapcount.load(core::sync::atomic::Ordering::Acquire);
                let rc = m.refcount.load(core::sync::atomic::Ordering::Acquire);
                if mc != 0 {
                    // flags: ANON(1<<4)/ANON_EXCLUSIVE(1<<9) distinguish a real
                    // data-page free-while-mapped (ANON set ⇒ a leaf user page
                    // freed with a live PTE = corruption) from a benign recycled
                    // PT-table/file frame carrying a stale mapcount (ANON clear).
                    let fl = meta.flags(pfn).map(|f| f.bits()).unwrap_or(0);
                    klog::write_raw(b"[COW-LEAK] free-while-mapped pa="); klog::write_hex_u64(pa);
                    klog::write_raw(b" mapcount="); klog::write_dec_u64(mc as u64);
                    klog::write_raw(b" refcount="); klog::write_dec_u64(rc as u64);
                    klog::write_raw(b" flags="); klog::write_hex_u64(fl as u64);
                    klog::write_raw(b"\n");
                    // Sampled rmap cross-check: name a concrete still-mapping VA
                    // (the O(1) mapcount may itself be under-counted; the rmap
                    // walk over the anon_vma chain is the authoritative oracle).
                    cow_dbg_rmap_report(pa);
                }
            }
            m.refcount.store(0, core::sync::atomic::Ordering::Release);
            // F157-A1: a frame re-entering the free list has no mappings —
            // reset mapcount to 0 so the next `alloc_one_frame` starts clean
            // (Linux `free_pages_prepare` zeroes `_mapcount`). Direct frees
            // (PT tables, AS root) never had a mapcount; this is idempotent.
            m.mapcount.store(0, core::sync::atomic::Ordering::Release);
            m.memcg.store(cgroup::NO_MEMCG, core::sync::atomic::Ordering::Release);
            // F157-A3: clear the page-class bits (Linux `free_pages_prepare`
            // -> `__folio_clear_anon`/`PAGE_FLAGS_CHECK_AT_FREE`). A recycled
            // frame must not inherit a stale ANON / ANON_EXCLUSIVE from its
            // previous life, or the COW-reuse fast path could fire on a fresh
            // non-anon allocation. set_anon_rmap_for_pa re-establishes them
            // for the next anon owner.
            let _ = meta.clear_flags(pfn,
                crate::PageFlags::ANON | crate::PageFlags::ANON_EXCLUSIVE
                    | crate::PageFlags::FILE | crate::PageFlags::SHMEM
                    | crate::PageFlags::DIRTY | crate::PageFlags::REFERENCED
                    | crate::PageFlags::UPTODATE | crate::PageFlags::PAGETABLE);
        }
    }
    // PAGE POISONING (debug-watchdog): fill the freed frame with 0xAA so a
    // later alloc can detect a write-while-free (use-after-free / stale-TLB
    // write that the PT-walk-based FWM detector can't see). Linux PAGE_POISONING.
    #[cfg(feature = "debug-watchdog")]
    {
        let hhdm = crate::user_as::hhdm_offset();
        if hhdm != 0 {
            // SAFETY: pa is a just-freed PMM frame; HHDM mirror is kernel-writable; 4 KiB granule.
            unsafe { core::ptr::write_bytes((hhdm + pa) as *mut u8, 0xAA, PAGE_BYTES_USIZE); }
        }
    }
    // debug-cow item 3: poison freed frames with 0xCC. `alloc_one_frame`
    // checks the pattern; any non-0xCC byte on a frame coming off the free
    // list = it was written WHILE FREE (free-while-mapped via a stale TLB,
    // double-alloc, or the allocator handed out an in-use frame). 0xCC is
    // distinct from debug-watchdog's 0xAA so the two probes don't alias.
    #[cfg(feature = "debug-cow")]
    {
        // debug-cow probe 1: the frame is leaving for the free list — clear
        // its allocated bit so a later alloc that finds the bit still set
        // (test_and_set returns true) is a genuine double-alloc, not a stale
        // mark from this frame's previous life.
        alloc_integrity::clear(pa / PAGE_BYTES);
        let hhdm = crate::user_as::hhdm_offset();
        if hhdm != 0 {
            // SAFETY: pa is a just-freed PMM frame; HHDM mirror is kernel-writable; 4 KiB granule.
            unsafe { core::ptr::write_bytes((hhdm + pa) as *mut u8, 0xCC, PAGE_BYTES_USIZE); }
        }
    }
    // SAFETY: caller asserts pa was a prior alloc and is no longer mapped per fn contract; crate::Buddy::free's preconditions reduce to "page aligned + within range" which alloc_one_frame guarantees.
    unsafe { p.free(pfn, crate::Order(0)); }
}
