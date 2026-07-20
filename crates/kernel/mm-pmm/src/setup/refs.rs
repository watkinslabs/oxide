use super::*;
#[cfg(feature = "debug-atexit")]
use super::metadata::dec_ctx_root;

pub unsafe fn inc_ref(pa: u64) {
    if let Some(meta) = page_meta() {
        let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
        #[cfg(feature = "debug-atexit")]
        if hal::zerotrap::is_armed(pa) {
            klog::write_raw(b"[ARMED-INCREF] pa=");
            klog::write_hex_u64(pa & !(hal::PAGE_SIZE_BYTES - 1));
            klog::write_raw(b" rc-before=");
            klog::write_dec_u64(meta.refcount(pfn).unwrap_or(0) as u64);
            klog::write_raw(b"\n");
        }
        let _ = meta.inc_ref(pfn);
        // F157-A1: every `inc_ref` call adds one user PTE to an existing
        // frame (fork child install, shmem MAP_SHARED fault, KernelFrame
        // vvar fault), so the live-mapping count rises in lock-step.
        let _ = meta.inc_map(pfn);
        // F157-A3 (THE load-bearing CLEAR, Linux `copy_present_pte` ->
        // `folio_clear_anon_exclusive`): `inc_ref` is precisely "a second
        // reference now exists for this frame" — a fork child installing
        // the parent's page, a second MAP_SHARED mapper, etc. The frame is
        // therefore no longer exclusively owned, so the COW-reuse fast path
        // must not fire for it. Clearing here covers EVERY fork-shared anon
        // page (fork_cow_pages calls inc_ref per shared PTE). Clearing on
        // non-anon frames (shmem/KernelFrame) is a harmless no-op — the bit
        // was never set on them.
        let _ = meta.clear_flags(pfn, crate::PageFlags::ANON_EXCLUSIVE);
    }
}

/// Acquire a non-PTE owner reference to a managed frame.  Cache I/O and
/// reclaim use this while a page is looked up but not mapped; unlike
/// [`inc_ref`], it deliberately does not alter `mapcount`.
/// # SAFETY: caller must release the matching object reference with
/// `dec_object_ref_and_maybe_free_frame`.
/// # C: O(1)
pub unsafe fn inc_object_ref(pa: u64) {
    if let Some(meta) = page_meta() {
        let _ = meta.inc_ref(hal::Pfn(pa / hal::PAGE_SIZE_BYTES));
    }
}

/// The SINGLE free-on-zero choke point — Linux `__folio_put` +
/// `free_pages_prepare`'s `VM_BUG_ON_PAGE(page_mapped(page), page)`. BOTH
/// ref-drop paths (PTE teardown via `dec_and_maybe_free_frame`, object/pin
/// release via `dec_object_ref_and_maybe_free_frame`) funnel here once refcount
/// reaches 0, so the "free vs. still-mapped" decision and the never-free-a-
/// mapped-page invariant live in exactly ONE place — there is no second free
/// path to drift out of sync (the duplication that hid the free-while-mapped).
///
/// Returns the frame to the buddy ONLY if no live user PTE maps it
/// (`mapcount == 0`). A nonzero mapcount means a mapping's reference was lost
/// (an unpaired object dec, a double-drop, or a missing map-time inc): a live
/// PTE still points here, so freeing would be a free-while-mapped — the reused
/// frame gets written through the surviving PTE, smashing a free-node link →
/// the merge-time `FWM-CORRUPT` / bitmap double-free panic. Restore refcount to
/// the mapping count and DON'T free; the frame is released when that last PTE is
/// finally torn down (Linux `zap_pte_range` → `page_remove_rmap` → `put_page`).
/// # SAFETY: caller just dropped the last counted reference (refcount hit 0);
/// `pa` is a page-aligned PMM frame.
/// # C: O(1)
#[track_caller]
unsafe fn release_frame_on_zero(pa: u64) {
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let meta = match page_meta() {
        Some(m) => m,
        // Pre-init (no PageMeta): the buddy isn't refcount-tracked; direct free.
        // SAFETY: pre-init fallback; same preconditions as free_one_frame.
        None => { unsafe { free_one_frame(pa); } return; }
    };
    // NEVER free a page a live PTE still maps (Linux `page_mapped` VM_BUG_ON).
    // Excludes the wrapped-underflow value (~u32::MAX) healed by the callers.
    let mc = meta.mapcount(pfn).unwrap_or(0);
    if mc != 0 && mc < 0x8000_0000 {
        #[cfg(feature = "debug-pmm")]
        {
            let loc = core::panic::Location::caller();
            klog::write_raw(b"[FWM-PREVENTED] refcount hit 0 with mapcount=");
            klog::write_dec_u64(mc as u64);
            klog::write_raw(b" pa="); klog::write_hex_u64(pa);
            klog::write_raw(b" (restored, not freed) at ");
            klog::write_raw(loc.file().as_bytes());
            klog::write_raw(b":"); klog::write_dec_u64(loc.line() as u64);
            klog::write_raw(b"\n");
        }
        if let Some(m) = meta.get(pfn) {
            m.refcount.store(mc, core::sync::atomic::Ordering::Release);
        }
        return;
    }
    // BISECT (debug-leak-teardown): leak ONLY as_teardown frees (caller file
    // user_as); munmap/COW still reclaim. If this clears the corruption, the
    // bad free is at teardown.
    #[cfg(feature = "debug-leak-teardown")]
    if core::panic::Location::caller().file().contains("user_as") { return; }
    // DIAG (debug-noreclaim): leak instead of freeing.
    #[cfg(not(feature = "debug-noreclaim"))]
    // SAFETY: refcount hit 0 and mapcount is 0 — no AS holds or maps this frame;
    // same preconditions as free_one_frame.
    unsafe { free_one_frame(pa); }
}

/// Drop an object-owned frame reference without changing mapcount. Use for
/// inode/base pins: no user PTE is removed by this operation. User PTE
/// teardown must keep using `dec_and_maybe_free_frame`, which decrements both
/// mapcount and refcount. Both funnel through `release_frame_on_zero` when the
/// last reference drops — one free path, one invariant (Linux `put_page`).
/// # SAFETY: caller owns one non-PTE reference to `pa`.
/// # C: O(1) amortised
#[track_caller]
pub unsafe fn dec_object_ref_and_maybe_free_frame(pa: u64) {
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    if let Some(meta) = page_meta() {
        if let Some(new) = meta.dec_ref(pfn) {
            // SAFETY: refcount just reached 0; single free-on-zero choke point
            // enforces the never-free-a-mapped-page invariant.
            if new == 0 { unsafe { release_frame_on_zero(pa); } }
        }
        return;
    }
    // SAFETY: pre-init fallback; same preconditions as free_one_frame.
    unsafe { free_one_frame(pa); }
}

/// F157-A3: the `wp_page_reuse` predicate. True iff `pa` is an
/// exclusively-owned anonymous frame — Linux `wp_can_reuse_anon_folio`'s
/// proof that a write fault may reuse the frame in place (flip W, no
/// copy) instead of COW-splitting it. Four conjuncts, all read from
/// `PageMeta`:
///   * `ANON`            — never reuse a file / page-cache-aliased frame.
///   * `ANON_EXCLUSIVE`  — set at anon birth, CLEARED on every fork-share
///                         (`inc_ref`); proves no fork ever shared it.
///   * `mapcount == 1`   — exactly one live PTE references it.
///   * `refcount == 1`   — exactly one *reference* exists. Linux's
///                         `wp_can_reuse_anon_folio` bails on
///                         `folio_ref_count(folio) > 1`: a non-PTE
///                         reference (GUP/io_uring pin, an in-flight
///                         drop not yet observed, or any path that
///                         bumped refcount) means another holder may
///                         still read/write the frame, so reusing it in
///                         place corrupts that holder. This was MISSING
///                         (only mapcount was checked) — an asymmetry
///                         with the sole-survivor RESTORE in
///                         `dec_and_maybe_free_frame`, which already
///                         requires `refcount == 1` before re-setting
///                         ANON_EXCLUSIVE. Restoring the symmetry: the
///                         exclusive bit may be set with refcount>1 only
///                         transiently (a peer dropped its PTE but its
///                         refcount dec is not yet visible / ordered
///                         after this read); the refcount guard fails
///                         such a window safe to a copy rather than a
///                         cross-process peer corruption — the residual
///                         non-COW SEGV signature.
/// Returns false pre-init / out-of-range (→ copy path, always correct).
/// # C: O(1)
pub fn can_reuse_anon_exclusive(pa: u64) -> bool {
    let meta = match page_meta() { Some(m) => m, None => return false };
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    let f = match meta.flags(pfn) { Some(f) => f, None => return false };
    f.contains(crate::PageFlags::ANON)
        && f.contains(crate::PageFlags::ANON_EXCLUSIVE)
        && meta.mapcount(pfn) == Some(1)
        && meta.refcount(pfn) == Some(1)
}

/// F157: refcount snapshot. Returns 0 if pre-init or out-of-range.
/// # C: O(1)
pub fn frame_refcount(pa: u64) -> u32 {
    page_meta()
        .and_then(|m| m.refcount(hal::Pfn(pa / hal::PAGE_SIZE_BYTES)))
        .unwrap_or(0)
}

/// Repair an under-counted frame's struct-page counts to `val` (both refcount
/// and mapcount). Used by the free-while-mapped backstop (`as_teardown` /
/// munmap peer-scan) after it authoritatively finds `val-1` peer address spaces
/// still mapping a frame whose refcount fell to <=1 — restoring the true
/// reference count so the subsequent dec lands above zero and the frame is NOT
/// freed while a peer maps it. No-op pre-init / out-of-range.
/// # SAFETY: caller verified via `fwm_peer_maps` that `val-1` peers map `pa`.
/// # C: O(1)
#[cfg(feature = "debug-fwm")]
pub unsafe fn repair_frame_counts(pa: u64, val: u32) {
    if let Some(meta) = page_meta() {
        if let Some(m) = meta.get(hal::Pfn(pa / hal::PAGE_SIZE_BYTES)) {
            m.refcount.store(val, core::sync::atomic::Ordering::Release);
            m.mapcount.store(val, core::sync::atomic::Ordering::Release);
        }
    }
}

/// F157: decrement refcount; if it reaches 0, return the frame to
/// the PMM. The standard "drop a page reference" path used by
/// AS-teardown leaf walk and COW shared-page split. Mirrors Linux
/// `put_page()` + `__free_pages()` when refcount hits zero.
/// Pre-init: falls back to `free_one_frame` (always frees).
/// # SAFETY: `pa` is a page-aligned PA originally returned by
/// `alloc_one_frame`; the caller asserts the calling site has
/// dropped its reference. If refcount reaches 0 the page must not
/// be reachable via any live PTE.
/// # C: O(1) amortised
#[track_caller]
pub unsafe fn dec_and_maybe_free_frame(pa: u64) {
    let pfn = hal::Pfn(pa / hal::PAGE_SIZE_BYTES);
    if let Some(meta) = page_meta() {
        #[cfg(feature = "debug-atexit")]
        let armed = hal::zerotrap::is_armed(pa);
        #[cfg(feature = "debug-atexit")]
        if armed {
            let loc = core::panic::Location::caller();
            let rc0 = meta.refcount(pfn).unwrap_or(0);
            klog::write_raw(b"[ARMED-DEC] pa=");
        klog::write_hex_u64(pa & !(hal::PAGE_SIZE_BYTES - 1));
            klog::write_raw(b" rc-before=");
            klog::write_dec_u64(rc0 as u64);
            klog::write_raw(b" ctx=");
            klog::write_hex_u64(dec_ctx_root());
            klog::write_raw(b" at ");
            klog::write_raw(loc.file().as_bytes());
            klog::write_raw(b":");
            klog::write_dec_u64(loc.line() as u64);
            klog::write_raw(b"\n");
            if rc0 == 1 {
                // Final release — owner-context = legit; foreign = FWM bug.
                vmm::tailwatch::note_final_free(pa, dec_ctx_root());
            }
        }
        // F157-A1: this drop corresponds to one user PTE being torn down
        // (munmap / AS-teardown leaf / madvise DONTNEED / COW-displaced
        // frame). Decrement the live-mapping count alongside the refcount.
        // Out-of-range pfns (device/MMIO PhysRange) return `None` here, same
        // as `dec_ref` below, so the early-return path is unaffected.
        let new_mc = meta.dec_map(pfn);
        // DIAG (debug-cow): mapcount 0→-1 = the EXTRA dec (a PTE-teardown
        // dec with no matching install inc). Name the call site + task.
        #[cfg(feature = "debug-cow")]
        if new_mc == Some(u32::MAX) {
            let loc = core::panic::Location::caller();
            klog::write_raw(b"[MAPNEG] pa=");
            klog::write_hex_u64(pa);
            klog::write_raw(b" rc=");
            klog::write_dec_u64(meta.refcount(pfn).unwrap_or(0) as u64);
            klog::write_raw(b" tid=");
            klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
            klog::write_raw(b" at ");
            klog::write_raw(loc.file().as_bytes());
            klog::write_raw(b":");
            klog::write_dec_u64(loc.line() as u64);
            klog::write_raw(b"\n");
        }
        if let Some(new) = meta.dec_ref(pfn) {
            // F157-A3 (RESTORE, Linux do_wp_page's reuse-path re-marks the
            // sole survivor exclusive): one mapper of a fork-shared anon
            // frame just went away. If exactly one PTE and one reference
            // remain, the survivor is the exclusive owner again — re-set
            // ANON_EXCLUSIVE so its next write fault can reuse in place
            // instead of pointlessly COW-copying a page nobody else maps.
            // Requires refcount==1 too so a GUP/io_uring pin (a non-PTE
            // reference that could still write) keeps the page non-exclusive.
            if new_mc == Some(1) && new == 1 {
                if meta.flags(pfn).map_or(false, |f| f.contains(crate::PageFlags::ANON)) {
                    let _ = meta.set_flags(pfn, crate::PageFlags::ANON_EXCLUSIVE);
                    // debug-cow: sole survivor is exclusive again and may
                    // legitimately write the page in place — drop its RO-shared
                    // snapshot so a later free doesn't false-positive.
                    #[cfg(feature = "debug-cow")]
                    vmm::debug_cow::forget(pa);
                }
            }
            // Over-dec detection: dec on a refcount-0 frame wraps to a huge
            // value — a PTE torn down whose inc_ref was never paired, or a
            // double-dec. Audit #11: the SELF-HEAL (reset rc/mc to 0, do NOT
            // free-into-a-wrapped-count) must run in PRODUCTION too, not just
            // debug builds — otherwise a stray underflow wraps mapcount to
            // ~u32::MAX in release with no recovery, permanently pinning the
            // frame (and, worse, a wrapped refcount would never re-hit 0 to
            // free). The klog stays debug-gated (no steady-state noise).
            if new > 0x8000_0000 {
                #[cfg(feature = "debug-watchdog")]
                {
                    klog::write_raw(b"[REFBUG] dec-underflow pa="); klog::write_hex_u64(pa);
                    klog::write_raw(b" new="); klog::write_hex_u64(new as u64);
                    klog::write_raw(b"\n");
                }
                if let Some(m) = meta.get(pfn) {
                    m.refcount.store(0, core::sync::atomic::Ordering::Release);
                    m.mapcount.store(0, core::sync::atomic::Ordering::Release);
                }
                return;
            }
            if new == 0 {
                // DIAG (debug-watchdog): free-while-mapped RED-HANDED trap —
                // name the frame + residual mapcount + caller + tid. The actual
                // never-free-a-mapped-page ENFORCEMENT + free lives in the single
                // free-on-zero choke point `release_frame_on_zero` below, shared
                // with the object-ref drop path (no duplicated free path).
                #[cfg(feature = "debug-watchdog")]
                if let Some(mc) = new_mc {
                    if mc != 0 && mc < 0x8000_0000 {
                        let loc = core::panic::Location::caller();
                        klog::write_raw(b"[FWM] pa="); klog::write_hex_u64(pa);
                        klog::write_raw(b" residual-mapcount="); klog::write_dec_u64(mc as u64);
                        klog::write_raw(b" tid=");
                        klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
                        klog::write_raw(b" at ");
                        klog::write_raw(loc.file().as_bytes());
                        klog::write_raw(b":"); klog::write_dec_u64(loc.line() as u64);
                        klog::write_raw(b"\n");
                    }
                }
                // SAFETY: refcount just reached 0; the single free-on-zero choke
                // point enforces never-free-a-mapped-page + noreclaim/leak gates.
                unsafe { release_frame_on_zero(pa); }
            }
            return;
        }
        // PageMeta is installed but this pfn has NO slot ⇒ it is OUTSIDE the
        // PMM-managed RAM range: device/MMIO memory mapped via
        // `VmaBacking::PhysRange` (remap_pfn_range / VM_PFNMAP) — e.g. the
        // virtio-gpu scanout. Such mappings are NEVER refcounted and MUST NOT
        // be returned to the buddy (Linux `vm_normal_page` returns NULL for
        // PFNMAP, so zap_pte_range never frees them). Freeing it would hand a
        // live device frame to the allocator → free-while-mapped aliasing.
        return;
    }
    // Pre-init only (no PageMeta yet): the buddy isn't refcount-tracked, so a
    // direct free is the documented fallback. Post-init, the branch above
    // handles both in-range (dec) and out-of-range (skip) frames.
    // SAFETY: same as free_one_frame; caller assertion stands.
    unsafe { free_one_frame(pa); }
}
