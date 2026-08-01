// The `GlobalAlloc` surface: `alloc` / `dealloc` dispatch across the size-class
// front end, the diagnostic gates, and the sorted hole list.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

use crate::sizeclass;
use crate::state::KAlloc;
#[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag", feature = "debug-efence"))]
use crate::caller;
#[cfg(feature = "debug-efence")]
use crate::efence;
#[cfg(feature = "debug-heappoison")]
use crate::poison;
#[cfg(feature = "debug-dealloc-diag")]
use crate::recent::record_recent_op;
#[cfg(feature = "debug-hw-watchpoint")]
use crate::limits::WATCHPOINT_MIN_SIZE;
#[cfg(feature = "debug-hw-watchpoint")]
use crate::watchpoint::{arm_watchpoint, disarm_watchpoint_if_reclaimed, disarm_watchpoint_now};

// SAFETY: `KAlloc::alloc` returns either null or a NonNull pointing
// into the heap region the caller passed to `init`. `dealloc` accepts
// only pointers that came from `alloc`; both paths take the inner
// Spinlock so the hole list mutations are serialized.
unsafe impl GlobalAlloc for KAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.is_initialized() { return ptr::null_mut(); }
        // debug-efence (C213): route the small-object size class to the
        // page-per-object guard arena so a later UAF write to the freed object
        // faults (naming the writer). Loose prefilter here; the arena applies
        // the authoritative size/align predicate and may decline (null → fall
        // through to the normal heap). Bypassed entirely until `efence::init`
        // installs the hook.
        #[cfg(feature = "debug-efence")]
        if layout.size() > 0 && layout.size() <= 4096 && layout.align() as u64 <= 4096 {
            let p = efence::try_alloc(layout.size(), layout.align(), caller::alloc_return_ip());
            if !p.is_null() { return p; }
        }
        // Diagnostic-only (debug-heappoison): carve a trailing redzone onto
        // every allocation so a heap buffer OVERFLOW (a write past the
        // caller's own requested bytes, into the next allocation) is caught
        // at free time instead of silently landing on whatever neighbor
        // happens to be there — the exact "wild write, unrelated victim"
        // shape this session's zram/heap-corruption hunt keeps finding.
        // Falls back to the plain layout if the redzone addition would
        // overflow (astronomically large request; safe to just not pad it).
        #[cfg(feature = "debug-heappoison")]
        let carve_layout = poison::alloc_layout(layout).unwrap_or(layout);
        #[cfg(not(feature = "debug-heappoison"))]
        let carve_layout = layout;
        // IRQ-atomic across the WHOLE alloc (incl. the unlocked grow window).
        let _irq = self.irq_off();
        // `kmalloc` front end (`sizeclass.rs`): small objects come off an O(1)
        // per-size LIFO, never the O(N) hole-list walk. A class-routed layout is
        // ALWAYS served here — `dealloc` re-derives the same class from the same
        // `Layout`, so a routed object must never have come from the hole list.
        if let Some(i) = sizeclass::class_index(carve_layout) {
            {
                let mut g = self.inner.lock();
                if let Some(p) = g.classes.pop(i) { return p.as_ptr(); }
            }
            // SAFETY: refill carves an allocator-owned slab under the same lock.
            return unsafe { self.refill_class(i) }.map_or(ptr::null_mut(), |p| p.as_ptr());
        }
        // Disarm before this op touches the hole list, so kalloc's own header
        // writes (split/coalesce) don't self-trip the freed-block watchpoint.
        #[cfg(feature = "debug-hw-watchpoint")]
        disarm_watchpoint_now();
        // B1347: tight-mode op-START validate (before the carve can panic).
        #[cfg(feature = "debug-dealloc-diag")]
        self.tight_precheck(caller::alloc_return_ip());
        let mut g = self.inner.lock();
        if let Some(p) = g.holes.alloc(carve_layout) {
            #[cfg(feature = "debug-dealloc-diag")]
            g.size_track.record(p.as_ptr() as usize, carve_layout.size());
            // B1346: record the alloc-return-IP so a later corruption of this
            // block (once freed) names the recycled victim's type + the writer's
            // (prev-alloc) type.
            #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
            g.holes.record_alloc_ip(p.as_ptr() as usize, caller::alloc_return_ip());
            #[cfg(feature = "debug-dealloc-diag")]
            record_recent_op(caller::alloc_return_ip(), p.as_ptr() as usize, true);
            drop(g);
            // B1347: tick the diag validator on ALLOC too. The boot corruptor
            // manifests inside the zram-disksize ALLOC burst (compressor init +
            // slots.resize), where a dealloc-only tick never runs — so validate
            // catches the first bad free node within a few allocs of creation
            // and names the running context (see periodic_validate_diag).
            #[cfg(feature = "debug-dealloc-diag")]
            self.periodic_validate_diag(caller::alloc_return_ip());
            #[cfg(feature = "debug-heappoison")]
            {
                // SAFETY: `p` was just carved with `carve_layout`'s extra
                // trailing bytes reserved exactly for this redzone.
                unsafe { poison::arm_redzone(p.as_ptr(), layout); }
                self.periodic_validate(caller::UNKNOWN_RETURN_IP);
            }
            #[cfg(feature = "debug-hw-watchpoint")]
            disarm_watchpoint_if_reclaimed(p.as_ptr() as usize);
            return p.as_ptr();
        }
        // `klog` fans out to framebuffer consoles, whose scroll path can
        // allocate. Release the heap lock before diagnostics or PMM growth so
        // that diagnostic output cannot recursively spin on this lock.
        drop(g);
        #[cfg(feature = "debug-heappoison")]
        {
            klog::write_primary_raw(b"[KALLOC] allocation-miss bytes=");
            klog::write_primary_dec_u64(carve_layout.size() as u64);
            klog::write_primary_raw(b" align=");
            klog::write_primary_dec_u64(carve_layout.align() as u64);
            klog::write_primary_raw(b"\n");
        }
        // SAFETY: same allocation contract; the IRQ guard above is still held.
        unsafe { self.grow_and_alloc(layout, carve_layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() { return; }
        // debug-efence (C213): a fenced object lives in the arena window, NOT
        // the hole list — intercept before any poison/precheck touches it as
        // if it were a kalloc-carved block. `try_free` range-rejects fast, then
        // flips the page RO. Returns true = fully handled here.
        #[cfg(feature = "debug-efence")]
        if efence::try_free(ptr, caller::dealloc_return_ip()) { return; }
        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
        let free_ip = caller::dealloc_return_ip();
        // Diagnostic-only (debug-heappoison): must match `alloc`'s expansion
        // exactly (same deterministic function of `layout` alone) so the
        // hole-list reclaim covers the SAME span that was carved out,
        // trailing redzone included. Check the redzone BEFORE anything else
        // touches this block — a mismatch means ITS OWNER (not some later
        // reader) overflowed past its own requested bytes.
        #[cfg(feature = "debug-heappoison")]
        {
            // SAFETY: `ptr` was returned by this allocator's `alloc(layout)`,
            // which armed a redzone at `ptr+layout.size()` sized to fit
            // within `alloc_layout(layout)`'s padding.
            unsafe { poison::check_redzone(ptr, layout); }
        }
        #[cfg(feature = "debug-heappoison")]
        let carve_layout = poison::alloc_layout(layout).unwrap_or(layout);
        #[cfg(not(feature = "debug-heappoison"))]
        let carve_layout = layout;
        // IRQ-atomic: dealloc mutates the same hole list an IRQ-context alloc
        // touches; disable IRQs for the whole op (see `IrqOff`).
        let _irq = self.irq_off();
        // `kmalloc` front end: the same routing predicate `alloc` used, on the
        // same `Layout` Rust guarantees is passed back, so a class-routed object
        // returns to the class it was carved from and never to the hole list.
        if let Some(i) = sizeclass::class_index(carve_layout) {
            let mut g = self.inner.lock();
            // SAFETY: `ptr` came from `alloc(layout)`, which routed the identical
            // layout to class `i`, and the caller no longer borrows it.
            unsafe { g.classes.push(i, ptr) };
            return;
        }
        // B1347: tight-mode op-START validate (before the coalesce can panic).
        #[cfg(feature = "debug-dealloc-diag")]
        self.tight_precheck(free_ip);
        // Disarm before this op touches the hole list (coalesce writes the
        // freed block's + neighbors' headers); re-armed on the final freed
        // block at exit, so only EXTERNAL writes between ops fault.
        #[cfg(feature = "debug-hw-watchpoint")]
        disarm_watchpoint_now();
        // SAFETY: caller-asserted that `ptr` was previously returned by
        // `alloc(layout)` and is no longer borrowed.
        let nn = unsafe { core::ptr::NonNull::new_unchecked(ptr) };
        // debug-heappoison: poison + quarantine small blocks (delay reuse) so a
        // UAF read hits 0xEE deterministically; only really free an evicted one.
        // Gated on the CALLER's requested size (not the carved/padded size) —
        // POISON_MAX is about the caller's own size class.
        #[cfg(feature = "debug-heappoison")]
        if layout.size() <= poison::POISON_MAX {
            let mut g = self.inner.lock();
            // Preflight while the same lock protects both ownership domains:
            // a stale release cannot poison an existing free-list header.
            assert!(!g.quarantine.contains(ptr, carve_layout), "kalloc duplicate quarantined free");
            assert!(g.holes.can_dealloc(nn, carve_layout).is_ok(), "kalloc invalid free");
            // Byte address of a block that became a genuine free HoleHdr this
            // call, to arm a hardware watchpoint on AFTER the lock drops.
            #[cfg(feature = "debug-hw-watchpoint")]
            let mut freed_hdr: Option<usize> = None;
            // SAFETY: preflight proved this allocation is neither free nor
            // quarantined, so the transition into the quarantine is exclusive.
            if let Some((vptr, vlayout)) = unsafe { poison::quarantine(&mut g.quarantine, ptr, carve_layout, free_ip) } {
                // Record provenance BEFORE reinsertion: once this span is a
                // real hole again, this is the last point anything knows
                // "what used to be here" for a corruption discovered later.
                g.holes.record_evicted(vptr as usize, vlayout.size() as u32, free_ip);
                // SAFETY: `vptr` was quarantined from a prior alloc via `quarantine`; now evicted, so reclaim it to the hole list.
                let vnn = unsafe { core::ptr::NonNull::new_unchecked(vptr) };
                // SAFETY: evicted quarantined block; re-insert into the hole list.
                assert!(unsafe { g.holes.dealloc(vnn, vlayout) }.is_ok(), "kalloc invalid free");
                #[cfg(feature = "debug-hw-watchpoint")]
                { freed_hdr = Some(vptr as usize); }
            }
            drop(g);
            // debug-hw-watchpoint: arm the write-watchpoint on the block that
            // just rejoined the free list (lock dropped — the hook reaches into
            // the arch debug-register path).
            #[cfg(feature = "debug-hw-watchpoint")]
            if let Some(a) = freed_hdr { arm_watchpoint(a); }
            self.periodic_validate(free_ip);
            return;
        }
        let mut g = self.inner.lock();
        // Bounded live-allocation size ledger (`debug-dealloc-diag`, see
        // `size_track.rs`): if this exact pointer was recorded at alloc
        // time with a DIFFERENT size than what's being freed with now, the
        // caller's Layout is wrong — `add_free_region` has no way to detect
        // this itself (it only checks the freed range against OTHER FREE
        // nodes, never against live neighbors), so an oversized dealloc
        // here silently corrupts whatever live allocation follows. This is
        // the direct, targeted check for that whole bug class.
        #[cfg(feature = "debug-dealloc-diag")]
        if let Some(recorded) = g.size_track.take(ptr as usize) {
            if recorded != carve_layout.size() {
                klog::write_primary_raw(b"[KALLOC] size-mismatch ptr=");
                klog::write_primary_hex_u64(ptr as u64);
                klog::write_primary_raw(b" alloc_size=");
                klog::write_primary_dec_u64(recorded as u64);
                klog::write_primary_raw(b" dealloc_size=");
                klog::write_primary_dec_u64(carve_layout.size() as u64);
                klog::write_primary_raw(b" dealloc_caller_ip=0x");
                klog::write_primary_hex_u64(caller::dealloc_return_ip());
                klog::write_primary_raw(b"\n");
                panic!("kalloc dealloc size mismatch");
            }
        }
        // B1346: record this block's dealloc-return-IP for corruption
        // provenance BEFORE dealloc coalesces/reinserts it. If this exact block
        // is later found corrupt as a free-list node, its last free-IP names
        // where the stale-pointer WRITER freed its own object (addr2line the IP).
        #[cfg(any(feature = "debug-heappoison", feature = "debug-dealloc-diag"))]
        g.holes.record_free_ip(ptr as usize, caller::dealloc_return_ip());
        #[cfg(feature = "debug-dealloc-diag")]
        record_recent_op(free_ip, ptr as usize, false);
        // SAFETY: same as above; routed through HoleList::dealloc which
        // re-inserts the region into the sorted hole list.
        let dealloc_result = unsafe { g.holes.dealloc(nn, carve_layout) };
        // Print BEFORE the assert: this is the only diagnostic this
        // failure gets on a non-debug-heappoison build (the fast,
        // reliable ~15s smoke-profile repro of this session's corruption
        // hunt runs bare `debug-boot`, not `debug-heappoison` -- that
        // feature changes kalloc's internal timing enough to mask the
        // fast repro). Tag alone narrows MalformedNode/OverlappingFree/
        // OutsideOwnedRegion/AddressOverflow into very different
        // mechanisms.
        #[cfg(feature = "debug-dealloc-diag")]
        if let Err(e) = dealloc_result {
            klog::write_primary_raw(b"[KALLOC] dealloc-failed tag=");
            klog::write_primary_raw(e.tag());
            klog::write_primary_raw(b" ptr=");
            klog::write_primary_hex_u64(ptr as u64);
            klog::write_primary_raw(b" size=");
            klog::write_primary_dec_u64(carve_layout.size() as u64);
            klog::write_primary_raw(b" align=");
            klog::write_primary_dec_u64(carve_layout.align() as u64);
            klog::write_primary_raw(b"\n");
        }
        assert!(dealloc_result.is_ok(), "kalloc invalid free");
        drop(g);
        // debug-hw-watchpoint: `ptr` is now (part of) a genuine free HoleHdr.
        // Arm a hardware write-watchpoint over its 16 bytes so a later stray
        // kernel write to the freed node #DB-traps and names the writer. If
        // `ptr` coalesced into a lower-addressed neighbor it's mid-region
        // rather than the header, so this catches the (common, unmerged) case
        // where the freed block stays its own header — single most-recently-
        // freed block, per the v1 diagnostic scope.
        //
        // Size-filtered on `WATCHPOINT_MIN_SIZE` (`limits.rs`): watching every
        // freed block was pure noise.
        #[cfg(feature = "debug-hw-watchpoint")]
        if carve_layout.size() >= WATCHPOINT_MIN_SIZE {
            arm_watchpoint(ptr as usize);
        }
        #[cfg(feature = "debug-heappoison")]
        self.periodic_validate(free_ip);
        #[cfg(feature = "debug-dealloc-diag")]
        self.periodic_validate_diag(free_ip);
    }
}
