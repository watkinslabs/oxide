use super::*;
use super::double_free::{df_dump, df_note};
use super::free_node::{read_u64, OFF_NEXT};
#[cfg(feature = "debug-pmm")]
use super::free_node::{OFF_ORDER, OFF_POISON, OFF_PREV};
use super::inner::PmmInner;

/// PMM owner. Single-instance kernel-wide; constructed in the boot path
/// after the firmware memory map is parsed (`10§6.3`). All access goes
/// through the `Buddy` spinlock per `10§7`. Generic over `IrqGate` per
/// `06§3.1`: kernel targets pass `hal_x86_64::X86IrqGate` /
/// `hal_aarch64::ArmIrqGate` to actually disable IRQs around the lock;
/// hosted tests use `NoopIrq`.
pub struct Pmm<B: PageBacking, I: IrqGate = NoopIrq> {
    /// Backing held outside the lock so `page_ptr` is lock-free.
    /// PageBacking::page_ptr is pure pointer arithmetic; concurrent
    /// callers see the same address. Higher-rank consumers (slab at
    /// rank Slab=10) can safely call `page_ptr` while holding their
    /// own spinlock without violating `06§3.6` partial order.
    pub(super) backing: B,
    pub(super) inner: Spinlock<PmmInner, Buddy>,
    _i: PhantomData<fn() -> I>,
}

impl<B: PageBacking, I: IrqGate> Pmm<B, I> {
    /// Build a PMM from one or more usable physical regions. Each
    /// region is greedy-largest-aligned-block seeded; the union must
    /// not overlap (caller invariant per `10§6.3`).
    ///
    /// # C: O(n + N) where n=regions, N=max_pfn / smallest order
    /// # Ctx: pre-init, single-CPU
    pub fn init(backing: B, regions: &[UsableRegion]) -> KResult<Self> {
        Self::init_zoned(backing, regions, None)
    }

    /// As [`Pmm::init`], with the zone boundaries supplied by the platform.
    /// `None` uses the boundaries this arch derives from its own limits.
    ///
    /// # C: O(n + N) where n=regions, N=max_pfn / smallest order
    /// # Ctx: pre-init, single-CPU
    pub fn init_zoned(backing: B, regions: &[UsableRegion], limits: Option<ZoneLimits>) -> KResult<Self> {
        if regions.is_empty() { return Err(Error::OutOfRange); }
        let mut pfn_max: u64 = 0;
        let mut total: u64 = 0;
        for r in regions {
            let end = r.start.0.checked_add(r.len_pfn).ok_or(Error::OutOfRange)?;
            if end > pfn_max { pfn_max = end; }
            total = total.checked_add(r.len_pfn).ok_or(Error::OutOfRange)?;
        }
        // Defensive overlap detection — caller invariant per `10§6.3`,
        // but seeding the same page twice corrupts the free-list, so
        // reject at boot rather than crash later.
        for i in 0..regions.len() {
            let a = &regions[i];
            if a.len_pfn == 0 { continue; }
            let a_end = a.start.0 + a.len_pfn;
            for j in (i + 1)..regions.len() {
                let b = &regions[j];
                if b.len_pfn == 0 { continue; }
                let b_end = b.start.0 + b.len_pfn;
                if a.start.0 < b_end && b.start.0 < a_end {
                    return Err(Error::Overlap);
                }
            }
        }

        let mut bitmaps = [&[][..]; ORDERS];
        for o in 0..ORDERS {
            let blocks = (pfn_max + (1u64 << o) - 1) >> o;
            let words = ((blocks + 63) >> 6) as usize;
            bitmaps[o] = backing.bitmap_storage(o as u8, words);
        }

        let layout = ZoneLayout::new(limits.unwrap_or_else(|| ZoneLimits::arch_default(pfn_max, PAGE_SIZE_BYTES)), pfn_max);
        let mut spanned = [0u64; NR_ZONES];
        for zi in 0..NR_ZONES { spanned[zi] = layout.span_at(zi).spanned_pages(); }

        let mut inner = PmmInner {
            pfn_max,
            bitmaps,
            layout,
            zonelist: Zonelist::default(),
            free_heads: [[PFN_NULL; ORDERS]; NR_ZONES],
            free_count: [[0; ORDERS]; NR_ZONES],
            managed: [0; NR_ZONES],
            spanned,
            reserve: [[0; NR_ZONES]; NR_ZONES],
            wmark: [ZoneWatermarks::default(); NR_ZONES],
            allocated: 0,
            reserved: 0,
            initial_free: total,
            alloc_events: 0,
            alloc_event_pages: 0,
            free_events: 0,
            free_event_pages: 0,
        };

        for r in regions {
            // SAFETY: caller-asserted regions disjoint and in-range; the
            // pages have not been touched by any other subsystem yet.
            unsafe { inner.seed_range(&backing, r.start.0, r.start.0 + r.len_pfn) };
        }

        // A zone with no seeded page is not a fallback candidate: entering it
        // costs a walk step and can never answer.
        let mut populated = [false; NR_ZONES];
        for zi in 0..NR_ZONES { populated[zi] = inner.managed[zi] > 0; }
        inner.zonelist = Zonelist::build(populated);
        inner.reserve = lowmem_reserve(inner.managed, DEFAULT_LOWMEM_RESERVE_RATIO);

        Ok(Self { backing, inner: Spinlock::new(inner), _i: PhantomData })
    }

    /// Recompute per-zone watermarks from the current tunables. Called once
    /// the boot path knows the managed totals, and again whenever the
    /// tunables change. # C: O(NR_ZONES); # Lk: Buddy
    pub fn refresh_watermarks(&self, tunables: crate::watermark::WatermarkTunables) {
        let mut g = self.inner.lock_irqsave::<I>();
        let total: u64 = g.managed.iter().sum();
        for zi in 0..NR_ZONES {
            g.wmark[zi] = crate::watermark::derive_zone_watermarks(g.managed[zi], total, tunables, PAGE_SIZE_BYTES);
        }
    }

    /// Per-zone observation for the statistics files. # C: O(NR_ZONES*ORDERS)
    /// # Lk: Buddy
    pub fn zone_snapshot(&self) -> [ZoneStat; NR_ZONES] {
        let g = self.inner.lock_irqsave::<I>();
        let mut out = [ZoneStat::EMPTY; NR_ZONES];
        for zi in 0..NR_ZONES {
            let span = g.layout.span_at(zi);
            out[zi] = ZoneStat {
                zone: ZoneType::from_index(zi).unwrap_or(ZoneType::Movable),
                start_pfn: span.start_pfn,
                spanned_pages: g.spanned[zi],
                present_pages: g.managed[zi],
                managed_pages: g.managed[zi],
                free_pages: g.zone_free_pages(zi),
                free_orders: g.free_count[zi],
                wmark: g.wmark[zi],
                lowmem_reserve: g.reserve[zi],
            };
        }
        out
    }

    /// Reserve `[start, start+len_pfn)` from the boot path. Called
    /// after [`Pmm::init`] for kernel-image / ACPI / framebuffer
    /// ranges that were inside a usable region (`10§6.3`). Reserved
    /// pages count as `allocated` permanently.
    ///
    /// # C: O(len_pfn × MAX_ORDER)
    /// # Ctx: pre-init, single-CPU
    pub fn reserve_early(&self, start: Pfn, len_pfn: u64) -> KResult<()> {
        let mut g = self.inner.lock_irqsave::<I>();
        let end = start.0.checked_add(len_pfn).ok_or(Error::OutOfRange)?;
        if end > g.pfn_max { return Err(Error::OutOfRange); }
        let mut p = start.0;
        while p < end {
            // Find smallest containing block currently on a free-list.
            let mut k: Option<u8> = None;
            for o in 0..=MAX_ORDER {
                if g.bitmap_get(o, p >> o) { k = Some(o); break; }
            }
            let Some(mut o) = k else {
                // Page already allocated/reserved by an earlier call,
                // or outside seeded RAM. Skip.
                p += 1;
                continue;
            };
            let mut blk = (p >> o) << o;
            // Remove from free-list at order o.
            // SAFETY: bitmap-truth says blk is on free_list[o].
            let zi = g.zi(blk);
            unsafe { g.unlink_free(&self.backing, blk, o) };
            g.bitmap_clear(o, blk >> o);
            g.free_count[zi][o as usize] -= 1;
            // Split down to order 0 along the half containing p.
            while o > 0 {
                o -= 1;
                let half = 1u64 << o;
                let buddy = blk + half;
                if p >= buddy {
                    // SAFETY: half is order-o aligned, in-range, not on
                    // any list (just split out).
                    unsafe { g.push_free(&self.backing, blk, o) };
                    g.bitmap_set(o, blk >> o);
                    g.free_count[zi][o as usize] += 1;
                    blk = buddy;
                } else {
                    // SAFETY: buddy is order-o aligned, in-range, not on
                    // any list (just split out).
                    unsafe { g.push_free(&self.backing, buddy, o) };
                    g.bitmap_set(o, buddy >> o);
                    g.free_count[zi][o as usize] += 1;
                }
            }
            // blk now == p; consume it as permanently reserved.
            debug_assert_eq!(blk, p);
            g.allocated += 1;
            g.reserved += 1;
            g.managed[zi] -= 1;
            p += 1;
        }
        Ok(())
    }

    /// Allocate one buddy block of `order`. Returns the base PFN.
    /// Always picks lower half on split (deterministic) per `10§6.1`.
    /// Verifies the head free-node inside lock; zeros pages outside lock.
    ///
    /// # C: O(MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off
    /// # Lk: Buddy
    pub fn alloc(&self, order: Order) -> KResult<Pfn> {
        self.alloc_gfp(order, 0)
    }

    /// Allocate one buddy block of `order` for an allocation whose zone bits
    /// are `gfp`. The bits name the highest zone the block may come from; the
    /// walk descends from there and can never rise above it, so a bounded
    /// request that cannot be met fails instead of escaping its bound.
    ///
    /// # C: O(NR_ZONES × MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off
    /// # Lk: Buddy
    pub fn alloc_gfp(&self, order: Order, gfp: u32) -> KResult<Pfn> {
        let Ok(zone) = crate::zone::gfp_zone(gfp) else { return Err(Error::InvalidOrder) };
        let hi = zone.index();
        // Preserve the allocator ABI: invalid orders are rejected by
        // `alloc_inner` before any order-derived arithmetic is evaluated.
        if order.0 <= MAX_ORDER {
            crate::watermark::before_allocation(self.free_pages(), 1u64 << order.0);
        }
        let mut r = self.alloc_inner_zoned(order, hi, AllocWmark::Low);
        // Exhaustion is not the answer until reclaim and the out-of-memory
        // selector have both been given their turn: any allocation that
        // cannot be satisfied enters the slowpath, not only a user fault.
        if matches!(r, Err(Error::NoMem)) { r = self.alloc_slowpath(order, hi); }
        if r.is_ok() { crate::watermark::after_allocation(self.free_pages()); }
        if let Ok(pfn) = r { hal::zerotrap::trap_buddy(pfn.0 * hal::PAGE_SIZE_BYTES, b"ALLOC"); }
        r
    }

    /// Allocate one buddy block wholly below `max_exclusive`.
    ///
    /// DMA masks are allocator constraints, not a driver's post-allocation
    /// rejection loop: selecting a suitable free block under the buddy lock
    /// preserves the ordinary ownership/accounting path without churning high
    /// memory. # C: O(free blocks + MAX_ORDER), bounded by managed memory
    /// # Ctx: any; brief IRQ-off
    /// # Lk: Buddy
    pub fn alloc_below(&self, order: Order, max_exclusive: Pfn) -> KResult<Pfn> {
        if order.0 > MAX_ORDER { return Err(Error::InvalidOrder); }
        let limit = max_exclusive.0;
        let span = 1u64 << order.0;
        if limit < span { return Err(Error::NoMem); }
        crate::watermark::before_allocation(self.free_pages(), span);
        let pfn = {
            let mut g = self.inner.lock_irqsave::<I>();
            let upper = core::cmp::min(limit, g.pfn_max);
            // Zones above the aperture cannot contain a qualifying block, and
            // the walk descends, so the search stays inside the bound by
            // construction; the per-candidate span check enforces it again for
            // the zone the aperture cuts through.
            let mut found = None;
            let mut pos = 0usize;
            'zones: while let Some(zi) = g.zonelist.entry(pos) {
                pos += 1;
                if g.layout.span_at(zi).start_pfn >= upper { continue; }
                for k in order.0..=MAX_ORDER {
                    let mut candidate = g.free_heads[zi][k as usize];
                    while candidate != PFN_NULL {
                        if candidate.checked_add(span).is_some_and(|end| end <= upper) {
                            found = Some((candidate, k, zi));
                            break 'zones;
                        }
                        // SAFETY: candidate is on this live free list, so its intrusive next field is readable.
                        let ptr = unsafe { self.backing.page_ptr(Pfn(candidate)) };
                        let next = unsafe { read_u64(ptr, OFF_NEXT) };
                        if next == PFN_NULL || next >= g.pfn_max { break; }
                        candidate = next;
                    }
                }
            }
            let Some((pfn, mut k, zi)) = found else { return Err(Error::NoMem); };
            // SAFETY: `pfn` was found on free_list[k] while holding the buddy lock.
            unsafe { g.unlink_free(&self.backing, pfn, k) };
            g.bitmap_clear(k, pfn >> k);
            g.free_count[zi][k as usize] -= 1;
            while k > order.0 {
                k -= 1;
                let buddy = pfn + (1u64 << k);
                // SAFETY: splitting the selected lower half creates one free, aligned upper buddy.
                unsafe { g.push_free(&self.backing, buddy, k) };
                g.bitmap_set(k, buddy >> k);
                g.free_count[zi][k as usize] += 1;
            }
            // SAFETY: the selected block is no longer on a free list and is exclusively PMM-owned.
            unsafe { g.verify_poison(&self.backing, pfn) };
            g.allocated += span;
            g.alloc_events += 1;
            g.alloc_event_pages += span;
            pfn
        };
        for k in 0..span {
            // SAFETY: this allocation exclusively owns every page in its selected buddy block.
            let p = unsafe { self.backing.page_ptr(Pfn(pfn + k)) };
            hal::zerotrap::trap(p as *const u8, PAGE_SIZE_BYTES as usize);
            // SAFETY: `p` spans one just-allocated PMM page and cannot alias another owner.
            unsafe { core::ptr::write_bytes(p, 0, PAGE_SIZE_BYTES as usize) };
        }
        crate::watermark::after_allocation(self.free_pages());
        hal::zerotrap::trap_buddy(pfn * hal::PAGE_SIZE_BYTES, b"ALLOC");
        Ok(Pfn(pfn))
    }

    /// Reclaim/kill retry loop taken when the fast path found no block.
    /// Policy lives in `crate::oom_entry`; this only supplies the three
    /// actions it drives.
    /// # C: bounded retries; # Ctx: blockable only; # Sleeps: yes
    fn alloc_slowpath(&self, order: Order, hi: usize) -> KResult<Pfn> {
        // The first thing the slowpath does, before deciding whether this
        // context may reclaim at all, is re-walk the zonelist against the min
        // watermark: a non-blocking caller is entitled to the part of the
        // reserve that a blockable one is not, and that attempt must happen
        // even when reclaim is closed to it.
        let wmark = if crate::oom_entry::context_allows_slowpath() { AllocWmark::Min } else { AllocWmark::MinNonBlock };
        if let Ok(pfn) = self.alloc_inner_zoned(order, hi, wmark) { return Ok(pfn); }
        let allowed = crate::oom_entry::context_allows_slowpath();
        match crate::oom_entry::run_slowpath(order.0, allowed,
            || self.alloc_inner_zoned(order, hi, wmark).ok(),
            crate::oom_entry::reclaim_once,
            crate::oom_entry::invoke_oom)
        {
            Some(pfn) => Ok(pfn),
            None => Err(Error::NoMem),
        }
    }

    /// Walk the fallback order from the highest permitted zone downward and
    /// take the first block a zone can give up without crossing its
    /// watermark. Every zone reached is at or below `hi`, which is what makes
    /// the address bound of a constrained request unconditional.
    fn alloc_inner_zoned(&self, order: Order, hi: usize, wmark: AllocWmark) -> KResult<Pfn> {
        if order.0 > MAX_ORDER { return Err(Error::InvalidOrder); }
        let pfn;
        let o = order.0;
        {
            let mut g = self.inner.lock_irqsave::<I>();
            let mut taken: Option<u64> = None;
            let mut pos = 0usize;
            while let Some(zi) = g.zonelist.entry(pos) {
                pos += 1;
                if zi > hi { continue; }
                let Some(zone) = ZoneType::from_index(zi) else { continue };
                let mark = match wmark { AllocWmark::Low => g.wmark[zi].low, _ => g.wmark[zi].min };
                let area = g.free_count[zi];
                if !zone_watermark_ok(zone, o, mark, wmark, &g.reserve, hi, &area) { continue; }
                // SAFETY: the buddy lock is held and `zi` came from the zonelist.
                if let Some(p) = unsafe { g.take_block(&self.backing, zi, o) } { taken = Some(p); break; }
            }
            let Some(p) = taken else { return Err(Error::NoMem); };
            pfn = p;
            // SAFETY: pfn is the popped (and possibly split-down) free block
            // head; verify its node before releasing the lock.
            unsafe { g.verify_poison(&self.backing, pfn) };
            let pages = 1u64 << o;
            g.allocated += pages;
            g.alloc_events += 1;
            g.alloc_event_pages += pages;
        }
        // Zero outside the lock per `10§6.1`. Backing is held outside
        // the spinlock so this loop never re-enters the Buddy lock.
        let span = 1u64 << o;
        for k in 0..span {
            // SAFETY: pfn..pfn+span is the just-allocated block, owned
            // by the caller; backing.page_ptr is pure ptr arithmetic.
            let p = unsafe { self.backing.page_ptr(Pfn(pfn + k)) };
            // The setup allocator poisons order-0 frees before `free` stamps
            // its intrusive header. Inspect the preserved body now: the zero
            // below is the first allocator write that would erase evidence of
            // a stale write while the page was free.
            #[cfg(feature = "debug-watchdog")]
            // SAFETY: p names the just-allocated, still-unzeroed page.
            unsafe {
                super::poison::report_watchdog_mismatch(
                    p,
                    (pfn + k) * PAGE_SIZE_BYTES,
                )
            };
            #[cfg(feature = "debug-cow")]
            // SAFETY: same ownership and bounds as the watchdog scan above.
            unsafe {
                super::poison::report_cow_mismatch(
                    p,
                    (pfn + k) * PAGE_SIZE_BYTES,
                )
            };
            // SAFETY: pointer is page-aligned and points to PAGE_SIZE_BYTES
            // of caller-owned memory; no aliasing for the duration.
            hal::zerotrap::trap((p) as *const u8, (PAGE_SIZE_BYTES as usize) as usize);
            // SAFETY: `p` is the HHDM address of a page this call just removed
            // from the free lists, so the allocator owns the whole
            // PAGE_SIZE_BYTES span exclusively and no other CPU can hold a
            // reference to it until the Pfn is returned to the caller.
            unsafe { core::ptr::write_bytes(p, 0, PAGE_SIZE_BYTES as usize) };
        }
        Ok(Pfn(pfn))
    }

    /// Free a buddy block; merge with its sibling iteratively up to
    /// `MAX_ORDER` per `10§6.2`. Sibling existence checked via bitmap
    /// (O(1) atomic), NOT free-list walk.
    ///
    /// # SAFETY: `pfn` is aligned to `1<<order` and was returned by a
    /// prior `alloc(order)` (or `reserve_early`-released — not v1).
    /// Double-free is detected by the bitmap-set check at entry.
    /// # C: O(MAX_ORDER) bounded
    /// # Ctx: any; brief IRQ-off
    /// # Lk: Buddy
    #[track_caller]
    pub unsafe fn free(&self, pfn: Pfn, order: Order) {
        // wrapping_mul: an out-of-range/garbage pfn (u64::MAX) must reach the
        // range kassert below, not panic here with an overflow message.
        hal::zerotrap::trap_buddy(pfn.0.wrapping_mul(hal::PAGE_SIZE_BYTES), b"FREE");
        // Original freeing call-site (via the #[track_caller] chain on
        // free_one_frame / dec_and_maybe_free_frame) — for the double-free
        // diagnostic ring.
        let loc = core::panic::Location::caller();
        kassert!(order.0 <= MAX_ORDER, "pmm free invalid order");
        let mut g = self.inner.lock_irqsave::<I>();
        let mut p = pfn.0;
        let mut o = order.0;
        kassert!(p < g.pfn_max, "pmm free pfn out of range");
        kassert!(p & ((1u64 << o) - 1) == 0, "pmm free pfn misaligned for order");
        for ck in o..=MAX_ORDER {
            if g.bitmap_get(ck, p >> ck) {
                // klog (serial/fbcon) neither takes the buddy lock nor frees
                // pages, so dumping while holding `g` is lock-order-safe.
                df_dump(pfn.0, loc);
                kassert!(false, "pmm double free detected by bitmap");
            }
        }
        // Record this (good) free so a LATER double free of this pfn can
        // name us as the prior freer. Only order-0 (the teardown granularity).
        if order.0 == 0 { df_note(pfn.0, loc); }
        let zone = g.zi(p);
        loop {
            if o == MAX_ORDER { break; }
            let buddy = p ^ (1u64 << o);
            if buddy + (1u64 << o) > g.pfn_max { break; }
            // A merged block must stay inside one zone: its accounting belongs
            // to one zone's lists, and a block straddling the boundary would
            // let a bounded allocation take pages above its bound.
            if g.zi(buddy) != zone { break; }
            if !g.bitmap_get(o, buddy >> o) { break; }
            // [debug-cow] FREE-WHILE-MAPPED trap: `buddy`'s bitmap says it is
            // free, so its FreeNode header MUST still carry POISON_MAGIC. If a
            // live owner overwrote the freed page (free-while-mapped / refcount
            // underflow), the poison is gone and the next/prev links below are
            // garbage — `unlink_free` would dereference them and #GP. Catch it
            // HERE, deterministically, and name the frame + its last freer
            // (df_dump reads the #[track_caller] free ring) so the premature
            // free's call-site is known instead of a bare #GP. Gated on
            // debug-pmm (the free-ring feature) — a minimal-overhead build that
            // keeps the corruption's timing close to a prod boot, unlike
            // debug-cow whose poison writes perturb it.
            #[cfg(feature = "debug-pmm")]
            {
                // SAFETY: buddy is order-o free per bitmap ⇒ PMM-owned page.
                let bp = unsafe { self.backing.page_ptr(Pfn(buddy)) };
                // SAFETY: 32B header read from an owned page.
                let m = unsafe { read_u64(bp, OFF_POISON) };
                if m != POISON_MAGIC {
                    // SAFETY: same owned page; dump the garbage links + order tag.
                    let (nx, pv, od) = unsafe {
                        (read_u64(bp, OFF_NEXT), read_u64(bp, OFF_PREV), read_u64(bp, OFF_ORDER))
                    };
                    klog::write_raw(b"[FWM-CORRUPT] free-node overwritten while free: pa=");
                    klog::write_hex_u64(buddy * PAGE_SIZE_BYTES);
                    klog::write_raw(b" pfn="); klog::write_hex_u64(buddy);
                    klog::write_raw(b" order="); klog::write_dec_u64(o as u64);
                    klog::write_raw(b" poison="); klog::write_hex_u64(m);
                    klog::write_raw(b" next="); klog::write_hex_u64(nx);
                    klog::write_raw(b" prev="); klog::write_hex_u64(pv);
                    klog::write_raw(b" ordhdr="); klog::write_hex_u64(od);
                    klog::write_raw(b" merged-from-free-of="); klog::write_hex_u64(pfn.0);
                    klog::write_raw(b" at="); klog::write_raw(loc.file().as_bytes());
                    klog::write_raw(b":"); klog::write_dec_u64(loc.line() as u64);
                    klog::write_raw(b"\n[FWM-CORRUPT] last freer of the corrupt frame:\n");
                    df_dump(buddy, loc);
                }
            }
            // SAFETY: bitmap I3 says buddy is on free_list[o].
            unsafe { g.unlink_free(&self.backing, buddy, o) };
            g.bitmap_clear(o, buddy >> o);
            g.free_count[zone][o as usize] -= 1;
            if buddy < p { p = buddy; }
            o += 1;
        }
        // SAFETY: p..p+(1<<o) is order-o aligned, in-range, not on any
        // free-list (just merged out of it or it's the original).
        unsafe { g.push_free(&self.backing, p, o) };
        g.bitmap_set(o, p >> o);
        g.free_count[zone][o as usize] += 1;
        let pages = 1u64 << order.0;
        g.allocated -= pages;
        g.free_events += 1;
        g.free_event_pages += pages;
    }

    /// Total free pages across all orders.
    /// # C: O(MAX_ORDER)
    pub fn free_pages(&self) -> u64 {
        let g = self.inner.lock_irqsave::<I>();
        let mut sum = 0u64;
        for zi in 0..NR_ZONES { sum += g.zone_free_pages(zi); }
        sum
    }

    /// Per-order free-block counts (`free_count[o]` = number of free
    /// order-`o` blocks). For `/proc/buddyinfo` (Linux `frag_show`).
    /// Read-only snapshot under the buddy lock.
    /// # C: O(ORDERS)
    pub fn free_orders(&self) -> [u64; ORDERS] {
        let g = self.inner.lock_irqsave::<I>();
        let mut out = [0u64; ORDERS];
        for zi in 0..NR_ZONES { for o in 0..ORDERS { out[o] += g.free_count[zi][o]; } }
        out
    }

    /// Total allocated pages.
    /// # C: O(1)
    pub fn allocated_pages(&self) -> u64 {
        self.inner.lock_irqsave::<I>().allocated
    }

    /// Total pfn span the PMM owns (`pfn_max`).
    /// # C: O(1)
    pub fn pfn_max(&self) -> u64 {
        self.inner.lock_irqsave::<I>().pfn_max
    }

    /// Snapshot buddy ownership and successful allocation/free events under
    /// one Buddy critical section. # C: O(MAX_ORDER); # Lk: Buddy
    pub fn snapshot(&self) -> PmmSnapshot {
        let g = self.inner.lock_irqsave::<I>();
        let mut free_pages = 0u64;
        for zi in 0..NR_ZONES { free_pages += g.zone_free_pages(zi); }
        PmmSnapshot {
            managed_pages: g.initial_free,
            free_pages,
            allocated_pages: g.allocated - g.reserved,
            reserved_pages: g.reserved,
            alloc_events: g.alloc_events,
            alloc_event_pages: g.alloc_event_pages,
            free_events: g.free_events,
            free_event_pages: g.free_event_pages,
        }
    }

    /// Page-aligned pointer to `pfn`. **Lock-free** — backing is stored
    /// outside the Buddy spinlock so callers at higher rank (slab at
    /// rank Slab=10) can invoke without violating `06§3.6`.
    ///
    /// # SAFETY: caller holds the page (no aliasing); pfn in-range.
    /// # C: O(1)
    pub unsafe fn page_ptr(&self, pfn: Pfn) -> *mut u8 {
        // SAFETY: backing.page_ptr is pure pointer arithmetic; pfn is
        // caller-owned per fn contract.
        unsafe { self.backing.page_ptr(pfn) }
    }

}
