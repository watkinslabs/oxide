// Construction. Resolves the zone partition from the platform's limits,
// seeds every usable region into the zone that owns it, and derives the
// state that is a function of the resulting per-zone managed counts.
use super::*;
use super::inner::PmmInner;

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
            present: [0; NR_ZONES],
            spanned,
            reserve: [[0; NR_ZONES]; NR_ZONES],
            wmark: [ZoneWatermarks::default(); NR_ZONES],
            tunables: None,
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
        // Watermarks stay unset here, as they do in the reference: they are a
        // function of the final managed totals, which the boot path publishes
        // once every zone is seeded.
        let _ = inner.recompute_derived();

        Ok(Self { backing, inner: Spinlock::new(inner), _i: PhantomData })
    }
}
