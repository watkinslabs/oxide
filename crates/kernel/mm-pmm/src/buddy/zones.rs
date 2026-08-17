// Per-zone thresholds and observation: the sole producer of the watermarks
// the allocation gate reads, and the per-zone rows a statistics file reports.
use super::*;

impl<B: PageBacking, I: IrqGate> Pmm<B, I> {
    /// Recompute per-zone watermarks from the current tunables and publish
    /// their aggregate to the reclaim policy. Driven once the boot path has
    /// seeded every zone, and again whenever the tunables change; a zone's
    /// share of the total minimum is proportional to the pages it manages, so
    /// both the per-zone allocation gate and the whole-system reclaim policy
    /// come from this one derivation.
    /// # C: O(NR_ZONES); # Lk: Buddy
    pub fn refresh_watermarks(&self, tunables: crate::watermark::WatermarkTunables) {
        let derived = {
            let mut g = self.inner.lock_irqsave::<I>();
            g.tunables = Some(tunables);
            g.recompute_derived()
        };
        if let Some((total, agg)) = derived {
            let right = crate::watermark::PublishGuard::acquire();
            crate::watermark::publish(&right, total, agg);
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
                present_pages: g.present[zi],
                managed_pages: g.managed[zi],
                free_pages: g.zone_free_pages(zi),
                free_orders: g.free_count[zi],
                wmark: g.wmark[zi],
                lowmem_reserve: g.reserve[zi],
            };
        }
        out
    }
}
