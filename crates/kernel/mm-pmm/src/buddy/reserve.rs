// Permanent boot-path reservations. Pages taken here leave a zone's managed
// count for good, so every threshold derived from that count is re-derived
// before the lock is released.
use super::*;

impl<B: PageBacking, I: IrqGate> Pmm<B, I> {
    /// Reserve `[start, start+len_pfn)` from the boot path. Called
    /// after [`Pmm::init`] for kernel-image / ACPI / framebuffer
    /// ranges that were inside a usable region (`10§6.3`). Reserved
    /// pages count as `allocated` permanently.
    ///
    /// # C: O(len_pfn × MAX_ORDER)
    /// # Ctx: pre-init, single-CPU
    pub fn reserve_early(&self, start: Pfn, len_pfn: u64) -> KResult<()> {
        self.reserve_early_inner(start, len_pfn, false, false)
    }

    /// Permanently reserve a boot range whose contents must not enter a hibernation image.
    /// # C: O(len_pfn × MAX_ORDER)
    /// # Ctx: pre-init, single-CPU
    pub fn reserve_early_nosave(&self, start: Pfn, len_pfn: u64) -> KResult<()> {
        self.reserve_early_inner(start, len_pfn, true, false)
    }

    /// Reserve a boot range only if every page is still free.
    ///
    /// Unlike the compatibility reservation above, this operation is
    /// transactional with respect to the requested range: a caller that is
    /// publishing a physical region must not receive success after the
    /// allocator skipped pages already claimed by the kernel image, firmware,
    /// or an earlier reservation.  The preflight and the removal run under
    /// the same allocator lock, so no intervening allocator operation can
    /// invalidate the answer.
    pub fn reserve_early_exact(&self, start: Pfn, len_pfn: u64) -> KResult<()> {
        self.reserve_early_inner(start, len_pfn, true, true)
    }

    fn reserve_early_inner(&self, start: Pfn, len_pfn: u64, nosave: bool, exact: bool) -> KResult<()> {
        let mut g = self.inner.lock_irqsave::<I>();
        let end = start.0.checked_add(len_pfn).ok_or(Error::OutOfRange)?;
        if end > g.pfn_max { return Err(Error::OutOfRange); }
        if exact {
            let mut p = start.0;
            while p < end {
                if !(0..=MAX_ORDER).any(|o| g.bitmap_get(o, p >> o)) {
                    return Err(Error::Overlap);
                }
                p += 1;
            }
        }
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
                if nosave { self.hibernate_forbid(Pfn(p)); }
                p += 1;
                continue;
            };
            let mut blk = (p >> o) << o;
            // Remove from free-list at order o.
            // SAFETY: bitmap-truth says blk is on free_list[o].
            let zi = g.zi(blk);
            let mt = g.migratetype(blk);
            // SAFETY: bitmap-truth says this exact block is linked on the derived list.
            unsafe { g.unlink_free(&self.backing, blk, o, mt) };
            g.bitmap_clear(o, blk >> o);
            g.free_count[zi][mt.index()][o as usize] -= 1;
            // Split down to order 0 along the half containing p.
            while o > 0 {
                o -= 1;
                let half = 1u64 << o;
                let buddy = blk + half;
                if p >= buddy {
                    // SAFETY: half is order-o aligned, in-range, not on
                    // any list (just split out).
                    unsafe { g.push_free(&self.backing, blk, o, mt) };
                    g.bitmap_set(o, blk >> o);
                    g.free_count[zi][mt.index()][o as usize] += 1;
                    blk = buddy;
                } else {
                    // SAFETY: buddy is order-o aligned, in-range, not on
                    // any list (just split out).
                    unsafe { g.push_free(&self.backing, buddy, o, mt) };
                    g.bitmap_set(o, buddy >> o);
                    g.free_count[zi][mt.index()][o as usize] += 1;
                }
            }
            // blk now == p; consume it as permanently reserved.
            debug_assert_eq!(blk, p);
            g.allocated += 1;
            g.reserved += 1;
            g.managed[zi] -= 1;
            if nosave { self.hibernate_forbid(Pfn(p)); }
            self.zone_free[zi].fetch_sub(1, Ordering::AcqRel);
            p += 1;
        }
        // The reservation took pages out of a zone's managed count, so every
        // threshold derived from that count is now stale. Recompute before
        // releasing the lock; publish the aggregate after.
        let derived = g.recompute_derived();
        for zi in 0..NR_ZONES {
            self.pcp_zone[zi].refresh(g.wmark[zi], g.reserve[zi], g.managed[zi]);
        }
        drop(g);
        if let Some((total, agg)) = derived {
            let right = crate::watermark::PublishGuard::acquire();
            crate::watermark::publish(&right, total, agg);
        }
        Ok(())
    }
}
