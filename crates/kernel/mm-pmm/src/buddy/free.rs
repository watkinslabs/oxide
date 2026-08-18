//! Free-side state transitions: order-0 pages enter a local pageset while
//! larger blocks immediately return to the mergeable buddy lists.

use super::*;
use super::double_free::{df_dump, df_note};
#[cfg(feature = "debug-pmm")]
use super::free_node::{read_u64, OFF_NEXT, OFF_ORDER, OFF_POISON, OFF_PREV};
use super::inner::PmmInner;

impl<B: PageBacking, I: IrqGate> Pmm<B, I> {
    /// Free one allocation. Order-0 pages take the per-CPU path; every larger
    /// block is merged immediately because retaining it would hide contiguous
    /// memory from higher-order callers.
    ///
    /// # SAFETY: `pfn` is aligned to `1 << order` and is still owned by the
    /// caller. It must have been returned by this PMM exactly once.
    /// # C: O(MAX_ORDER)
    /// # Ctx: any; brief IRQ-off
    /// # Lk: pageset for order-0; Buddy for larger blocks and pageset drains
    #[track_caller]
    pub unsafe fn free(&self, pfn: Pfn, order: Order) {
        hal::zerotrap::trap_buddy(pfn.0.wrapping_mul(hal::PAGE_SIZE_BYTES), b"FREE");
        let loc = core::panic::Location::caller();
        kassert!(order.0 <= MAX_ORDER, "pmm free invalid order");
        kassert!(pfn.0 < self.pfn_max, "pmm free pfn out of range");
        kassert!(pfn.0 & ((1u64 << order.0) - 1) == 0, "pmm free pfn misaligned for order");
        if order.0 == 0 {
            df_note(pfn.0, loc);
            self.free_to_pcp(pfn.0);
            return;
        }

        let zi = self.layout.index_of(pfn.0);
        kassert!(zi < NR_ZONES, "pmm free pfn outside zone layout");
        let mut g = self.inner.lock_irqsave::<I>();
        for ck in order.0..=MAX_ORDER {
            if g.bitmap_get(ck, pfn.0 >> ck) {
                df_dump(pfn.0, loc);
                kassert!(false, "pmm double free detected by bitmap");
            }
        }
        // SAFETY: the bitmap check proved pfn is not globally free; this
        // caller still owns the complete order-order block.
        unsafe { self.return_to_buddy(&mut g, pfn.0, order.0, loc) };
        let pages = 1u64 << order.0;
        g.allocated -= pages;
        g.free_events += 1;
        g.free_event_pages += pages;
        drop(g);
        self.zone_free[zi].fetch_add(pages, Ordering::AcqRel);
    }

    /// Place a known-free block into the mergeable buddy lists, coalescing
    /// only with a sibling that is already globally visible. PCP pages are
    /// intentionally not global siblings until their own drain transition.
    ///
    /// # SAFETY: caller holds `g`; pfn is a non-free block or a detached PCP
    /// page, and no one else can publish it while this transition runs.
    pub(super) unsafe fn return_to_buddy(
        &self,
        g: &mut PmmInner,
        pfn: u64,
        order: u8,
        loc: &'static core::panic::Location<'static>,
    ) {
        #[cfg(not(feature = "debug-pmm"))]
        let _ = loc;
        let mut p = pfn;
        let mut o = order;
        let zone = g.zi(p);
        let mt = g.migratetype(p);
        loop {
            if o == MAX_ORDER { break; }
            let buddy = p ^ (1u64 << o);
            if buddy + (1u64 << o) > g.pfn_max { break; }
            if g.zi(buddy) != zone || g.migratetype(buddy) != mt || !g.bitmap_get(o, buddy >> o) { break; }
            #[cfg(feature = "debug-pmm")]
            {
                // SAFETY: the buddy bitmap says this head is globally free.
                let bp = unsafe { self.backing.page_ptr(Pfn(buddy)) };
                // SAFETY: inspect the complete fixed FreeNode header.
                let magic = unsafe { read_u64(bp, OFF_POISON) };
                if magic != POISON_MAGIC {
                    // SAFETY: same globally owned header as the poison read.
                    let (next, prev, header_order) = unsafe {
                        (read_u64(bp, OFF_NEXT), read_u64(bp, OFF_PREV), read_u64(bp, OFF_ORDER))
                    };
                    klog::write_raw(b"[FWM-CORRUPT] free-node overwritten while free: pa=");
                    klog::write_hex_u64(buddy * PAGE_SIZE_BYTES);
                    klog::write_raw(b" pfn="); klog::write_hex_u64(buddy);
                    klog::write_raw(b" order="); klog::write_dec_u64(o as u64);
                    klog::write_raw(b" poison="); klog::write_hex_u64(magic);
                    klog::write_raw(b" next="); klog::write_hex_u64(next);
                    klog::write_raw(b" prev="); klog::write_hex_u64(prev);
                    klog::write_raw(b" ordhdr="); klog::write_hex_u64(header_order);
                    klog::write_raw(b" merged-from-free-of="); klog::write_hex_u64(pfn);
                    klog::write_raw(b" at="); klog::write_raw(loc.file().as_bytes());
                    klog::write_raw(b":"); klog::write_dec_u64(loc.line() as u64);
                    klog::write_raw(b"\n[FWM-CORRUPT] last freer of the corrupt frame:\n");
                    df_dump(buddy, loc);
                }
            }
            // SAFETY: bitmap truth names buddy as a global free-list node.
            unsafe { g.unlink_free(&self.backing, buddy, o, mt) };
            g.bitmap_clear(o, buddy >> o);
            g.free_count[zone][mt.index()][o as usize] -= 1;
            if buddy < p { p = buddy; }
            o += 1;
        }
        // SAFETY: p is aligned, in-range and not on any global free list.
        unsafe { g.push_free(&self.backing, p, o, mt) };
        g.bitmap_set(o, p >> o);
        g.free_count[zone][mt.index()][o as usize] += 1;
    }
}
