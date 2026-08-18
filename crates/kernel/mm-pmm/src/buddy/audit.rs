use super::*;
use super::free_node::{read_u64, OFF_NEXT, OFF_ORDER, OFF_POISON};

impl<B: PageBacking, I: IrqGate> Pmm<B, I> {
    /// Walk the global buddy lists and every per-CPU pageset; panic on an
    /// invariant violation. Verifies I1, I3, I4, I6, I7. I2 and I5 follow
    /// from I1 + I4 and the construction algorithm, so they need no
    /// independent walk.
    ///
    /// # SAFETY
    /// The allocator must be quiescent: the audit holds the global buddy
    /// lock, then observes the non-nested pageset locks and their atomic
    /// accounting as one consistent state.
    /// # C: O(N)
    pub unsafe fn audit(&self) {
        let g = self.inner.lock_irqsave::<I>();
        let mut total_free = 0u64;
        let mut global_free = [0u64; NR_ZONES];
        for o in 0..ORDERS {
            let order = o as u8;
            let mut n = 0u64;
            for zi in 0..NR_ZONES {
                let mut cur = g.free_heads[zi][o];
                while cur != PFN_NULL {
                    kassert!(g.bitmap_get(order, cur >> o), "I3: free-list node not in bitmap");
                    kassert!(cur & ((1u64 << o) - 1) == 0, "I4: free-list node misaligned");
                    // I9: the WHOLE block belongs to the zone whose list holds
                    // it. Checking only the base is vacuous — the base is what
                    // chose the list — and it is the tail that escapes a
                    // bounded allocation's address limit when a merge crosses
                    // a zone boundary.
                    kassert!(g.layout.span_at(zi).contains(cur), "I9: free-list node in the wrong zone");
                    kassert!(cur + (1u64 << o) <= g.layout.span_at(zi).end_pfn, "I9: free block straddles a zone boundary");
                    n += 1;
                    // SAFETY: `cur` is a head node on the free list.
                    let p = unsafe { self.backing.page_ptr(Pfn(cur)) };
                    // SAFETY: read that head node's stable intrusive header.
                    let m = unsafe { read_u64(p, OFF_POISON) };
                    kassert!(m == POISON_MAGIC, "I7: poison missing on free node");
                    // SAFETY: `next` resides in the same head-node header.
                    cur = unsafe { read_u64(p, OFF_NEXT) };
                }
            }
            let mut counted = 0u64;
            for zi in 0..NR_ZONES {
                counted += g.free_count[zi][o];
                global_free[zi] += g.free_count[zi][o] << o;
            }
            kassert!(n == counted, "I3: free_count vs list-length mismatch");
            let mut bits = 0u64;
            for w in g.bitmaps[o].iter() { bits += w.load(Ordering::Relaxed).count_ones() as u64; }
            kassert!(bits == counted, "I1: bitmap pop vs free_count mismatch");
            total_free += counted << o;
        }

        let mut pcp_total = 0u64;
        let mut pcp_by_zone = [0u64; NR_ZONES];
        for zi in 0..NR_ZONES {
            for cpu in 0..cpu::MAX_CPUS {
                let pcp = self.pcp.list(cpu, zi).lock_irqsave::<I>();
                let mut cur = pcp.head();
                let mut counted = 0u64;
                while cur != PFN_NULL {
                    kassert!(cur < self.pfn_max, "I8: pageset node out of range");
                    kassert!(self.layout.index_of(cur) == zi, "I8: pageset node in wrong zone");
                    kassert!(self.pcp_marked(cur), "I8: pageset node absent from bitmap");
                    for order in 0..ORDERS {
                        kassert!(!g.bitmap_get(order as u8, cur >> order), "I8: pageset node is globally free");
                    }
                    // SAFETY: `cur` is a pageset node while its lock is held.
                    let page = unsafe { self.backing.page_ptr(Pfn(cur)) };
                    // SAFETY: inspect the fixed header before following next.
                    let poison = unsafe { read_u64(page, OFF_POISON) };
                    kassert!(poison == POISON_MAGIC, "I7: poison missing on pageset node");
                    // SAFETY: the node is owned by this pageset lock.
                    let order = unsafe { core::ptr::read(page.add(OFF_ORDER)) };
                    kassert!(order == 0, "I8: pageset node has nonzero order");
                    // SAFETY: next resides in this same fixed header.
                    let next = unsafe { read_u64(page, OFF_NEXT) };
                    kassert!(next == PFN_NULL || next < self.pfn_max, "I8: pageset next out of range");
                    kassert!(next != cur, "I8: pageset self link");
                    counted += 1;
                    kassert!(counted <= pcp.count(), "I8: pageset cycle or count mismatch");
                    cur = next;
                }
                kassert!(counted == pcp.count(), "I8: pageset count vs list-length mismatch");
                pcp_by_zone[zi] += counted;
                pcp_total += counted;
            }
        }
        let mut bitmap_total = 0u64;
        for word in self.pcp_bitmap {
            bitmap_total += word.load(core::sync::atomic::Ordering::Relaxed).count_ones() as u64;
        }
        kassert!(bitmap_total == pcp_total, "I8: pageset bitmap vs list-length mismatch");
        for zi in 0..NR_ZONES {
            let reported = self.pcp_free[zi].load(core::sync::atomic::Ordering::Acquire);
            kassert!(reported == pcp_by_zone[zi], "I8: pageset accounting vs list-length mismatch");
            let free = self.zone_free[zi].load(core::sync::atomic::Ordering::Acquire);
            kassert!(free == global_free[zi] + pcp_by_zone[zi], "I6: zone free accounting violated");
        }
        let allocated = g.allocated.checked_sub(pcp_total)
            .expect("I6: pageset count exceeds allocated accounting");
        kassert!(total_free + pcp_total + allocated == g.initial_free, "I6: total accounting violated");
    }
}
