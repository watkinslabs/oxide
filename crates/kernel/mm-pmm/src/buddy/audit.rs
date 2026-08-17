use super::*;
use super::free_node::{read_u64, OFF_NEXT, OFF_POISON};

impl<B: PageBacking, I: IrqGate> Pmm<B, I> {
    /// Walk every order's bitmap + free-list; panic on invariant violation.
    /// Verifies I1, I3, I4, I6, I7. I2 and I5 follow from I1 + I4 and the
    /// construction algorithm, so they need no independent walk.
    ///
    /// # SAFETY
    /// Walks every populated bitmap word and each free-list head node.
    /// # C: O(N)
    pub unsafe fn audit(&self) {
        let g = self.inner.lock_irqsave::<I>();
        let mut total_free = 0u64;
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
            for zi in 0..NR_ZONES { counted += g.free_count[zi][o]; }
            kassert!(n == counted, "I3: free_count vs list-length mismatch");
            let mut bits = 0u64;
            for w in g.bitmaps[o].iter() { bits += w.load(Ordering::Relaxed).count_ones() as u64; }
            kassert!(bits == counted, "I1: bitmap pop vs free_count mismatch");
            total_free += counted << o;
        }
        kassert!(total_free + g.allocated == g.initial_free, "I6: total accounting violated");
    }
}
