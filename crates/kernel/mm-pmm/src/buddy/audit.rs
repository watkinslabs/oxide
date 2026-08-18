use super::*;
use super::free_node::{read_u64, OFF_NEXT, OFF_ORDER, OFF_POISON};

impl<B: PageBacking, I: IrqGate> Pmm<B, I> {
    /// Walk every global and per-CPU list, including its migratetype owner.
    /// # SAFETY: allocator transitions must be quiescent for the full walk.
    /// # C: O(N)
    pub unsafe fn audit(&self) {
        let g = self.inner.lock_irqsave::<I>();
        let mut total_global = 0u64;
        let mut global_by_zone = [0u64; NR_ZONES];
        for order_index in 0..ORDERS {
            let order = order_index as u8;
            let mut counted = 0u64;
            for zone in 0..NR_ZONES { for mt_index in 0..MIGRATE_TYPES {
                let mt = MigrateType::from_index(mt_index);
                let mut cur = g.free_heads[zone][mt_index][order_index];
                let mut list_count = 0u64;
                while cur != PFN_NULL {
                    kassert!(g.bitmap_get(order, cur >> order), "I3: free-list node not in bitmap");
                    kassert!(cur & ((1u64 << order) - 1) == 0, "I4: free-list node misaligned");
                    kassert!(g.layout.span_at(zone).contains(cur), "I9: free-list node in wrong zone");
                    kassert!(cur + (1u64 << order) <= g.layout.span_at(zone).end_pfn, "I9: free block straddles zone");
                    kassert!(g.migratetype(cur) == mt, "I3: free-list node wrong migratetype");
                    // SAFETY: cur is a globally free head under Buddy.
                    let page = unsafe { self.backing.page_ptr(Pfn(cur)) };
                    // SAFETY: inspect its fixed intrusive header.
                    kassert!(unsafe { read_u64(page, OFF_POISON) } == POISON_MAGIC, "I7: poison missing on free node");
                    // SAFETY: next resides in the same initialized header.
                    cur = unsafe { read_u64(page, OFF_NEXT) };
                    list_count += 1;
                }
                kassert!(list_count == g.free_count[zone][mt_index][order_index], "I3: free_count vs list-length mismatch");
                counted += list_count; global_by_zone[zone] += list_count << order;
            }}
            let bits: u64 = g.bitmaps[order_index].iter().map(|word| word.load(Ordering::Relaxed).count_ones() as u64).sum();
            kassert!(bits == counted, "I1: bitmap pop vs free_count mismatch");
            total_global += counted << order;
        }

        let mut pcp_total = 0u64;
        let mut pcp_by_zone = [0u64; NR_ZONES];
        for zone in 0..NR_ZONES { for mt_index in 0..MIGRATE_TYPES { for cpu in 0..cpu::MAX_CPUS {
            let mt = MigrateType::from_index(mt_index);
            let pcp = self.pcp.list(cpu, zone, mt).lock_irqsave::<I>();
            let mut cur = pcp.head(); let mut list_count = 0u64;
            while cur != PFN_NULL {
                kassert!(cur < self.pfn_max, "I8: pageset node out of range");
                kassert!(self.layout.index_of(cur) == zone, "I8: pageset node wrong zone");
                kassert!(self.pageblocks.get(cur) == mt, "I8: pageset node wrong migratetype");
                kassert!(self.pcp_marked(cur), "I8: pageset node absent from bitmap");
                for order in 0..ORDERS { kassert!(!g.bitmap_get(order as u8, cur >> order), "I8: pageset node globally free"); }
                // SAFETY: cur is owned by the held pageset list.
                let page = unsafe { self.backing.page_ptr(Pfn(cur)) };
                // SAFETY: inspect the fixed list header.
                let (poison, order, next) = unsafe { (read_u64(page, OFF_POISON), core::ptr::read(page.add(OFF_ORDER)), read_u64(page, OFF_NEXT)) };
                kassert!(poison == POISON_MAGIC, "I7: poison missing on pageset node");
                kassert!(order == 0, "I8: pageset node has nonzero order");
                kassert!(next == PFN_NULL || next < self.pfn_max, "I8: pageset next out of range");
                kassert!(next != cur, "I8: pageset self link");
                cur = next; list_count += 1; kassert!(list_count <= pcp.count(), "I8: pageset cycle or count mismatch");
            }
            kassert!(list_count == pcp.count(), "I8: pageset count vs list-length mismatch");
            pcp_total += list_count; pcp_by_zone[zone] += list_count;
        }}}
        let bitmap_total: u64 = self.pcp_bitmap.iter().map(|word| word.load(Ordering::Relaxed).count_ones() as u64).sum();
        kassert!(bitmap_total == pcp_total, "I8: pageset bitmap vs list-length mismatch");
        for zone in 0..NR_ZONES {
            kassert!(self.pcp_free[zone].load(Ordering::Acquire) == pcp_by_zone[zone], "I8: pageset accounting mismatch");
            kassert!(self.zone_free[zone].load(Ordering::Acquire) == global_by_zone[zone] + pcp_by_zone[zone], "I6: zone free accounting violated");
        }
        let allocated = g.allocated.checked_sub(pcp_total).expect("I6: pageset count exceeds allocated accounting");
        kassert!(total_global + pcp_total + allocated == g.initial_free, "I6: total accounting violated");
    }
}
