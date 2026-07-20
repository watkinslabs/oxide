use block::KResult;

use super::{Slot, State, Zram, ZramStats, PAGE_BYTES};

impl State {
    /// Refresh Linux `mm_stat.mem_used_total` and its high-water mark from
    /// the allocator's physical page footprint, never object payload bytes.
    /// Returns whether the resulting footprint satisfies `mem_limit`.
    /// # C: O(number of pool pages)
    pub(crate) fn account_pool_usage(&mut self) -> KResult<bool> {
        let used = self.pool.allocated_bytes()?;
        self.used = used;
        self.max = self.max.max(used);
        Ok(self.limit == 0 || used <= self.limit)
    }
}

impl Zram {
    /// # C: O(logical zram pages)
    pub fn stats(&self) -> ZramStats {
        let state = self.state.lock();
        let mut orig_data_size = 0;
        let mut compr_data_size = 0;
        let mut same_pages = 0;
        let mut huge_pages = 0;
        for index in 0..state.slots.len() {
            let slot = state.slots.get(index).expect("zram slot index validated by table length");
            if !matches!(slot, Slot::Empty) { orig_data_size += PAGE_BYTES as u64; }
            compr_data_size += slot.bytes() as u64;
            if matches!(slot, Slot::Same(_)) { same_pages += 1; }
            if slot.is_huge() { huge_pages += 1; }
        }
        let backing_pages = state.backing.as_ref().map_or(0, |backing|
            backing.extents.iter().filter(|used| **used).count() as u64,
        );
        ZramStats {
            disksize: state.size, mem_limit: state.limit, mem_used: state.used,
            mem_used_max: state.max, orig_data_size, compr_data_size, same_pages,
            reads: state.reads, writes: state.writes,
            failed_reads: state.failed_reads, failed_writes: state.failed_writes,
            invalid_io: state.invalid_io, notify_free: state.notify_free,
            miss_free: state.miss_free,
            pages_compacted: state.pages_compacted, huge_pages, huge_pages_since: state.huge_pages_since,
            backing_pages, backing_reads: state.backing_reads, backing_writes: state.backing_writes,
            writeback_limit: state.writeback_limit, writeback_batch_size: state.writeback_batch_size, writeback_limit_enable: state.writeback_limit_enable,
            compressed_writeback: state.compressed_writeback,
        }
    }
}
