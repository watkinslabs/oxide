use alloc::sync::{Arc, Weak};

use block::{BlockError, KResult};
use sync::{Spinlock, TaskList};
use crate::zsmalloc::ZsPool;

mod parse;
use parse::{parse_linux_bool, parse_mem_size};
mod backing;
use backing::Backing;
mod writeback;
mod idle;
pub(crate) use idle::monotonic_ns;
mod table;
use table::SlotTable;
mod compression;
pub(crate) use compression::{Compression, CompressionConfig};
/// Compatibility alias for the configured primary backend's canonical name.
/// The backend registry owns the string; this public constant never selects it.
pub const ZRAM_COMP_ALGORITHM: &str = Compression::Lz4.name();
mod stats;
mod slot;
pub(crate) use slot::{BackingFormat, Slot};
#[cfg(feature = "memory-tracking")]
mod tracking;
#[cfg(feature = "memory-tracking")]
pub use tracking::ZramBlockState;

pub const ZRAM_BLOCK_SIZE: u32 = 512;
/// Linux's primary compressor has compression priority zero; secondary
/// compressors occupy priorities one through three in the slot metadata.
pub(super) const PRIMARY_COMPRESSION_PRIORITY: u8 = 0;
/// Linux zram writeback accounting granularity (`bd_stat` and limits).
pub const ZRAM_WRITEBACK_ACCOUNTING_BYTES: u64 = 4096;
/// Linux default maximum number of concurrently submitted writeback requests.
pub const ZRAM_WRITEBACK_BATCH_SIZE_DEFAULT: u32 = 32;
/// Linux `notify_free` units added for one wholly discarded zram page.
pub(super) const NOTIFY_FREE_PER_DISCARDED_PAGE: u64 = 1;
/// Minimum encoded-object size eligible for recompression without a request threshold.
pub(super) const RECOMP_MIN_COMPRESSED_BYTES: usize = 0;
pub const ZRAM_DEBUG_STAT_VERSION: u32 = 1;
pub(super) const PAGE_BYTES: usize = hal::PAGE_SIZE_BYTES as usize;

/// Convert a Linux byte-valued zram sysfs setting to allocator pages.
/// Linux stores both `disksize` and `mem_limit` as `PAGE_ALIGN(value)`.
/// # C: O(1)
fn page_align(value: u64) -> KResult<u64> {
    let page = PAGE_BYTES as u64;
    value.checked_add(page - 1).map(|value| value / page * page).ok_or(BlockError::Einval)
}

/// Number of Linux writeback accounting units represented by one PMM page.
/// # C: O(1)
pub(super) const fn writeback_units_per_page() -> u64 {
    hal::PAGE_SIZE_BYTES / ZRAM_WRITEBACK_ACCOUNTING_BYTES
}

/// Round a 4 KiB-unit writeback budget down to whole zram pages, matching
/// Linux `writeback_limit_store` on hosts whose page exceeds 4 KiB.
/// # C: O(1)
pub(super) const fn align_writeback_limit(value: u64) -> u64 {
    value / writeback_units_per_page() * writeback_units_per_page()
}

pub(super) struct State {
    pub(super) size: u64,
    pub(super) limit: u64,
    pub(super) used: u64,
    pub(super) max: u64,
    pub(super) slots: SlotTable,
    pub(super) pool: ZsPool,
    pub(super) backing: Option<Backing>,
    pub(super) writeback_limit: u64,
    pub(super) writeback_batch_size: u32,
    /// Budget reserved by accepted writeback I/O. It is separate from the
    /// completed-write count so concurrent requests cannot oversubscribe the
    /// Linux-visible remaining limit.
    pub(super) writeback_reserved: u64,
    /// Accepted backing writes whose completion still owns a canonical slot.
    pub(super) active_writebacks: usize,
    pub(super) writeback_limit_enable: bool,
    pub(super) compressed_writeback: bool,
    pub(super) primary_algorithm: CompressionConfig,
    pub(super) recompression_algorithms: [Option<CompressionConfig>; 3],
    pub(super) backing_reads: u64,
    pub(super) backing_writes: u64,
    pub(super) reads: u64,
    pub(super) writes: u64,
    pub(super) failed_reads: u64,
    pub(super) failed_writes: u64,
    pub(super) invalid_io: u64,
    pub(super) notify_free: u64,
    pub(super) miss_free: u64,
    pub(super) huge_pages_since: u64,
    pub(super) pages_compacted: u64,
}

impl State {
    /// Return the immutable compressor configuration recorded by a zram slot.
    /// # C: O(1)
    pub(super) fn compression_config(&self, priority: u8) -> KResult<&CompressionConfig> {
        if priority == PRIMARY_COMPRESSION_PRIORITY { return Ok(&self.primary_algorithm); }
        let index = usize::from(priority).checked_sub(usize::from(PRIMARY_COMPRESSION_PRIORITY) + 1).ok_or(BlockError::Einval)?;
        self.recompression_algorithms.get(index).and_then(Option::as_ref).ok_or(BlockError::Einval)
    }

    pub(super) fn initialize_compressors(&mut self) -> KResult<()> {
        self.primary_algorithm.initialize()?;
        for config in self.recompression_algorithms.iter_mut().flatten() { config.initialize()?; }
        Ok(())
    }
}

pub struct Zram {
    pub(super) state: Spinlock<State, TaskList>,
    /// Stable strong-reference source for owned backing-I/O completions. A
    /// request completion keeps the device alive until it has resolved its
    /// canonical slot state, even if userspace closes its last fd meanwhile.
    self_ref: Spinlock<Weak<Zram>, TaskList>,
    /// Readers wait here while one owner reloads a backed slot. This is a
    /// process-context wait, never a polling loop over an in-flight disk I/O.
    #[cfg(target_os = "oxide-kernel")]
    pub(super) loading_waiters: sched::live::WaitList,
    #[cfg(target_os = "oxide-kernel")]
    pub(super) writeback_waiters: sched::live::WaitList,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZramStats {
    pub disksize: u64,
    pub mem_limit: u64,
    pub mem_used: u64,
    pub mem_used_max: u64,
    pub orig_data_size: u64,
    pub compr_data_size: u64,
    pub same_pages: u64,
    pub reads: u64,
    pub writes: u64,
    pub failed_reads: u64,
    pub failed_writes: u64,
    pub invalid_io: u64,
    pub notify_free: u64,
    pub miss_free: u64,
    pub pages_compacted: u64,
    pub huge_pages: u64,
    pub huge_pages_since: u64,
    pub backing_pages: u64,
    pub backing_reads: u64,
    pub backing_writes: u64,
    pub writeback_limit: u64,
    pub writeback_batch_size: u32,
    pub writeback_limit_enable: bool,
    pub compressed_writeback: bool,
}


impl Zram {
    /// Drain zspages detached by a completed state transaction. This acquires
    /// state only to take ownership, then releases PMM frames after dropping it.
    /// # C: O(number of retired zspages)
    pub(crate) fn drain_retired_zspages(&self) -> KResult<()> {
        let retired = { self.state.lock().pool.take_retired() };
        retired.release()
    }
    /// # C: O(1)
    pub fn new() -> Arc<Self> {
        #[cfg(any(test, feature = "hosted"))]
        crate::zsmalloc::install_hosted_test_provider();
        let zram = Arc::new(Self {
            state: Spinlock::new(State {
                size: 0, limit: 0, used: 0, max: 0, slots: SlotTable::new(), pool: ZsPool::new(),
                backing: None, writeback_limit: 0, writeback_batch_size: ZRAM_WRITEBACK_BATCH_SIZE_DEFAULT, writeback_reserved: 0, active_writebacks: 0, writeback_limit_enable: false, compressed_writeback: false,
                primary_algorithm: CompressionConfig::default_for(Compression::default_algorithm()), recompression_algorithms: [const { None }; 3], backing_reads: 0, backing_writes: 0,
                reads: 0, writes: 0, failed_reads: 0, failed_writes: 0, invalid_io: 0, notify_free: 0, miss_free: 0, huge_pages_since: 0, pages_compacted: 0,
            }),
            #[cfg(target_os = "oxide-kernel")]
            loading_waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            writeback_waiters: sched::live::WaitList::new(),
            self_ref: Spinlock::new(Weak::new()),
        });
        *zram.self_ref.lock() = Arc::downgrade(&zram);
        zram
    }

    pub(super) fn strong_ref(&self) -> Arc<Self> {
        self.self_ref.lock().upgrade().expect("live zram owns its completion reference")
    }

    /// # C: O(number of metadata chunks)
    pub fn set_disksize(&self, size: u64) -> KResult<()> {
        if size == 0 { return Err(BlockError::Einval); }
        let size = page_align(size)?;
        let count = usize::try_from(size / PAGE_BYTES as u64).map_err(|_| BlockError::Einval)?;
        let mut state = self.state.lock();
        if state.size != 0 { return Err(BlockError::Ebusy); }
        state.initialize_compressors()?;
        if let Err(error) = state.slots.resize(count) {
            state.primary_algorithm = CompressionConfig::default_for(Compression::default_algorithm());
            state.recompression_algorithms = [const { None }; 3];
            return Err(error);
        }
        state.size = size;
        Ok(())
    }

    /// Parse and apply Linux sysfs `disksize` bytes (`K`/`M`/`G` suffixes).
    /// # C: O(device pages) on initialisation
    pub fn set_disksize_text(&self, text: &str) -> KResult<()> { self.set_disksize(parse_mem_size(text)?) }

    /// # C: O(1)
    pub fn set_mem_limit(&self, limit: u64) -> KResult<()> {
        self.state.lock().limit = page_align(limit)?;
        Ok(())
    }

    /// Parse and apply Linux sysfs `mem_limit` bytes (`K`/`M`/`G` suffixes).
    /// # C: O(1)
    pub fn set_mem_limit_text(&self, text: &str) -> KResult<()> {
        self.set_mem_limit(parse_mem_size(text)?)
    }

    /// # C: O(logical metadata + backing claim release)
    pub fn reset(&self) -> KResult<()> {
        #[cfg(target_os = "oxide-kernel")]
        loop {
            let state = self.state.lock();
            if state.active_writebacks == 0 { break; }
            // SAFETY: reset publishes itself before dropping zram state;
            // writeback completion takes that lock, resolves its slot, wakes,
            // and only then permits this reset to release the backing claim.
            unsafe { self.writeback_waiters.park(); }
            drop(state);
            // SAFETY: reset has no state lock held and immediately yields.
            unsafe { sched::live::schedule::schedule(); }
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        if self.state.lock().active_writebacks != 0 { return Err(BlockError::Ebusy); }
        let (backing, retired) = {
            let mut state = self.state.lock();
            let retired = state.pool.retire_all()?;
            state.size = 0;
            state.limit = 0;
            state.used = 0;
            state.max = 0;
            state.slots.clear();
            state.pool = ZsPool::new();
            let backing = state.backing.take().map(|backing| backing.disk.name.clone());
            state.reads = 0;
            state.writes = 0;
            state.failed_reads = 0;
            state.failed_writes = 0;
            state.invalid_io = 0;
            state.notify_free = 0;
            state.miss_free = 0;
            state.huge_pages_since = 0;
            state.pages_compacted = 0;
            state.writeback_limit = 0;
            state.writeback_batch_size = ZRAM_WRITEBACK_BATCH_SIZE_DEFAULT;
            state.writeback_reserved = 0;
            state.writeback_limit_enable = false;
            state.compressed_writeback = false;
            state.primary_algorithm = CompressionConfig::default_for(Compression::default_algorithm());
            state.recompression_algorithms = [const { None }; 3];
            state.backing_reads = 0;
            state.backing_writes = 0;
            (backing, retired)
        };
        retired.release()?;
        if let Some(name) = backing { let _ = block::registry::release(&name); }
        Ok(())
    }
    /// # C: O(1)
    pub fn initialized(&self) -> bool { self.state.lock().size != 0 }

    /// Canonical Linux `backing_dev` path, or `None` before a device is claimed.
    /// # C: O(1)
    pub fn backing_dev(&self) -> Option<alloc::string::String> {
        let state = self.state.lock();
        state.backing.as_ref().map(|backing| backing.path.clone())
    }

    /// Persist every currently resident data page to the claimed backing disk.
    /// A page altered while its I/O is pending remains resident; its stale
    /// extent is released by the writeback transaction.
    /// # C: O(zram pages × backing page I/O)
    pub fn writeback_all(&self) -> KResult<()> {
        self.require_initialized()?;
        let slots = self.state.lock().slots.len();
        let result = crate::writeback::writeback_pages(self, 0..slots);
        self.drain_retired_zspages()?;
        result
    }

    /// Persist one zram page selected by its zero-based page index.
    /// # C: O(backing page I/O + compression)
    pub fn writeback_page_index(&self, index: u64) -> KResult<()> {
        self.require_initialized()?;
        let index = usize::try_from(index).map_err(|_| BlockError::Einval)?;
        let result = crate::writeback::writeback_page(self, index);
        self.drain_retired_zspages()?;
        result
    }

    /// Execute one Linux zram writeback selector (`idle`, `huge`,
    /// `huge_idle`, `incompressible`, or `page_index=`).
    /// # C: O(zram pages × backing page I/O)
    pub fn writeback_text(&self, text: &str) -> KResult<()> {
        self.require_initialized()?;
        let result = crate::writeback::writeback_text(self, text);
        self.drain_retired_zspages()?;
        result
    }

    /// Execute a Linux multi-compressor recompression request.
    /// # C: O(selected zram pages × compression)
    pub fn recompress_text(&self, text: &str) -> KResult<()> {
        self.require_initialized()?;
        let result = crate::writeback::recompress_text(self, text);
        self.drain_retired_zspages()?;
        result
    }

    /// Set the remaining Linux writeback budget in 4 KiB units, rounded down
    /// to whole zram pages before any backing I/O can consume it.
    /// # C: O(1)
    pub fn set_writeback_limit_text(&self, text: &str) -> KResult<()> {
        let pages = text.trim().parse::<u64>().map_err(|_| BlockError::Einval)?;
        self.state.lock().writeback_limit = align_writeback_limit(pages);
        Ok(())
    }

    /// Enable or disable enforcement of the configured writeback budget.
    /// # C: O(1)
    pub fn set_writeback_limit_enable_text(&self, text: &str) -> KResult<()> {
        let enabled = text.trim().parse::<u64>().map_err(|_| BlockError::Einval)? != 0;
        self.state.lock().writeback_limit_enable = enabled;
        Ok(())
    }

    /// Enable Linux compressed backing-store writeback before initialization.
    /// The zram slot table retains the exact compressed-object length needed
    /// to reconstruct a backing page, matching Linux's per-slot metadata.
    /// # C: O(1)
    pub fn set_compressed_writeback_text(&self, text: &str) -> KResult<()> {
        let enabled = parse_linux_bool(text)?;
        let mut state = self.state.lock();
        if state.size != 0 { return Err(BlockError::Ebusy); }
        state.compressed_writeback = enabled;
        Ok(())
    }

    /// Current Linux compressed-writeback configuration.
    /// # C: O(1)
    pub fn compressed_writeback(&self) -> bool { self.state.lock().compressed_writeback }

    /// # C: O(1)
    pub fn reset_mem_used_max(&self) -> KResult<()> {
        let mut state = self.state.lock();
        state.max = state.pool.allocated_bytes()?;
        Ok(())
    }

    /// Compact eligible zspages in place; stable handles remain valid because
    /// zsmalloc owns physical relocation and its object registry.
    /// # C: O(zspages cubed in the most fragmented class)
    pub fn compact(&self) -> KResult<()> {
        self.require_initialized()?;
        let retired = {
            let mut state = self.state.lock();
            let released = state.pool.compact()?;
            state.account_pool_usage()?;
            state.pages_compacted = state.pages_compacted.checked_add(released as u64).ok_or(BlockError::Eio)?;
            state.pool.take_retired()
        };
        retired.release()?;
        Ok(())
    }

    /// PMM shrinker count hook: report only zspages that can be detached by
    /// same-class compaction at this instant. # C: O(zspages squared)
    pub(crate) fn reclaimable_pages(&self) -> usize { self.state.lock().pool.reclaimable_pages() }

    /// PMM shrinker scan hook. It retains zram's State lock only while moving
    /// stable handles, then releases detached PMM frames after that lock drops.
    /// # C: O(zspages cubed)
    pub(crate) fn reclaim_pages(&self, target: usize) -> usize {
        if target == 0 || !self.initialized() { return 0; }
        let retired = {
            let mut state = self.state.lock();
            let Ok(released) = state.pool.compact_budget(target) else { return 0; };
            if state.account_pool_usage().is_err() { return 0; }
            let Ok(total) = state.pages_compacted.checked_add(released as u64).ok_or(BlockError::Eio) else { return 0; };
            state.pages_compacted = total;
            (released, state.pool.take_retired())
        };
        if retired.1.release().is_err() { return 0; }
        retired.0
    }

    /// # C: O(1)
    pub fn algorithm(&self) -> &'static str { self.state.lock().primary_algorithm.algorithm.name() }

    fn require_initialized(&self) -> KResult<()> {
        if self.initialized() { Ok(()) } else { Err(BlockError::Einval) }
    }
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicU32, Ordering};

    use block::{BlockDevice, BlockError, BlockRequest, MemDisk};
    use sync::TaskList;

    use super::{Slot, Zram, PAGE_BYTES, ZRAM_BLOCK_SIZE};

    static WRITEBACK_OVERFLOW_ID: AtomicU32 = AtomicU32::new(0);
    const FIRST_PAGE_BLOCK: u64 = 0;
    const FIRST_PAGE_INDEX: u64 = 0;
    const ONE_BACKING_PAGE: u64 = 1;
    /// The representable active-I/O maximum forces checked admission failure.
    const MAX_ACTIVE_WRITEBACKS: usize = usize::MAX;
    const RANDOM_SEED: u32 = 0x9e37_79b9;
    const XORSHIFT_LEFT_A: u32 = 13;
    const XORSHIFT_RIGHT: u32 = 17;
    const XORSHIFT_LEFT_B: u32 = 5;

    fn random_page() -> alloc::vec::Vec<u8> {
        let mut state = RANDOM_SEED;
        let mut page = alloc::vec![0; PAGE_BYTES];
        for byte in &mut page {
            state ^= state << XORSHIFT_LEFT_A;
            state ^= state >> XORSHIFT_RIGHT;
            state ^= state << XORSHIFT_LEFT_B;
            *byte = state as u8;
        }
        page
    }

    #[test]
    fn writeback_counter_overflow_preserves_slot_and_extent() {
        let id = WRITEBACK_OVERFLOW_ID.fetch_add(1, Ordering::Relaxed);
        let name = alloc::format!("zram-writeback-overflow-{}", id);
        let blocks = PAGE_BYTES as u64 / ZRAM_BLOCK_SIZE as u64;
        let disk: Arc<dyn BlockDevice> = MemDisk::<TaskList>::new(ZRAM_BLOCK_SIZE, blocks * ONE_BACKING_PAGE);
        assert_ne!(block::registry::register(&name, disk), 0);
        let zram = Zram::new();
        zram.set_backing_dev_text(&alloc::format!("/dev/{}", name)).unwrap();
        zram.set_disksize(PAGE_BYTES as u64).unwrap();
        zram.submit_sync(&mut BlockRequest::new_write(FIRST_PAGE_BLOCK, blocks as u32, random_page())).unwrap();
        zram.state.lock().active_writebacks = MAX_ACTIVE_WRITEBACKS;
        assert_eq!(zram.writeback_page_index(FIRST_PAGE_INDEX), Err(BlockError::Enomem));
        let mut state = zram.state.lock();
        assert!(matches!(state.slots.get(FIRST_PAGE_INDEX as usize), Some(Slot::Packed { .. } | Slot::Raw { .. })));
        assert!(state.backing.as_ref().expect("configured backing").extents.iter().all(|used| !*used));
        state.active_writebacks = 0;
        drop(state);
        zram.reset().unwrap();
        assert!(block::registry::unregister(&name));
    }
}
