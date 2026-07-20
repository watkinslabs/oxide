// Canonical resident-memory facts owned by address-space implementations.
//
// Linux reports these values through VM accounting, but the formatter must not
// infer them from buddy allocation: a PMM page can be slab, anonymous, page
// table, or a cache page.  The filesystem address-space owner is the only
// layer that knows when a resident cache/shmem frame is published, dirtied,
// sent to writeback, or removed.

use core::sync::atomic::{AtomicU64, Ordering};

/// Snapshot of resident address-space pages. `file_cache_pages` deliberately
/// excludes tmpfs/shmem pages; Linux reports the latter separately as Shmem.
/// `dirty_file_pages` and `writeback_file_pages` are mutually exclusive state
/// counts for regular-file cache pages. # C: O(1)
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MemoryPageSnapshot {
    pub file_cache_pages:     u64,
    pub dirty_file_pages:     u64,
    pub writeback_file_pages: u64,
    pub shmem_pages:          u64,
}

struct MemoryPageCounters {
    file_cache_pages:     AtomicU64,
    dirty_file_pages:     AtomicU64,
    writeback_file_pages: AtomicU64,
    shmem_pages:          AtomicU64,
}

static PAGES: MemoryPageCounters = MemoryPageCounters {
    file_cache_pages:     AtomicU64::new(0),
    dirty_file_pages:     AtomicU64::new(0),
    writeback_file_pages: AtomicU64::new(0),
    shmem_pages:          AtomicU64::new(0),
};

/// Subtract an owned transition without permitting a wrapped counter to become
/// a believable but false VM fact. Every caller has already removed the exact
/// owner entry; an underflow is an internal lifecycle violation. # C: O(1)
fn remove(counter: &AtomicU64, n: u64) {
    let mut old = counter.load(Ordering::Acquire);
    loop {
        hal::kassert!(old >= n, "memory page counter underflow");
        match counter.compare_exchange_weak(old, old - n, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(now) => old = now,
        }
    }
}

/// Snapshot facts that address-space implementations have published. This is
/// intentionally not a `/proc` renderer: callers aggregate it with facts from
/// PMM, reclaim, and VMM without reconstructing categories from allocations.
/// # C: O(1)
pub fn memory_page_snapshot() -> MemoryPageSnapshot {
    MemoryPageSnapshot {
        file_cache_pages:     PAGES.file_cache_pages.load(Ordering::Acquire),
        dirty_file_pages:     PAGES.dirty_file_pages.load(Ordering::Acquire),
        writeback_file_pages: PAGES.writeback_file_pages.load(Ordering::Acquire),
        shmem_pages:          PAGES.shmem_pages.load(Ordering::Acquire),
    }
}

/// Publish `n` regular-file cache frames after their page-index entries become
/// reachable. # C: O(1)
pub fn account_file_cache_publish(n: u64) { PAGES.file_cache_pages.fetch_add(n, Ordering::AcqRel); }

/// Remove `n` regular-file cache frames after their page-index entries stop
/// being reachable. # C: O(1)
pub fn account_file_cache_remove(n: u64) { remove(&PAGES.file_cache_pages, n); }

/// Transition `n` clean regular-file cache pages to dirty. Call only for a
/// clean→dirty set insertion; repeat writes to an already-dirty page are not a
/// second transition. # C: O(1)
pub fn account_file_cache_dirty(n: u64) { PAGES.dirty_file_pages.fetch_add(n, Ordering::AcqRel); }

/// Discard `n` dirty tags without writeback (truncate/invalidate). # C: O(1)
pub fn account_file_cache_discard_dirty(n: u64) { remove(&PAGES.dirty_file_pages, n); }

/// Move `n` dirty regular-file cache pages into writeback. Completion must call
/// [`account_file_cache_writeback_complete`] exactly once, including failure.
/// # C: O(1)
pub fn account_file_cache_writeback_begin(n: u64) {
    remove(&PAGES.dirty_file_pages, n);
    PAGES.writeback_file_pages.fetch_add(n, Ordering::AcqRel);
}

/// Finish `n` writeback pages, optionally returning `redirty` pages to dirty
/// state after I/O failure. `redirty <= n` is an owner invariant. # C: O(1)
pub fn account_file_cache_writeback_complete(n: u64, redirty: u64) {
    hal::kassert!(redirty <= n, "writeback redirty exceeds completion");
    remove(&PAGES.writeback_file_pages, n);
    PAGES.dirty_file_pages.fetch_add(redirty, Ordering::AcqRel);
}

/// Publish `n` resident shmem/tmpfs frames after their page-index entries are
/// reachable. # C: O(1)
pub fn account_shmem_publish(n: u64) { PAGES.shmem_pages.fetch_add(n, Ordering::AcqRel); }

/// Remove `n` resident shmem/tmpfs frames after their page-index entries stop
/// being reachable. # C: O(1)
pub fn account_shmem_remove(n: u64) { remove(&PAGES.shmem_pages, n); }

#[cfg(test)]
mod tests {
    use super::*;
    use sync::{Spinlock, TaskList as TaskListClass};

    static TEST_SERIAL: Spinlock<(), TaskListClass> = Spinlock::new(());

    #[test]
    fn file_cache_writeback_failure_returns_only_planned_pages_to_dirty() {
        let _serial = TEST_SERIAL.lock();
        let before = memory_page_snapshot();
        account_file_cache_publish(3);
        account_file_cache_dirty(3);
        account_file_cache_writeback_begin(3);
        assert_eq!(memory_page_snapshot(), MemoryPageSnapshot {
            file_cache_pages: before.file_cache_pages + 3,
            dirty_file_pages: before.dirty_file_pages,
            writeback_file_pages: before.writeback_file_pages + 3,
            shmem_pages: before.shmem_pages,
        });
        // One planned page was no longer flushable; the two actual I/O failures
        // are re-dirtied. This is the rollback shape used by framecache.
        account_file_cache_writeback_complete(3, 2);
        assert_eq!(memory_page_snapshot(), MemoryPageSnapshot {
            file_cache_pages: before.file_cache_pages + 3,
            dirty_file_pages: before.dirty_file_pages + 2,
            writeback_file_pages: before.writeback_file_pages,
            shmem_pages: before.shmem_pages,
        });
        account_file_cache_discard_dirty(2);
        account_file_cache_remove(3);
        assert_eq!(memory_page_snapshot(), before);
    }

    #[test]
    fn shmem_publish_rollback_leaves_no_file_cache_or_dirty_fact() {
        let _serial = TEST_SERIAL.lock();
        let before = memory_page_snapshot();
        account_shmem_publish(1);
        assert_eq!(memory_page_snapshot(), MemoryPageSnapshot {
            shmem_pages: before.shmem_pages + 1,
            ..before
        });
        account_shmem_remove(1);
        assert_eq!(memory_page_snapshot(), before);
    }
}
