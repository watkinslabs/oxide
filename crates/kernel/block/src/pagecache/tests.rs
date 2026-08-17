//! Page-cache tests (`17§7`).
//!
//! `query.rs`     — what a mapping holds, and the eviction that is a hint.
//! `radix.rs`     — the index tree on its own.
//! `locking.rs`   — `PG_LOCKED`: one fetch per miss however many race it.
//! `writeback.rs` — the dirty list, the thresholds, `fsync`, the flusher.
//! `reclaim.rs`   — the two-list LRU, and that eviction cannot lose a write.
//! `fstarget.rs`  — the write side as a filesystem uses it: a whole-mapping
//!                  target, a dirty mark that does not write back, and the
//!                  writer's own balance.
//! `frames.rs`    — a cached page as a machine frame, and the two eviction
//!                  paths that must leave a mapped one alone.

mod frames;
mod fstarget;
mod locking;
mod query;
mod radix;
mod reclaim;
mod writeback;

extern crate alloc;
use alloc::sync::Arc;

use core::sync::atomic::{AtomicUsize, Ordering};

use crate::blockdev::{BlockDevice, BlockRequest, MemDisk};
use crate::types::{BlockOp, KResult, PAGE_BYTES};

pub(super) type Disk = MemDisk<sync::Inode>;

/// The LRU, the dirty count and the thresholds are machine-wide by design, so
/// a test that asserts on them must be the only one running. Held for the
/// whole body; a poisoned lock still hands the section over, since the state
/// is reset on entry either way.
static MACHINE: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn fresh_machine() -> std::sync::MutexGuard<'static, ()> {
    let guard = MACHINE.lock().unwrap_or_else(|e| e.into_inner());
    super::global::reset_for_test();
    guard
}

/// A device that counts what reaches it, so "the page was written back" and
/// "the page was written back ONCE" are different assertions. Writes can also
/// be made to fail, which is how the re-dirty-on-failure path is reached
/// without a broken disk.
pub(super) struct CountingDisk {
    inner:  Arc<Disk>,
    writes: AtomicUsize,
    reads:  AtomicUsize,
    flushes: AtomicUsize,
    fail:   AtomicUsize,
}

impl CountingDisk {
    pub(super) fn new(pages: u64) -> Arc<Self> {
        Arc::new(Self {
            inner: Disk::new(512, pages * (PAGE_BYTES as u64 / 512)),
            writes: AtomicUsize::new(0), reads: AtomicUsize::new(0),
            flushes: AtomicUsize::new(0), fail: AtomicUsize::new(0),
        })
    }
    pub(super) fn writes(&self) -> usize { self.writes.load(Ordering::Acquire) }
    pub(super) fn reads(&self) -> usize { self.reads.load(Ordering::Acquire) }
    pub(super) fn flushes(&self) -> usize { self.flushes.load(Ordering::Acquire) }
    /// Make the next `n` writes fail.
    pub(super) fn fail_writes(&self, n: usize) { self.fail.store(n, Ordering::Release); }
    /// Read the medium directly, bypassing any cache.
    pub(super) fn medium_page(&self, offset: u64) -> alloc::vec::Vec<u8> {
        let blocks = (PAGE_BYTES / 512) as u32;
        let mut req = BlockRequest::new_read(offset / 512, blocks, 512);
        self.inner.submit_sync(&mut req).expect("medium read");
        req.buffer
    }
}

impl BlockDevice for CountingDisk {
    fn block_size(&self) -> u32 { self.inner.block_size() }
    fn capacity_blocks(&self) -> u64 { self.inner.capacity_blocks() }
    fn submit_sync(&self, req: &mut BlockRequest) -> KResult<()> {
        match req.op {
            BlockOp::Write => {
                self.writes.fetch_add(1, Ordering::AcqRel);
                let pending = self.fail.load(Ordering::Acquire);
                if pending > 0 {
                    self.fail.store(pending - 1, Ordering::Release);
                    return Err(crate::types::BlockError::Eio);
                }
            }
            BlockOp::Read => { self.reads.fetch_add(1, Ordering::AcqRel); }
            _ => {}
        }
        self.inner.submit_sync(req)
    }
    fn flush(&self) -> KResult<()> { self.flushes.fetch_add(1, Ordering::AcqRel); self.inner.flush() }
}

// ------------------------------------------------------- the frame provider
//
// A cached page becomes a machine frame only through the provider the machine
// installs, so every test about a mapped page needs one. This is that provider,
// backed by a leaked host pool: `pa` is an index into it, offset by one page so
// no valid frame has address zero — which the storage type reads as "on the
// heap".

/// Frames the test pool holds.
pub(super) const POOL_PAGES: usize = 64;
const FRAME_BASE: u64 = PAGE_BYTES as u64;

static NEXT_FRAME: AtomicUsize = AtomicUsize::new(0);
static RELEASED: AtomicUsize = AtomicUsize::new(0);
static POOL: AtomicUsize = AtomicUsize::new(0);
/// What the provider answers for "does a user page table map this frame".
/// Global rather than per frame: a test says which answer it is testing, and the
/// machine-wide test lock makes that unambiguous.
static ALL_MAPPED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

fn pool() -> *mut u8 {
    let held = POOL.load(Ordering::Acquire);
    if held != 0 { return held as *mut u8; }
    let fresh = alloc::boxed::Box::leak(alloc::vec![0u8; POOL_PAGES * PAGE_BYTES].into_boxed_slice())
        .as_mut_ptr();
    match POOL.compare_exchange(0, fresh as usize, Ordering::AcqRel, Ordering::Acquire) {
        Ok(_) => fresh,
        Err(won) => won as *mut u8,
    }
}

fn test_alloc() -> Option<u64> {
    let n = NEXT_FRAME.fetch_add(1, Ordering::AcqRel);
    if n >= POOL_PAGES { return None; }
    Some(FRAME_BASE + (n * PAGE_BYTES) as u64)
}

pub(super) fn test_frame_ptr(pa: u64) -> Option<*mut u8> {
    let idx = pa.checked_sub(FRAME_BASE)? as usize;
    if idx >= POOL_PAGES * PAGE_BYTES { return None; }
    // SAFETY: `idx` is a page-aligned offset inside the leaked pool.
    Some(unsafe { pool().add(idx) })
}

unsafe fn test_release(_pa: u64) { RELEASED.fetch_add(1, Ordering::AcqRel); }

fn test_mapped(_pa: u64) -> bool { ALL_MAPPED.load(Ordering::Acquire) }

static TEST_PROVIDER: super::store::FrameProvider = super::store::FrameProvider {
    alloc: test_alloc, ptr: test_frame_ptr, release: test_release, mapped: test_mapped,
};

/// Install the test frame allocator. Process-global, exactly as the machine's
/// is, so it is installed rather than handed to a caller.
pub(super) fn with_frames() {
    let _ = pool();
    super::store::install_frame_provider(&TEST_PROVIDER);
}

/// Say whether the provider reports every frame as user-mapped.
pub(super) fn set_all_mapped(on: bool) { ALL_MAPPED.store(on, Ordering::Release); }

/// References the provider has been asked to return.
pub(super) fn released() -> usize { RELEASED.load(Ordering::Acquire) }
