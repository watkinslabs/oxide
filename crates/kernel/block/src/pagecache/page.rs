//! One cached page and its per-page lock bit (`17§4.1`, `17§4.2` step 5).
//!
//! `PG_LOCKED` is a bit in the page's own flag word, taken with an atomic
//! test-and-set and released with a store plus a wake. Waiters do NOT get a
//! wait list each: a hashed table of shared wait lists is indexed by the
//! page's address, exactly as the reference does, so a page costs one flag
//! word rather than a queue head. A spurious wake from a table collision is
//! harmless — the waiter re-tests the bit.
//!
//! What the lock buys, and why the cache was wrong without it: the miss path
//! publishes a LOCKED, not-uptodate page into the tree BEFORE it fetches, so a
//! second reader of the same index finds that page and blocks on the bit
//! instead of issuing a second read of the same bytes.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use sync::{Inode as InodeClass, Spinlock};

use crate::types::{InodeId, PageFlags, PAGE_BYTES};

use super::store::PageBuf;

/// Shared wait lists, indexed by a hash of the page address. Sized as the
/// reference sizes its own page-wait table.
#[cfg(target_os = "oxide-kernel")]
const PAGE_WAIT_SLOTS: usize = 256;
#[cfg(target_os = "oxide-kernel")]
static PAGE_WAIT: [sched::live::WaitList; PAGE_WAIT_SLOTS] =
    [const { sched::live::WaitList::new() }; PAGE_WAIT_SLOTS];

/// One cached page per `17§4.1`.
///
/// Reconciliation with the spec struct: `offset`/`flags` are as written there;
/// the spec's `refcount` is the `Arc` every handle to this page is held
/// through, so the count lives in the allocation rather than beside it, and
/// there is exactly one of it. The spec's `pfn: Pfn` is a [`PageBuf`], which is
/// a heap buffer until something asks to MAP the page and the machine frame it
/// was moved into from then on; `inode: Weak<dyn Inode>` is an opaque `InodeId`
/// — see the module manifest in `pagecache.rs` for why.
pub struct CachedPage {
    pub inode:  InodeId,
    pub offset: u64,
    pub flags:  AtomicU32,
    pub data:   Spinlock<PageBuf, InodeClass>,
    /// Owner note the filesystem hangs on the page, opaque here.
    ///
    /// A mapping whose index is a DEVICE address rather than a file offset
    /// cannot say which file a page belongs to from its key, so the filesystem
    /// records it on the page and drops pages by it later. Zero is "nothing
    /// recorded", which is what an ordinary file-offset mapping leaves it as.
    pub tag: AtomicU64,
}

impl CachedPage {
    /// Construct a fresh uptodate cached page. Visible to the cache itself and
    /// to in-crate tests; FSes go through `PageCache::read_page` /
    /// `write_page` rather than calling this directly.
    /// # C: O(1)
    pub fn new(inode: InodeId, offset: u64, data: Vec<u8>) -> Arc<Self> {
        debug_assert_eq!(data.len(), PAGE_BYTES);
        Arc::new(Self {
            inode, offset,
            flags: AtomicU32::new(PageFlags::UPTODATE.bits()),
            data:  Spinlock::new(PageBuf::from_vec(data)),
            tag:   AtomicU64::new(0),
        })
    }

    /// The machine frame this page's bytes live in, or `None` while they are on
    /// the heap.
    ///
    /// What a shared writable mapping needs and the only thing that can satisfy
    /// it: a user page table can point at a frame and cannot point at a heap
    /// buffer. Answered without converting, because a residency question must
    /// not allocate.
    /// # C: O(1)
    pub fn pa(&self) -> Option<u64> { self.data.lock().pa() }

    /// Move this page's bytes into a machine frame if they are not in one
    /// already, and report its address.
    ///
    /// The conversion is one-way and in place, so the page never has two
    /// copies and the address, once handed out, does not change while the page
    /// is resident. `None` is "this page cannot be mapped" — no allocator
    /// installed, or no frame to be had — never a second copy.
    /// # C: O(page) on the first call, O(1) after
    pub fn to_frame(&self) -> Option<u64> { self.data.lock().to_frame() }

    /// Whether a user page table maps this page right now. # C: O(1)
    pub fn user_mapped(&self) -> bool { self.data.lock().user_mapped() }

    /// The placeholder the miss path publishes before it fetches: LOCKED by
    /// its creator and NOT uptodate, so any other finder waits rather than
    /// reads it or re-fetches it. # C: O(page)
    pub(super) fn new_locked(inode: InodeId, offset: u64) -> Arc<Self> {
        Arc::new(Self {
            inode, offset,
            flags: AtomicU32::new(PageFlags::LOCKED.bits()),
            data:  Spinlock::new(PageBuf::zeroed()),
            tag:   AtomicU64::new(0),
        })
    }

    /// The owner note this page carries. # C: O(1)
    pub fn tag(&self) -> u64 { self.tag.load(Ordering::Acquire) }

    /// Record the owner note. # C: O(1)
    pub fn set_tag(&self, tag: u64) { self.tag.store(tag, Ordering::Release); }

    /// # C: O(1)
    pub fn flags(&self) -> PageFlags {
        PageFlags::from_bits_retain(self.flags.load(Ordering::Acquire))
    }

    /// # C: O(1)
    pub fn is_dirty(&self) -> bool { self.flags().contains(PageFlags::DIRTY) }

    /// Contents match the medium's, so a reader may use them. # C: O(1)
    pub fn is_uptodate(&self) -> bool { self.flags().contains(PageFlags::UPTODATE) }

    /// Handed to the driver and not yet completed. # C: O(1)
    pub fn is_writeback(&self) -> bool { self.flags().contains(PageFlags::WRITEBACK) }

    /// On the active list rather than the inactive one. # C: O(1)
    pub fn is_active(&self) -> bool { self.flags().contains(PageFlags::ACTIVE) }

    /// # C: O(1)
    pub fn is_locked(&self) -> bool { self.flags().contains(PageFlags::LOCKED) }

    /// Set bits, return previous full word. # C: O(1)
    pub fn set_flags(&self, bits: PageFlags) -> PageFlags {
        let prev = self.flags.fetch_or(bits.bits(), Ordering::AcqRel);
        PageFlags::from_bits_retain(prev)
    }

    /// Clear bits, return previous full word. # C: O(1)
    pub fn clear_flags(&self, bits: PageFlags) -> PageFlags {
        let prev = self.flags.fetch_and(!bits.bits(), Ordering::AcqRel);
        PageFlags::from_bits_retain(prev)
    }

    /// Take `PG_LOCKED` if it is free, without waiting. # C: O(1)
    pub fn trylock(&self) -> bool {
        !self.set_flags(PageFlags::LOCKED).contains(PageFlags::LOCKED)
    }

    /// Take `PG_LOCKED`, waiting for whoever holds it.
    /// # Ctx: process # Sleeps: y # C: O(1) uncontended
    pub fn lock_page(&self) {
        if self.trylock() { return; }
        #[cfg(target_os = "oxide-kernel")]
        // SAFETY: the page lock is only ever taken in process context with no
        // mapping spinlock held; `unlock_page` wakes this page's hashed wait
        // list after clearing the bit, so the predicate is re-tested on wake.
        unsafe {
            let _ = sched::live::wait_event_uninterruptible(wait_slot(self), || self.trylock());
        }
        #[cfg(not(target_os = "oxide-kernel"))]
        while !self.trylock() { sync::spin_relax::relax(); }
    }

    /// Release `PG_LOCKED` and wake everyone parked on this page.
    /// # C: O(waiters)
    pub fn unlock_page(&self) {
        self.clear_flags(PageFlags::LOCKED);
        #[cfg(target_os = "oxide-kernel")]
        wait_slot(self).wake_all();
    }

    /// Publish fetched contents and release the lock the fetcher held: the
    /// page becomes usable and every waiter is woken in one step, so a waiter
    /// never observes an unlocked page that is not yet uptodate. # C: O(waiters)
    pub(super) fn finish_fetch(&self, bytes: Vec<u8>) {
        {
            let mut buf = self.data.lock();
            let n = core::cmp::min(buf.len(), bytes.len());
            buf[..n].copy_from_slice(&bytes[..n]);
            for b in buf[n..].iter_mut() { *b = 0; }
        }
        self.set_flags(PageFlags::UPTODATE);
        self.unlock_page();
    }
}

/// The wait list this page shares with every other page hashing to the same
/// slot. Collisions cost a spurious wake, never a missed one.
#[cfg(target_os = "oxide-kernel")]
fn wait_slot(page: &CachedPage) -> &'static sched::live::WaitList {
    // Fibonacci-hash the page address so adjacent allocations spread.
    const GOLDEN: u64 = 0x9e37_79b9_7f4a_7c15;
    let key = (page as *const CachedPage as u64).wrapping_mul(GOLDEN);
    &PAGE_WAIT[(key >> (u64::BITS - 8)) as usize % PAGE_WAIT_SLOTS]
}
