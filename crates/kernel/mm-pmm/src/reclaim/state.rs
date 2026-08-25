use core::marker::PhantomData;

use hal::Pfn;
use sync::{IrqGate, Spinlock, TaskList};

use crate::irq_gate::PmmIrq;

use crate::{reclaim_state, PageFlags, PageMetaArr, ReclaimPageState};

#[path = "ops.rs"]
mod ops;

/// Linux-style reclaim LRU class. Queue position is an index only; PageMeta
/// flags are authoritative for class, membership, and isolation.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Lru { InactiveAnon, ActiveAnon, InactiveFile, ActiveFile, Unevictable }

impl Lru {
    const COUNT: usize = 5;
    const fn index(self) -> usize {
        match self {
            Self::InactiveAnon => 0,
            Self::ActiveAnon => 1,
            Self::InactiveFile => 2,
            Self::ActiveFile => 3,
            Self::Unevictable => 4,
        }
    }
    const fn active(self) -> bool { matches!(self, Self::ActiveAnon | Self::ActiveFile) }
    const fn unevictable(self) -> bool { matches!(self, Self::Unevictable) }
    fn class_matches(self, flags: PageFlags) -> bool {
        let anon = flags.intersects(PageFlags::ANON | PageFlags::SHMEM);
        let file = flags.contains(PageFlags::FILE);
        match self {
            Self::InactiveAnon | Self::ActiveAnon => anon && !file,
            Self::InactiveFile | Self::ActiveFile => file && !anon,
            // Mlocked pages retain their anon/file classification while living
            // on the unevictable LRU; either Linux class is valid here.
            Self::Unevictable => anon ^ file,
        }
    }
}

/// Isolated page identity. The original LRU is retained until the caller puts
/// the page back or finishes reclaim, so the operation cannot silently change
/// its class.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Isolation { pfn: Pfn, lru: Lru }
impl Isolation {
    /// PFN held off-LRU by this reclaim transaction. # C: O(1)
    pub const fn pfn(self) -> Pfn { self.pfn }
    /// LRU from which this page was isolated. # C: O(1)
    pub const fn lru(self) -> Lru { self.lru }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ReclaimError { OutOfRange, State, Class }

/// Result of one bounded anonymous-LRU aging pass. `scanned` counts queue
/// entries whose PageMeta state was consumed; a page may remain on its prior
/// LRU when its reference sample does not require a class transition.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Aging {
    pub scanned: usize,
    pub activated: usize,
    pub deactivated: usize,
}

/// Lock-consistent observation of the reclaim-owned page population and
/// transition events.  Membership remains encoded in `PageMeta.flags`; these
/// counts are updated only after that authoritative transition succeeds.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct ReclaimSnapshot {
    pub inactive_anon: u64,
    pub active_anon: u64,
    pub inactive_file: u64,
    pub active_file: u64,
    pub unevictable: u64,
    pub isolated: u64,
    pub scanned: u64,
    pub stolen: u64,
    pub activated: u64,
    pub deactivated: u64,
}

const NO_PFN: u64 = u64::MAX;

fn decode_link(raw: u64) -> Option<Pfn> {
    (raw != NO_PFN).then_some(Pfn(raw))
}

/// Linux `list_head` embedded in `struct page`, split between this list's
/// head/tail and each [`crate::PageMeta`]'s PFN links. The reclaim lock owns
/// every mutation, making exact deletion and FIFO rotation O(1).
#[derive(Copy, Clone)]
struct LruList { head: Option<Pfn>, tail: Option<Pfn>, len: usize }

impl LruList {
    const fn new() -> Self { Self { head: None, tail: None, len: 0 } }

    fn len(&self) -> usize { self.len }

    fn push_back(&mut self, meta: &PageMetaArr, pfn: Pfn) -> Result<(), ReclaimError> {
        let page = meta.get(pfn).ok_or(ReclaimError::OutOfRange)?;
        match (self.head, self.tail, self.len) {
            (None, None, 0) => {}
            (Some(head), Some(tail), len) if len != 0 => {
                let head_page = meta.get(head).ok_or(ReclaimError::OutOfRange)?;
                let tail_page = meta.get(tail).ok_or(ReclaimError::OutOfRange)?;
                if head_page.lru_prev.load(core::sync::atomic::Ordering::Relaxed) != NO_PFN
                    || tail_page.lru_next.load(core::sync::atomic::Ordering::Relaxed) != NO_PFN
                { return Err(ReclaimError::State); }
            }
            _ => return Err(ReclaimError::State),
        }
        if page.lru_prev.load(core::sync::atomic::Ordering::Relaxed) != NO_PFN
            || page.lru_next.load(core::sync::atomic::Ordering::Relaxed) != NO_PFN
            || self.head == Some(pfn) || self.tail == Some(pfn)
        { return Err(ReclaimError::State); }
        page.lru_prev.store(self.tail.map_or(NO_PFN, |old| old.0), core::sync::atomic::Ordering::Relaxed);
        if let Some(tail) = self.tail {
            meta.get(tail).ok_or(ReclaimError::OutOfRange)?.lru_next
                .store(pfn.0, core::sync::atomic::Ordering::Relaxed);
        } else {
            self.head = Some(pfn);
        }
        self.tail = Some(pfn);
        self.len += 1;
        Ok(())
    }

    fn pop_front(&mut self, meta: &PageMetaArr) -> Result<Option<Pfn>, ReclaimError> {
        let Some(pfn) = self.head else {
            if self.tail.is_some() || self.len != 0 { return Err(ReclaimError::State); }
            return Ok(None);
        };
        self.remove(meta, pfn)?;
        Ok(Some(pfn))
    }

    fn remove(&mut self, meta: &PageMetaArr, pfn: Pfn) -> Result<(), ReclaimError> {
        if self.len == 0 { return Err(ReclaimError::State); }
        let page = meta.get(pfn).ok_or(ReclaimError::OutOfRange)?;
        let prev = decode_link(page.lru_prev.load(core::sync::atomic::Ordering::Relaxed));
        let next = decode_link(page.lru_next.load(core::sync::atomic::Ordering::Relaxed));
        if prev == Some(pfn) || next == Some(pfn) { return Err(ReclaimError::State); }

        // Validate the complete splice before mutating either neighbor. A bad
        // backlink must not leave the LRU half-unlinked.
        let prev_page = match prev {
            Some(old) => {
                let old_page = meta.get(old).ok_or(ReclaimError::OutOfRange)?;
                if self.head == Some(pfn)
                    || decode_link(old_page.lru_next.load(core::sync::atomic::Ordering::Relaxed)) != Some(pfn)
                {
                    return Err(ReclaimError::State);
                }
                Some(old_page)
            }
            None if self.head == Some(pfn) => None,
            None => return Err(ReclaimError::State),
        };
        let next_page = match next {
            Some(new) => {
                let new_page = meta.get(new).ok_or(ReclaimError::OutOfRange)?;
                if self.tail == Some(pfn)
                    || decode_link(new_page.lru_prev.load(core::sync::atomic::Ordering::Relaxed)) != Some(pfn)
                {
                    return Err(ReclaimError::State);
                }
                Some(new_page)
            }
            None if self.tail == Some(pfn) => None,
            None => return Err(ReclaimError::State),
        };

        if let Some(old_page) = prev_page {
            old_page.lru_next.store(next.map_or(NO_PFN, |new| new.0), core::sync::atomic::Ordering::Relaxed);
        } else {
            self.head = next;
        }
        if let Some(new_page) = next_page {
            new_page.lru_prev.store(prev.map_or(NO_PFN, |old| old.0), core::sync::atomic::Ordering::Relaxed);
        } else {
            self.tail = prev;
        }
        page.lru_prev.store(NO_PFN, core::sync::atomic::Ordering::Relaxed);
        page.lru_next.store(NO_PFN, core::sync::atomic::Ordering::Relaxed);
        self.len -= 1;
        if self.len == 0 && (self.head.is_some() || self.tail.is_some()) { return Err(ReclaimError::State); }
        Ok(())
    }
}

struct Queues {
    q: [LruList; Lru::COUNT],
    pages: [u64; Lru::COUNT],
    isolated: u64,
    scanned: u64,
    stolen: u64,
    activated: u64,
    deactivated: u64,
}
impl Queues {
    fn new() -> Self {
        Self {
            q: core::array::from_fn(|_| LruList::new()),
            pages: [0; Lru::COUNT], isolated: 0, scanned: 0, stolen: 0,
            activated: 0, deactivated: 0,
        }
    }

    fn snapshot(&self) -> ReclaimSnapshot {
        ReclaimSnapshot {
            inactive_anon: self.pages[Lru::InactiveAnon.index()],
            active_anon: self.pages[Lru::ActiveAnon.index()],
            inactive_file: self.pages[Lru::InactiveFile.index()],
            active_file: self.pages[Lru::ActiveFile.index()],
            unevictable: self.pages[Lru::Unevictable.index()],
            isolated: self.isolated,
            scanned: self.scanned,
            stolen: self.stolen,
            activated: self.activated,
            deactivated: self.deactivated,
        }
    }
}

/// Canonical PMM reclaim-LRU index. The `TaskList` lock is acquired after
/// PageTable/AddressSpace locks (`06§3.6`) and never while the Buddy lock is
/// held.
///
/// It masks local interrupts for its whole critical section, for the reason
/// the buddy lock does: `free_one_frame` unlinks a page from its LRU on the
/// way to the free list, and that path runs in interrupt context too. Taken
/// plainly, an interrupt arriving on the CPU that already holds it spins for
/// it forever with interrupts masked — a one-CPU deadlock that stops the whole
/// machine, observed as a soft lockup inside `free_one_frame` a few seconds
/// into boot. The reference masks interrupts across every LRU mutation for the
/// same reason.
///
/// The gate is a parameter so a test can watch it: a probe gate counts the
/// masked sections and proves the lock is not being taken plainly.
pub struct Reclaim<I: IrqGate = PmmIrq> { q: Spinlock<Queues, TaskList>, _irq: PhantomData<I> }


impl<I: IrqGate> Default for Reclaim<I> { fn default() -> Self { Self::new() } }
