use alloc::collections::VecDeque;

use hal::Pfn;
use sync::{Spinlock, TaskList};

use crate::{reclaim_state, PageFlags, PageMetaArr, ReclaimPageState};

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

struct Queues {
    q: [VecDeque<Pfn>; Lru::COUNT],
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
            q: core::array::from_fn(|_| VecDeque::new()),
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
/// held. Stage 0 owns no allocator or pageout call sites, so this establishes
/// the ordering boundary before any reclaim wiring exists.
pub struct Reclaim { q: Spinlock<Queues, TaskList> }

impl Reclaim {
    /// Empty LRU index. # C: O(1)
    pub fn new() -> Self { Self { q: Spinlock::new(Queues::new()) } }

    /// Admit one classified page to exactly one LRU. The PageMeta flag
    /// transition and queue insertion are serialized by this LRU lock.
    /// # C: O(1); # Lk: TaskList
    pub fn add(&self, meta: &PageMetaArr, pfn: Pfn, lru: Lru) -> Result<(), ReclaimError> {
        let page = meta.get(pfn).ok_or(ReclaimError::OutOfRange)?;
        let mut q = self.q.lock();
        let flags = PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
        if reclaim_state(flags) != ReclaimPageState::NotOnLru { return Err(ReclaimError::State); }
        if !lru.class_matches(flags) { return Err(ReclaimError::Class); }
        let mut next = flags | PageFlags::LRU;
        if lru.active() { next.insert(PageFlags::ACTIVE); }
        if lru.unevictable() { next.insert(PageFlags::UNEVICTABLE); }
        page.flags.fetch_or(next.bits() & !flags.bits(), core::sync::atomic::Ordering::AcqRel);
        q.q[lru.index()].push_back(pfn);
        q.pages[lru.index()] += 1;
        Ok(())
    }

    /// Record a reference to one evictable page. The PageMeta `REFERENCED`
    /// bit is the sole access sample; queue position remains only an index.
    /// # C: O(1); # Lk: TaskList
    pub fn mark_referenced(&self, meta: &PageMetaArr, pfn: Pfn) -> Result<(), ReclaimError> {
        let page = meta.get(pfn).ok_or(ReclaimError::OutOfRange)?;
        let _q = self.q.lock();
        let flags = PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
        if !Lru::InactiveAnon.class_matches(flags) && !Lru::InactiveFile.class_matches(flags) {
            return Err(ReclaimError::Class);
        }
        match reclaim_state(flags) {
            ReclaimPageState::OnLru { unevictable: false, .. } => {
                page.flags.fetch_or(PageFlags::REFERENCED.bits(), core::sync::atomic::Ordering::Release);
                Ok(())
            }
            _ => Err(ReclaimError::State),
        }
    }

    /// Record an anonymous or shmem reference. # C: O(1); # Lk: TaskList
    pub fn mark_anon_referenced(&self, meta: &PageMetaArr, pfn: Pfn) -> Result<(), ReclaimError> {
        let flags = meta.flags(pfn).ok_or(ReclaimError::OutOfRange)?;
        if !Lru::InactiveAnon.class_matches(flags) { return Err(ReclaimError::Class); }
        self.mark_referenced(meta, pfn)
    }

    /// Age at most `budget` entries from each anonymous LRU. A referenced
    /// inactive page is activated; an unreferenced active page is
    /// deactivated. A referenced active page remains active but consumes its
    /// sample, matching Linux's two-list aging rule. Every page remains in
    /// exactly one LRU throughout the locked transition. # C: O(budget); # Lk: TaskList
    pub fn age_anon(&self, meta: &PageMetaArr, budget: usize) -> Result<Aging, ReclaimError> {
        self.age_pair(meta, Lru::InactiveAnon, Lru::ActiveAnon, budget)
    }

    /// Age regular page-cache pages over the active/inactive file LRUs.
    /// # C: O(budget); # Lk: TaskList
    pub fn age_file(&self, meta: &PageMetaArr, budget: usize) -> Result<Aging, ReclaimError> {
        self.age_pair(meta, Lru::InactiveFile, Lru::ActiveFile, budget)
    }

    fn age_pair(&self, meta: &PageMetaArr, inactive: Lru, active: Lru, budget: usize) -> Result<Aging, ReclaimError> {
        let mut q = self.q.lock();
        let mut aging = Aging::default();
        // Snapshot both generations before either is touched: promotions made
        // while scanning inactive must wait until the next aging generation.
        let inactive_scan = core::cmp::min(q.q[inactive.index()].len(), budget);
        let active_scan = core::cmp::min(q.q[active.index()].len(), budget);
        Self::age_one_lru(&mut q, meta, inactive, active, inactive_scan, &mut aging)?;
        Self::age_one_lru(&mut q, meta, active, inactive, active_scan, &mut aging)?;
        Ok(aging)
    }

    fn age_one_lru(q: &mut Queues, meta: &PageMetaArr, lru: Lru, peer: Lru, budget: usize, aging: &mut Aging) -> Result<(), ReclaimError> {
        for _ in 0..budget {
            let Some(pfn) = q.q[lru.index()].pop_front() else { break; };
            // Linux's pgscan counts the queue entry as soon as reclaim has
            // inspected it; a later validation failure must not erase that
            // observable work.
            q.scanned += 1;
            let page = meta.get(pfn).ok_or(ReclaimError::OutOfRange)?;
            let flags = PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
            if !lru.class_matches(flags)
                || reclaim_state(flags) != (ReclaimPageState::OnLru { active: lru.active(), unevictable: false })
            {
                return Err(if lru.class_matches(flags) { ReclaimError::State } else { ReclaimError::Class });
            }
            let referenced = flags.contains(PageFlags::REFERENCED);
            let target = if !lru.active() && referenced { peer } else if lru.active() && !referenced { peer } else { lru };
            page.flags.fetch_update(core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire, |raw| {
                let current = PageFlags::from_bits_retain(raw);
                (lru.class_matches(current)
                    && reclaim_state(current) == ReclaimPageState::OnLru { active: lru.active(), unevictable: false })
                    .then_some(if target.active() {
                        (current - PageFlags::REFERENCED | PageFlags::ACTIVE).bits()
                    } else {
                        (current - PageFlags::REFERENCED - PageFlags::ACTIVE).bits()
                    })
            }).map_err(|_| ReclaimError::State)?;
            q.q[target.index()].push_back(pfn);
            aging.scanned += 1;
            if target != lru {
                q.pages[lru.index()] -= 1;
                q.pages[target.index()] += 1;
            }
            if target.active() && !lru.active() {
                aging.activated += 1;
                q.activated += 1;
            }
            if !target.active() && lru.active() {
                aging.deactivated += 1;
                q.deactivated += 1;
            }
        }
        Ok(())
    }

    /// Move an LRU page to or from the unevictable list. The ANON/SHMEM vs
    /// FILE classification remains in PageMeta, so munlock returns the page to
    /// its matching inactive generation without a shadow classification.
    /// # C: O(N_lru); # Lk: TaskList
    pub fn set_unevictable(&self, meta: &PageMetaArr, pfn: Pfn, enabled: bool) -> Result<(), ReclaimError> {
        let page = meta.get(pfn).ok_or(ReclaimError::OutOfRange)?;
        let mut q = self.q.lock();
        let flags = PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
        let state = reclaim_state(flags);
        let source = match state {
            ReclaimPageState::OnLru { active, unevictable: false } => {
                if flags.intersects(PageFlags::ANON | PageFlags::SHMEM) && !flags.contains(PageFlags::FILE) {
                    if active { Lru::ActiveAnon } else { Lru::InactiveAnon }
                } else if flags.contains(PageFlags::FILE) && !flags.intersects(PageFlags::ANON | PageFlags::SHMEM) {
                    if active { Lru::ActiveFile } else { Lru::InactiveFile }
                } else { return Err(ReclaimError::Class); }
            }
            ReclaimPageState::OnLru { unevictable: true, .. } if !enabled => Lru::Unevictable,
            ReclaimPageState::OnLru { unevictable: true, .. } => return Ok(()),
            _ => return Err(ReclaimError::State),
        };
        if enabled && source == Lru::Unevictable { return Ok(()); }
        let target = if enabled {
            Lru::Unevictable
        } else if flags.intersects(PageFlags::ANON | PageFlags::SHMEM) {
            Lru::InactiveAnon
        } else {
            Lru::InactiveFile
        };
        let pos = q.q[source.index()].iter().position(|queued| *queued == pfn).ok_or(ReclaimError::State)?;
        let _ = q.q[source.index()].remove(pos);
        page.flags.fetch_update(core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire, |raw| {
            let now = PageFlags::from_bits_retain(raw);
            (reclaim_state(now) == state).then_some(if enabled {
                (now - PageFlags::ACTIVE | PageFlags::UNEVICTABLE).bits()
            } else {
                (now - PageFlags::UNEVICTABLE - PageFlags::ACTIVE).bits()
            })
        }).map_err(|_| ReclaimError::State)?;
        q.pages[source.index()] -= 1;
        q.pages[target.index()] += 1;
        q.q[target.index()].push_back(pfn);
        Ok(())
    }

    /// Remove a page from its current LRU before its final PMM free.  A page
    /// that is already off-LRU is an ordinary non-reclaim allocation.  An
    /// isolated page is deliberately rejected: reclaim owns its terminal
    /// transition and a final free at that point is an ownership violation.
    /// # C: O(N_lru); # Lk: TaskList
    pub fn unlink_for_free(&self, meta: &PageMetaArr, pfn: Pfn) -> Result<(), ReclaimError> {
        let page = meta.get(pfn).ok_or(ReclaimError::OutOfRange)?;
        let mut q = self.q.lock();
        let flags = PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
        match reclaim_state(flags) {
            ReclaimPageState::NotOnLru => return Ok(()),
            ReclaimPageState::Isolated { .. } | ReclaimPageState::Invalid => return Err(ReclaimError::State),
            ReclaimPageState::OnLru { active, unevictable } => {
                let lru = if unevictable { Lru::Unevictable } else if flags.intersects(PageFlags::ANON | PageFlags::SHMEM) && !flags.contains(PageFlags::FILE) {
                    if active { Lru::ActiveAnon } else { Lru::InactiveAnon }
                } else if flags.contains(PageFlags::FILE) && !flags.intersects(PageFlags::ANON | PageFlags::SHMEM) {
                    if active { Lru::ActiveFile } else { Lru::InactiveFile }
                } else { return Err(ReclaimError::Class); };
                let pos = q.q[lru.index()].iter().position(|queued| *queued == pfn).ok_or(ReclaimError::State)?;
                let _ = q.q[lru.index()].remove(pos);
                page.flags.fetch_update(core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire, |raw| {
                    let current = PageFlags::from_bits_retain(raw);
                    (reclaim_state(current) == ReclaimPageState::OnLru { active, unevictable })
                        .then_some((current - PageFlags::LRU - PageFlags::ACTIVE - PageFlags::UNEVICTABLE).bits())
                }).map_err(|_| ReclaimError::State)?;
                q.pages[lru.index()] -= 1;
                Ok(())
            }
        }
    }

    /// Isolate the oldest page from `lru`. The returned token is required for
    /// both terminal transitions, preventing a PFN from being put on another
    /// queue by mistake. # C: O(1); # Lk: TaskList
    pub fn isolate(&self, meta: &PageMetaArr, lru: Lru) -> Result<Option<Isolation>, ReclaimError> {
        let mut q = self.q.lock();
        let Some(pfn) = q.q[lru.index()].pop_front() else { return Ok(None); };
        q.scanned += 1;
        let page = meta.get(pfn).ok_or(ReclaimError::OutOfRange)?;
        let flags = PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
        if !lru.class_matches(flags) { return Err(ReclaimError::Class); }
        if reclaim_state(flags) != (ReclaimPageState::OnLru { active: lru.active(), unevictable: lru.unevictable() }) {
            return Err(ReclaimError::State);
        }
        page.flags.fetch_update(core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire, |raw| {
            let current = PageFlags::from_bits_retain(raw);
            (lru.class_matches(current)
                && reclaim_state(current) == ReclaimPageState::OnLru { active: lru.active(), unevictable: lru.unevictable() })
                .then_some((current - PageFlags::LRU | PageFlags::ISOLATED).bits())
        }).map_err(|_| ReclaimError::State)?;
        q.pages[lru.index()] -= 1;
        q.isolated += 1;
        Ok(Some(Isolation { pfn, lru }))
    }

    /// Isolate the oldest member of `lru` charged directly to `memcg`.
    /// Unmatched entries are rotated once, preserving their FIFO order and
    /// keeping PageMeta as the sole membership/class truth.  Memcg pressure
    /// must never reclaim an unrelated cgroup merely because it happened to
    /// be older on the global LRU. # C: O(N_lru); # Lk: TaskList
    pub fn isolate_memcg(&self, meta: &PageMetaArr, lru: Lru, memcg: u64) -> Result<Option<Isolation>, ReclaimError> {
        let mut q = self.q.lock();
        let entries = q.q[lru.index()].len();
        for _ in 0..entries {
            let Some(pfn) = q.q[lru.index()].pop_front() else { break; };
            let page = meta.get(pfn).ok_or(ReclaimError::OutOfRange)?;
            let flags = PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
            if !lru.class_matches(flags)
                || reclaim_state(flags) != (ReclaimPageState::OnLru { active: lru.active(), unevictable: lru.unevictable() })
            { return Err(if lru.class_matches(flags) { ReclaimError::State } else { ReclaimError::Class }); }
            if page.memcg.load(core::sync::atomic::Ordering::Acquire) != memcg {
                q.q[lru.index()].push_back(pfn);
                continue;
            }
            q.scanned += 1;
            page.flags.fetch_update(core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire, |raw| {
                let current = PageFlags::from_bits_retain(raw);
                (lru.class_matches(current)
                    && reclaim_state(current) == ReclaimPageState::OnLru { active: lru.active(), unevictable: lru.unevictable() })
                    .then_some((current - PageFlags::LRU | PageFlags::ISOLATED).bits())
            }).map_err(|_| ReclaimError::State)?;
            q.pages[lru.index()] -= 1;
            q.isolated += 1;
            return Ok(Some(Isolation { pfn, lru }));
        }
        Ok(None)
    }

    /// Isolate one exact evictable anonymous PFN for an explicit page-out
    /// request. Direct reclaim uses [`Self::isolate`] and never searches by
    /// PFN; this operation exists only for a caller that already owns a VMA
    /// range and has identified a resident target. # C: O(N_lru); # Lk: TaskList
    pub fn isolate_anon_pfn(&self, meta: &PageMetaArr, pfn: Pfn) -> Result<Option<Isolation>, ReclaimError> {
        let page = meta.get(pfn).ok_or(ReclaimError::OutOfRange)?;
        let mut q = self.q.lock();
        let flags = PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
        let lru = match reclaim_state(flags) {
            ReclaimPageState::OnLru { active, unevictable: false }
                if Lru::InactiveAnon.class_matches(flags) => {
                    if active { Lru::ActiveAnon } else { Lru::InactiveAnon }
                }
            ReclaimPageState::NotOnLru | ReclaimPageState::Isolated { .. } => return Ok(None),
            _ => return Err(ReclaimError::Class),
        };
        let pos = q.q[lru.index()].iter().position(|queued| *queued == pfn).ok_or(ReclaimError::State)?;
        let _ = q.q[lru.index()].remove(pos);
        q.scanned += 1;
        page.flags.fetch_update(core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire, |raw| {
            let current = PageFlags::from_bits_retain(raw);
            (lru.class_matches(current)
                && reclaim_state(current) == ReclaimPageState::OnLru { active: lru.active(), unevictable: false })
                .then_some((current - PageFlags::LRU | PageFlags::ISOLATED).bits())
        }).map_err(|_| ReclaimError::State)?;
        q.pages[lru.index()] -= 1;
        q.isolated += 1;
        Ok(Some(Isolation { pfn, lru }))
    }

    /// Requeue an isolated page at the tail of its original LRU. # C: O(1); # Lk: TaskList
    pub fn putback(&self, meta: &PageMetaArr, isolated: Isolation) -> Result<(), ReclaimError> {
        let page = meta.get(isolated.pfn).ok_or(ReclaimError::OutOfRange)?;
        let mut q = self.q.lock();
        let flags = PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
        if !isolated.lru.class_matches(flags) { return Err(ReclaimError::Class); }
        if reclaim_state(flags) != (ReclaimPageState::Isolated { active: isolated.lru.active() }) { return Err(ReclaimError::State); }
        page.flags.fetch_update(core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire, |raw| {
            let current = PageFlags::from_bits_retain(raw);
            (isolated.lru.class_matches(current)
                && reclaim_state(current) == ReclaimPageState::Isolated { active: isolated.lru.active() })
                .then_some((current - PageFlags::ISOLATED | PageFlags::LRU).bits())
        }).map_err(|_| ReclaimError::State)?;
        q.q[isolated.lru.index()].push_back(isolated.pfn);
        q.isolated -= 1;
        q.pages[isolated.lru.index()] += 1;
        Ok(())
    }

    /// Finish a successful reclaim transaction. It only clears LRU ownership;
    /// the future allocator/pageout owner performs I/O, unmapping, and free.
    /// # C: O(1); # Lk: TaskList
    pub fn release(&self, meta: &PageMetaArr, isolated: Isolation) -> Result<(), ReclaimError> {
        let page = meta.get(isolated.pfn).ok_or(ReclaimError::OutOfRange)?;
        let mut q = self.q.lock();
        let flags = PageFlags::from_bits_retain(page.flags.load(core::sync::atomic::Ordering::Acquire));
        if !isolated.lru.class_matches(flags) { return Err(ReclaimError::Class); }
        if reclaim_state(flags) != (ReclaimPageState::Isolated { active: isolated.lru.active() }) { return Err(ReclaimError::State); }
        page.flags.fetch_update(core::sync::atomic::Ordering::AcqRel, core::sync::atomic::Ordering::Acquire, |raw| {
            let current = PageFlags::from_bits_retain(raw);
            (isolated.lru.class_matches(current)
                && reclaim_state(current) == ReclaimPageState::Isolated { active: isolated.lru.active() })
                .then_some((current - PageFlags::ISOLATED - PageFlags::ACTIVE - PageFlags::UNEVICTABLE).bits())
        }).map_err(|_| ReclaimError::State)?;
        q.isolated -= 1;
        q.stolen += 1;
        Ok(())
    }

    /// Number of PFNs indexed by one LRU. # C: O(1); # Lk: TaskList
    pub fn len(&self, lru: Lru) -> usize { self.q.lock().q[lru.index()].len() }

    /// Snapshot canonical reclaim populations and transition events. # C: O(1); # Lk: TaskList
    pub fn snapshot(&self) -> ReclaimSnapshot { self.q.lock().snapshot() }
}

impl Default for Reclaim { fn default() -> Self { Self::new() } }
