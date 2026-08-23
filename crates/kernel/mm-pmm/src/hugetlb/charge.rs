// hugetlb cgroup accounting for the pool: who a promised or handed-out huge
// page is charged to, and where that charge is released.
//
// The controller counts pages; it does not know which ones. That knowledge has
// to live beside the pages themselves, because the release path is given a
// physical address and nothing else — so the owner is recorded HERE, keyed by
// the page, and read back when the page goes home. A reservation has no page
// to hang off yet, so its owner is kept per cgroup until it is released.
//
// The granule crosses the crate boundary in one direction only: the pool's
// `HugePageSize` converts into the controller's `HugeGranule`, never back.

use alloc::collections::BTreeMap;
use cgroup::{HugeCounterKind, HugeGranule};
use sync::{HugetlbCharge, Spinlock};

use super::sizes::HugePageSize;

/// The controller's name for a pool granule. # C: O(1)
pub fn granule_of(size: HugePageSize) -> HugeGranule {
    match size {
        HugePageSize::Huge2M => HugeGranule::Huge2M,
        HugePageSize::Huge1G => HugeGranule::Huge1G,
    }
}

/// What one handed-out huge page is charged to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PageCharge {
    /// The cgroup that was charged when the page was handed out.
    pub cgid: u64,
    /// Whether the page ALSO carries a reservation charge taken at hand-out
    /// because nothing had reserved it in advance. A page consuming a
    /// reservation made earlier does not, or the reservation would be counted
    /// twice over the same page.
    pub deferred_rsvd: bool,
}

/// The cgroup charged for a reservation. It is carried by the reservation
/// until the promise is consumed or released; the releasing task is not an
/// accounting authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReservationToken {
    pub cgid: u64,
}

/// Owner records for one granule.
#[derive(Default)]
pub struct Ledger {
    pages: BTreeMap<u64, PageCharge>,
    resv: BTreeMap<u64, u64>,
}

impl Ledger {
    /// # C: O(1)
    pub const fn new() -> Self { Self { pages: BTreeMap::new(), resv: BTreeMap::new() } }

    /// Record a charged hand-out. # C: O(log n)
    pub fn insert_page(&mut self, pa: u64, charge: PageCharge) { self.pages.insert(pa, charge); }

    /// Take back the record for a released page. # C: O(log n)
    pub fn take_page(&mut self, pa: u64) -> Option<PageCharge> { self.pages.remove(&pa) }

    /// Record a reservation charged to `cgid`. # C: O(log n)
    pub fn add_resv(&mut self, cgid: u64, huge_pages: u64) {
        let e = self.resv.entry(cgid).or_insert(0);
        *e = e.saturating_add(huge_pages);
    }

    /// Take back reservations from the cgroup that created them.
    /// # C: O(1)
    pub fn take_resv(&mut self, cgid: u64, huge_pages: u64) -> u64 {
        let Some(have) = self.resv.get_mut(&cgid) else { return 0 };
        let take = core::cmp::min(*have, huge_pages);
        *have -= take;
        if *have == 0 { self.resv.remove(&cgid); }
        take
    }

    /// Retarget every record naming `from` at `to`, so a charge the controller
    /// has already moved to the parent is released against the cgroup that now
    /// holds it. # C: O(records)
    pub fn reparent(&mut self, from: u64, to: u64) {
        for c in self.pages.values_mut() {
            if c.cgid == from { c.cgid = to; }
        }
        if let Some(pages) = self.resv.remove(&from) { self.add_resv(to, pages); }
    }

    /// Outstanding reservation pages charged to `cgid`. The ledger's own
    /// observers: what a cgroup's files report comes from the controller's
    /// counters, so these exist to hold the ledger to its stated behaviour
    /// rather than to serve a reader. # C: O(log n)
    #[cfg(test)]
    pub fn resv_of(&self, cgid: u64) -> u64 { self.resv.get(&cgid).copied().unwrap_or(0) }

    /// The record a handed-out page carries. # C: O(log n)
    #[cfg(test)]
    pub fn page_of(&self, pa: u64) -> Option<PageCharge> { self.pages.get(&pa).copied() }
}

static LEDGER_2M: Spinlock<Ledger, HugetlbCharge> = Spinlock::new(Ledger::new());
static LEDGER_1G: Spinlock<Ledger, HugetlbCharge> = Spinlock::new(Ledger::new());

fn ledger(size: HugePageSize) -> &'static Spinlock<Ledger, HugetlbCharge> {
    match size { HugePageSize::Huge2M => &LEDGER_2M, HugePageSize::Huge1G => &LEDGER_1G }
}

#[cfg(target_os = "oxide-kernel")]
fn current_cgid() -> u64 {
    use core::sync::atomic::Ordering;
    let pid = sched::live::current().map(|t| t.tgid.load(Ordering::Acquire) as u64).unwrap_or(0);
    cgroup::cgroup_of(pid)
}
#[cfg(not(target_os = "oxide-kernel"))]
fn current_cgid() -> u64 { cgroup::cgroup_of(0) }

/// Charge `delta` promised pages of `size` to the reserving task's cgroup.
/// `Err(())` when a limit refuses it — the caller reports ENOMEM, which is
/// what a mapping the cgroup may not have gets.
/// # C: O(depth · subtree)
pub(super) fn charge_reserve(size: HugePageSize, delta: u64) -> Result<ReservationToken, ()> {
    if delta == 0 { return Ok(ReservationToken { cgid: current_cgid() }); }
    ensure_reparent_hook();
    let cgid = current_cgid();
    cgroup::try_charge_hugetlb(cgid, granule_of(size), HugeCounterKind::Reservation, delta)
        .map_err(|_| ())?;
    ledger(size).lock().add_resv(cgid, delta);
    Ok(ReservationToken { cgid })
}

/// Release `delta` promised pages of `size`. # C: O(records)
pub(super) fn uncharge_reserve(size: HugePageSize, owner: ReservationToken, delta: u64) {
    if delta == 0 { return; }
    let released = ledger(size).lock().take_resv(owner.cgid, delta);
    if released != 0 {
        cgroup::uncharge_hugetlb(owner.cgid, granule_of(size), HugeCounterKind::Reservation, released);
    }
}

/// Charge one page of `size` about to be handed out.
///
/// `reserved` says the caller is consuming a reservation it already holds:
/// that reservation record is being spent, so its charge is released here and
/// the page carries only its usage charge. A page nothing reserved takes a
/// reservation charge NOW instead, held for as long as the page is — which is
/// what keeps a fault that bypassed mapping-time reservation inside the same
/// reservation limit rather than outside every limit there is.
/// # C: O(depth · subtree)
pub(super) fn charge_alloc(size: HugePageSize, reserved: bool,
                           reservation: Option<ReservationToken>) -> Result<PageCharge, ()> {
    ensure_reparent_hook();
    let cgid = current_cgid();
    let g = granule_of(size);
    let deferred_rsvd = !reserved;
    if deferred_rsvd {
        cgroup::try_charge_hugetlb(cgid, g, HugeCounterKind::Reservation, 1).map_err(|_| ())?;
    }
    if cgroup::try_charge_hugetlb(cgid, g, HugeCounterKind::Usage, 1).is_err() {
        if deferred_rsvd { cgroup::uncharge_hugetlb(cgid, g, HugeCounterKind::Reservation, 1); }
        return Err(());
    }
    if reserved {
        let Some(owner) = reservation else {
            cgroup::uncharge_hugetlb(cgid, g, HugeCounterKind::Usage, 1);
            return Err(());
        };
        uncharge_reserve(size, owner, 1);
    }
    Ok(PageCharge { cgid, deferred_rsvd })
}

/// Give back a charge whose page never got handed out. # C: O(log n)
pub(super) fn cancel_alloc(size: HugePageSize, charge: PageCharge) {
    let g = granule_of(size);
    cgroup::uncharge_hugetlb(charge.cgid, g, HugeCounterKind::Usage, 1);
    if charge.deferred_rsvd {
        cgroup::uncharge_hugetlb(charge.cgid, g, HugeCounterKind::Reservation, 1);
    }
}

/// Bind a committed charge to the page it paid for. # C: O(log n)
pub(super) fn commit_alloc(size: HugePageSize, pa: u64, charge: PageCharge) {
    ledger(size).lock().insert_page(pa, charge);
}

/// Release the charge a page of `size` carried, when it goes back to the pool.
/// # C: O(log n)
pub(super) fn uncharge_page(size: HugePageSize, pa: u64) {
    let Some(charge) = ledger(size).lock().take_page(pa) else { return };
    cancel_alloc(size, charge);
}

/// Retarget every owner record naming `from` at `to`. Installed as the
/// controller's reparent hook: a removed cgroup's charges move to its parent,
/// and the records the release path reads have to move with them.
/// # C: O(records)
pub fn reparent_charges(from: u64, to: u64) {
    LEDGER_2M.lock().reparent(from, to);
    LEDGER_1G.lock().reparent(from, to);
}

/// Ensure the controller can retarget this module's owner records.
///
/// Installed on the first charge rather than from a bring-up call: the pool is
/// the only thing that creates records, so there is no window in which a
/// record exists and the hook does not, and no separate boot step that can be
/// forgotten.
/// # C: O(1)
fn ensure_reparent_hook() {
    use core::sync::atomic::{AtomicBool, Ordering};
    static INSTALLED: AtomicBool = AtomicBool::new(false);
    if INSTALLED.swap(true, Ordering::AcqRel) { return; }
    cgroup::set_hugetlb_reparent_hook(reparent_charges);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pages_owner_is_recorded_and_returned_once() {
        let mut l = Ledger::new();
        l.insert_page(0x4000_0000, PageCharge { cgid: 7, deferred_rsvd: true });
        assert_eq!(l.page_of(0x4000_0000), Some(PageCharge { cgid: 7, deferred_rsvd: true }));
        assert_eq!(l.take_page(0x4000_0000), Some(PageCharge { cgid: 7, deferred_rsvd: true }));
        assert_eq!(l.take_page(0x4000_0000), None, "a released page is not released twice");
    }

    #[test]
    fn a_reservation_release_uses_the_recorded_cgroup() {
        let mut l = Ledger::new();
        l.add_resv(3, 4);
        l.add_resv(9, 6);
        assert_eq!(l.take_resv(9, 2), 2);
        assert_eq!(l.resv_of(9), 4);
        assert_eq!(l.resv_of(3), 4);
    }

    #[test]
    fn a_release_from_one_record_never_spills_into_another() {
        let mut l = Ledger::new();
        l.add_resv(3, 4);
        l.add_resv(9, 6);
        assert_eq!(l.take_resv(9, 100), 6);
        assert_eq!(l.resv_of(3), 4, "a release never steals another cgroup's reservation");
        assert_eq!(l.resv_of(9), 0);
    }

    #[test]
    fn reparenting_retargets_both_page_and_reservation_records() {
        let mut l = Ledger::new();
        l.insert_page(0x1000, PageCharge { cgid: 5, deferred_rsvd: false });
        l.insert_page(0x2000, PageCharge { cgid: 6, deferred_rsvd: false });
        l.add_resv(5, 3);
        l.add_resv(6, 1);
        l.reparent(5, 6);
        assert_eq!(l.page_of(0x1000).unwrap().cgid, 6);
        assert_eq!(l.page_of(0x2000).unwrap().cgid, 6, "an unrelated record is untouched");
        assert_eq!(l.resv_of(5), 0);
        assert_eq!(l.resv_of(6), 4, "the moved reservation adds to what the parent held");
    }

    #[test]
    fn the_granule_conversion_is_total() {
        assert_eq!(granule_of(HugePageSize::Huge2M), HugeGranule::Huge2M);
        assert_eq!(granule_of(HugePageSize::Huge1G), HugeGranule::Huge1G);
        assert_eq!(granule_of(HugePageSize::Huge2M).bytes(), HugePageSize::Huge2M.bytes());
        assert_eq!(granule_of(HugePageSize::Huge1G).bytes(), HugePageSize::Huge1G.bytes());
    }
}
