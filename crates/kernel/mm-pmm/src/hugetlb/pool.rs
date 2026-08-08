// The live huge-page pool: reserved huge frames, grow/shrink, hand-out.
//
// A huge page comes from HERE, never from an ordinary buddy allocation dressed
// up as one: the pool takes contiguous runs once, holds them, and serves them
// to hugetlbfs. That is what makes `nr_hugepages` mean something — an operator
// sizes the pool and the memory is set aside whether or not anything maps it.
//
// The counters and their decisions live in `hstate`; this module only performs
// the physical work each plan names. The pool lock is never held across a
// buddy call: plan under the lock, release, allocate, re-take, commit.

use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use sync::{HugetlbPool, Spinlock};

use super::charge;
use super::hstate::HstateCounts;
use super::sizes::HugePageSize;

/// Per-granule live state.
struct PoolState {
    counts: HstateCounts,
    /// Physical base addresses of the pool's unhanded-out huge pages.
    free: Vec<u64>,
    /// Every huge page the pool owns, so a frame handed back can be recognised
    /// as the pool's rather than the buddy's. A set, not a list: a page is
    /// looked up here on every release, and a linear scan turns each release
    /// into work proportional to the size of the pool.
    owned: BTreeSet<u64>,
}

impl PoolState {
    const fn new() -> Self {
        Self { counts: HstateCounts { max: 0, nr: 0, free: 0, resv: 0, surplus: 0, overcommit: 0 }, free: Vec::new(), owned: BTreeSet::new() }
    }
}

static POOL_2M: Spinlock<PoolState, HugetlbPool> = Spinlock::new(PoolState::new());
static POOL_1G: Spinlock<PoolState, HugetlbPool> = Spinlock::new(PoolState::new());

fn pool(size: HugePageSize) -> &'static Spinlock<PoolState, HugetlbPool> {
    match size { HugePageSize::Huge2M => &POOL_2M, HugePageSize::Huge1G => &POOL_1G }
}

/// Take one contiguous run of `size` from the buddy allocator.
///
/// Pool invariant: a page SITTING ON THE FREE LIST carries head refcount 0.
/// The owner reference is seeded when the page is handed out and dropped when
/// the owner releases it, so a page returned to the buddy on a shrink is as
/// unreferenced as the buddy expects — a run left holding stale references is
/// one `alloc_contig`'s in-use check refuses to hand out ever again.
/// # C: O(2^order)
fn buddy_take(size: HugePageSize) -> Option<u64> {
    crate::setup::alloc_contig(size.order())
}

/// Give one run back to the buddy allocator.
/// # SAFETY: `pa` came from `buddy_take(size)`, no PTE maps it, and no CPU or
/// device can still reach it — the pool only calls this for a page whose head
/// reference has dropped to zero.
/// # C: O(MAX_ORDER)
unsafe fn buddy_give_back(pa: u64, size: HugePageSize) {
    // SAFETY: per this function's contract, which the single caller
    // (`release_runs`) satisfies by only passing pages off the free list.
    unsafe { crate::setup::free_contig(pa, size.order()); }
}

/// Grow the pool by up to `n` pages, returning how many were obtained.
/// # C: O(n * 2^order)
fn acquire_runs(size: HugePageSize, n: u64, out: &mut Vec<u64>) -> u64 {
    let mut got = 0;
    for _ in 0..n {
        match buddy_take(size) { Some(pa) => { out.push(pa); got += 1; } None => break }
    }
    got
}

/// Return `runs` to the buddy allocator.
/// # C: O(n * MAX_ORDER)
fn release_runs(size: HugePageSize, runs: &[u64]) {
    for &pa in runs {
        // SAFETY: every entry came off the pool free list, so no PTE maps it and the pool held its only reference.
        unsafe { buddy_give_back(pa, size); }
    }
}

/// Resize the persistent pool of `size` to `count` pages. Returns the
/// persistent count actually reached, which is short of `count` when the
/// buddy allocator could not supply the memory or when outstanding
/// reservations forbid releasing it.
/// # C: O(|count - current| * 2^order)
pub fn set_nr_hugepages(size: HugePageSize, count: u64) -> u64 {
    let plan = { pool(size).lock().counts.plan_resize(count) };
    let mut fresh: Vec<u64> = Vec::new();
    if plan.alloc > 0 { acquire_runs(size, plan.alloc, &mut fresh); }
    let mut to_release: Vec<u64> = Vec::new();
    {
        let mut g = pool(size).lock();
        // Re-plan against the state as it stands now: a concurrent reservation
        // may have consumed the headroom this resize was planned against, and
        // releasing on the stale plan would break a promise made in between.
        let now = g.counts.plan_resize(count);
        let allocated = fresh.len() as u64;
        for _ in 0..core::cmp::min(now.release, g.free.len() as u64) {
            if let Some(pa) = g.free.pop() {
                g.owned.remove(&pa);
                to_release.push(pa);
            }
        }
        for &pa in fresh.iter() { g.free.push(pa); g.owned.insert(pa); }
        let released = to_release.len() as u64;
        g.counts.commit_resize(count, now.absorb_surplus, allocated, released);
        g.counts.persistent()
    };
    release_runs(size, &to_release);
    pool(size).lock().counts.persistent()
}

/// Reserve `delta` pages of `size` for a mapping that has not faulted them.
/// `Err(())` when the pool cannot promise them — the caller reports `ENOMEM`,
/// which is what a mapping too large for the pool gets.
/// # C: O(delta * 2^order)
pub fn reserve(size: HugePageSize, delta: u64) -> Result<(), ()> {
    if delta == 0 { return Ok(()); }
    // The controller is charged at RESERVATION time, before the pool promises
    // anything: a cgroup over its reservation limit must fail the mapping,
    // not discover at fault time that the promise cannot be kept.
    charge::charge_reserve(size, delta)?;
    let need = match pool(size).lock().counts.plan_reserve(delta) {
        Ok(n) => n,
        Err(()) => { charge::uncharge_reserve(size, delta); return Err(()); }
    };
    let mut fresh: Vec<u64> = Vec::new();
    if need > 0 && acquire_runs(size, need, &mut fresh) < need {
        release_runs(size, &fresh);
        charge::uncharge_reserve(size, delta);
        return Err(());
    }
    let mut g = pool(size).lock();
    // Re-check under the lock: a peer reservation may have taken the headroom
    // while this one was allocating, and two promises over one page is exactly
    // the over-promise the reservation exists to prevent.
    let recheck = g.counts.plan_reserve(delta);
    match recheck {
        Ok(_) => {
            let added = fresh.len() as u64;
            for &pa in fresh.iter() { g.free.push(pa); g.owned.insert(pa); }
            g.counts.commit_reserve(delta, added);
            Ok(())
        }
        Err(()) => {
            drop(g);
            release_runs(size, &fresh);
            charge::uncharge_reserve(size, delta);
            Err(())
        }
    }
}

/// Drop a reservation of `delta` pages that will never be faulted.
/// # C: O(1)
pub fn unreserve(size: HugePageSize, delta: u64) {
    if delta == 0 { return; }
    pool(size).lock().counts.unreserve(delta);
    charge::uncharge_reserve(size, delta);
}

/// Take one huge page out of the pool. `reserved` says the caller holds a
/// reservation covering it; without one the page may only come from the
/// unpromised remainder.
/// # C: O(1)
pub fn alloc_huge_frame(size: HugePageSize, reserved: bool) -> Option<u64> {
    // Charged before the page is taken, with the pool lock not yet held: a
    // cgroup at its limit must not consume a page it cannot be charged for.
    let charged = charge::charge_alloc(size, reserved).ok()?;
    let mut g = pool(size).lock();
    if !g.counts.dequeue(reserved) { drop(g); charge::cancel_alloc(size, charged); return None; }
    let Some(pa) = g.free.pop() else {
        g.counts.enqueue();
        drop(g);
        charge::cancel_alloc(size, charged);
        return None;
    };
    drop(g);
    charge::commit_alloc(size, pa, charged);
    // Seed the owner reference the caller now holds. A free-list page carries
    // none, so this is the only place a hugetlb page acquires one.
    // SAFETY: `pa` heads a pool-owned run that is off the free list and
    // therefore reachable by nothing else; the caller releases the reference
    // through `huge_frame_dec_and_maybe_release`.
    unsafe { crate::setup::inc_object_ref(pa); }
    Some(pa)
}

/// Put one huge page back. Only a page the pool owns is accepted; a frame from
/// anywhere else would corrupt both the free list and the counters.
/// # C: O(log nr)
pub fn free_huge_frame(size: HugePageSize, pa: u64) {
    let mut g = pool(size).lock();
    if !g.owned.contains(&pa) { return; }
    if g.free.contains(&pa) { return; }
    g.free.push(pa);
    g.counts.enqueue();
}

/// Add one mapping reference to a huge page.
/// # C: O(1)
pub fn huge_frame_inc_ref(pa: u64) {
    // SAFETY: `pa` is the head frame of a pool-owned run, allocated with an
    // object reference by `alloc_contig_object` and still held by the pool.
    unsafe { crate::setup::inc_ref(pa); }
}

/// Drop the OWNER's reference to a huge page and, when the last reference goes,
/// return the page to the pool free list.
///
/// The pool, not the buddy allocator, is where a hugetlb page goes when its
/// last user drops it: returning it to the buddy would silently shrink the pool
/// the operator sized, and `nr_hugepages` would stop describing reality.
/// Returns whether the page went back on the free list.
/// # C: O(log nr)
pub fn huge_frame_dec_and_maybe_release(size: HugePageSize, pa: u64) -> bool {
    // SAFETY: `pa` is a pool-owned head frame and the caller holds the owner
    // reference `alloc_huge_frame` handed out; the pool decides where the page
    // goes when the count reaches zero, which is what this primitive requires.
    let rest = unsafe { crate::setup::dec_ref_no_free(pa) };
    if rest != 0 { return false; }
    free_huge_frame(size, pa);
    // The charge is released where the page is released, against the cgroup
    // recorded when it was handed out — not against whoever happens to be
    // running now, which is routinely a different one.
    charge::uncharge_page(size, pa);
    true
}

/// Pages the pool owns for `size`.
/// # C: O(1)
pub fn nr_hugepages(size: HugePageSize) -> u64 { pool(size).lock().counts.nr }

/// Pages the pool owns and has not handed out.
/// # C: O(1)
pub fn free_hugepages(size: HugePageSize) -> u64 { pool(size).lock().counts.free }

/// Pages promised to mappings that have not faulted them.
/// # C: O(1)
pub fn resv_hugepages(size: HugePageSize) -> u64 { pool(size).lock().counts.resv }

/// Pages taken beyond the operator's target to satisfy a reservation.
/// # C: O(1)
pub fn surplus_hugepages(size: HugePageSize) -> u64 { pool(size).lock().counts.surplus }

/// Read the surplus ceiling.
/// # C: O(1)
pub fn nr_overcommit_hugepages(size: HugePageSize) -> u64 { pool(size).lock().counts.overcommit }

/// Set the surplus ceiling.
/// # C: O(1)
pub fn set_nr_overcommit_hugepages(size: HugePageSize, n: u64) {
    pool(size).lock().counts.overcommit = n;
}

/// Whether `pa` is the head of a page this pool owns.
/// # C: O(log nr)
pub fn owns(size: HugePageSize, pa: u64) -> bool {
    pool(size).lock().owned.contains(&pa)
}
