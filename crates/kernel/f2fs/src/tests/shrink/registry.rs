//! Mounts joining and leaving the reclaim list, and the two callbacks reclaim
//! calls, driven against real mounted volumes.
//!
//! The list is one static shared by every test in this binary, so nothing here
//! asserts an absolute list length or an absolute reclaim total. Each test
//! measures its OWN mount: how the list length moved across a mount and a drop,
//! and what that mount's caches held before and after.
//!
//! Measuring its own mount is NOT enough on its own, because a shrink pass is
//! process-wide: it walks every mount registered at that moment, so one test's
//! `scan` frees entries out of another test's mounts, in the middle of that
//! test's before/after pair. That made `one_budget_is_shared_across_mounts`
//! fail intermittently — a budget of 8 with more than 8 entries gone, all of
//! them taken by a sibling's pass. So every test that calls a pass, or reads a
//! global total, takes [`shrink_lock`] first, and they run one at a time.

use super::*;
use super::super::registry::{holds_ptr, listed, listings};
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::{BlockDevice, BlockRequest, MemDisk};
use sync::TaskList;

use crate::extent::{Gate, Info, Kind};
use crate::mount::F2fs;
use crate::opts::Options;
use crate::test_image;
use crate::uapi::BLKSIZE;

const BS: u32 = BLKSIZE as u32;

/// Serialise the tests that drive the process-wide reclaim list.
///
/// The list and both callbacks are one per machine by design. Two tests
/// measuring their own mounts across their own pass would still see each
/// other's, because neither pass is scoped to a mount.
struct ShrinkTestLockClass;
impl sync::LockClass for ShrinkTestLockClass {
    fn rank() -> u16 { 35 }
    fn name() -> &'static str { "ShrinkTestLockClass" }
}
static SHRINK_TEST_LOCK: sync::Spinlock<(), ShrinkTestLockClass> = sync::Spinlock::new(());
fn shrink_lock() -> sync::Guard<'static, (), ShrinkTestLockClass> { SHRINK_TEST_LOCK.lock() }
/// Runs to plant, comfortably more than a quarter-budget takes in one pass.
const PLANTED: u32 = 40;

/// A mount with BOTH extent caches on. The age cache is opt-in — a default
/// mount leaves it off and its shrink pass correctly frees nothing — so a test
/// about reclaiming age entries has to ask for the cache that holds them.
fn mounted() -> Arc<F2fs> {
    let bytes = test_image::with_root().finish();
    let blocks = bytes.len() as u64 / u64::from(BS);
    let dev: Arc<MemDisk<TaskList>> = MemDisk::new(BS, blocks);
    let mut req = BlockRequest::new_write(0, blocks as u32, bytes);
    dev.submit_sync(&mut req).expect("device write");
    let mut opts = Options::defaults();
    opts.age_extent_cache = true;
    F2fs::open_with(dev, "/dev/vda", true, opts).expect("mount")
}

/// Runs the mount's two extent caches hold right now.
fn held(fs: &Arc<F2fs>) -> (u64, u64) {
    let v = fs.volume.lock();
    let c = v.extents();
    (c.node_count(Kind::Read), c.node_count(Kind::BlockAge))
}

/// Plant separated runs in both caches of one mount. The gap between runs is
/// what keeps them from merging into one, which would leave a single entry for
/// reclaim to find however many were added.
fn plant(fs: &Arc<F2fs>) {
    let mut v = fs.volume.lock();
    let mut c = v.extents_mut();
    for i in 0..PLANTED {
        let ino = 100 + i;
        c.init_trees(ino, Gate::regular(), None);
        let fofs = i * 4096;
        c.update_range(Kind::Read, ino, Info::read(fofs, 64, 10_000 + fofs));
        c.update_range(Kind::BlockAge, ino, Info::aged(fofs, 64, 1, 0));
    }
}

/// Mounting is what publishes a volume's caches to reclaim. Before this lane
/// nothing outside the caches' own tests ever called a shrink pass.
#[test]
fn mounting_joins_the_reclaim_list_and_dropping_leaves_it() {
    let _g = shrink_lock();
    let fs = mounted();
    assert!(listed(&fs), "a mount did not join the reclaim list");
    let ptr = Arc::as_ptr(&fs);
    drop(fs);
    assert!(!holds_ptr(ptr), "a dropped mount stayed in the reclaim list");
}

#[test]
fn a_mount_joining_twice_is_listed_once() {
    let _g = shrink_lock();
    let fs = mounted();
    assert_eq!(listings(&fs), 1);
    crate::shrink::join(&fs);
    assert_eq!(listings(&fs), 1, "a second join listed the same mount twice");
}

/// The count callback reports the entries a mount could give back, so it must
/// move when the mount's caches do.
#[test]
fn the_count_callback_rises_with_what_a_mount_has_cached() {
    let _g = shrink_lock();
    let fs = mounted();
    let before = count();
    plant(&fs);
    let after = count();
    let (read, age) = held(&fs);
    assert!(read > 0 && age > 0, "nothing was planted");
    assert!(after >= before + (read + age) as usize,
            "count {after} did not account for {read} read and {age} age entries over {before}");
}

/// The pass that reclaim actually calls, over a real mount's caches. The whole
/// point of the lane: this is the caller the shrink passes did not have.
#[test]
fn the_scan_callback_frees_a_mounts_cached_runs() {
    let _g = shrink_lock();
    let fs = mounted();
    plant(&fs);
    let (read_before, age_before) = held(&fs);
    let freed = scan(1_000);
    let (read_after, age_after) = held(&fs);
    assert!(freed > 0, "a scan over a populated cache freed nothing");
    assert!(read_after < read_before, "the read cache did not shrink");
    assert!(age_after < age_before, "the age cache did not shrink");
}

/// A budget is honoured, not treated as a hint. A pass that frees everything it
/// can find would empty a cache the machine asked for four entries from.
#[test]
fn a_scan_frees_no_more_than_its_budget() {
    let _g = shrink_lock();
    let fs = mounted();
    plant(&fs);
    let (read_before, age_before) = held(&fs);
    let freed = scan(8);
    assert!(freed <= 8, "a scan for 8 freed {freed}");
    let (read_after, age_after) = held(&fs);
    let gone = (read_before - read_after) + (age_before - age_after);
    assert!(gone <= 8, "a scan for 8 dropped {gone} entries");
    assert!(read_after > 0 || age_after > 0, "a small budget emptied the caches");
}

#[test]
fn a_scan_asked_for_nothing_frees_nothing() {
    let _g = shrink_lock();
    let fs = mounted();
    plant(&fs);
    let (read_before, age_before) = held(&fs);
    assert_eq!(scan(0), 0);
    assert_eq!(held(&fs), (read_before, age_before));
}

/// Leaving empties both caches rather than letting them go as part of the
/// filesystem disappearing, so the entries are accounted for as reclaimed.
#[test]
fn leaving_empties_both_extent_caches() {
    let _g = shrink_lock();
    let fs = mounted();
    plant(&fs);
    assert_ne!(held(&fs), (0, 0));
    // The one mount whose lock nobody else holds, which is what `leave` needs.
    let mut owned = Arc::try_unwrap(fs).map_err(|_| ()).expect("sole reference");
    crate::shrink::leave(&mut owned);
    let v = owned.volume.lock();
    let c = v.extents();
    assert_eq!((c.node_count(Kind::Read), c.node_count(Kind::BlockAge)), (0, 0));
    assert_eq!((c.zombie_count(Kind::Read), c.zombie_count(Kind::BlockAge)), (0, 0));
}

/// A mount that has gone away must not be visited again. The list holds weak
/// references precisely so it is not what keeps a filesystem alive.
#[test]
fn a_dropped_mount_is_not_visited_by_a_later_pass() {
    let _g = shrink_lock();
    let fs = mounted();
    plant(&fs);
    let ptr = Arc::as_ptr(&fs);
    drop(fs);
    assert!(!holds_ptr(ptr));
    // Both callbacks must survive walking a list that just lost an entry.
    let _ = count();
    let _ = scan(64);
}

/// Several mounts share one budget: reclaim asked for a number of entries, not
/// for that number from every mount it can find.
#[test]
fn one_budget_is_shared_across_mounts() {
    let _g = shrink_lock();
    let all: Vec<Arc<F2fs>> = (0..3).map(|_| mounted()).collect();
    for fs in &all { plant(fs); }
    let before: Vec<(u64, u64)> = all.iter().map(held).collect();
    let freed = scan(8);
    assert!(freed <= 8, "three mounts freed {freed} against a budget of 8");
    let after: Vec<(u64, u64)> = all.iter().map(held).collect();
    let gone: u64 = before.iter().zip(&after)
        .map(|((r0, a0), (r1, a1))| (r0 - r1) + (a0 - a1)).sum();
    assert!(gone <= 8, "three mounts dropped {gone} entries against a budget of 8");
}
