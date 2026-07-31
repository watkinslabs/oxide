// fsnotify RESOURCE ACCOUNTING — the `/proc/sys/fs/inotify/*` tunables and the
// per-user counters they bound.
//
// Lives here rather than beside the inotify group code because the two knobs
// have two different owners in the Linux contract and only one crate can hold
// both: `max_queued_events` is an fs/notify variable, while
// `max_user_instances`/`max_user_watches` are per-user-namespace ucount ceilings
// that the notify code only reads. procfs binds all three leaves, and procfs
// cannot depend on the fs crate (fs already depends on procfs), so the shared
// VFS layer is where they can be reached from both sides without a cycle.
//
// Deliberately free of any target gate so the admission arithmetic is
// hosted-testable.

use core::sync::atomic::{AtomicI64, Ordering};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};

/// `inotify_max_queued_events` boot value: the per-group notification-queue
/// depth a group snapshots at `inotify_init` time.
pub const INOTIFY_DEFAULT_MAX_QUEUED_EVENTS: i64 = 16_384;
/// `init_user_ns.ucount_max[UCOUNT_INOTIFY_INSTANCES]` boot value.
pub const INOTIFY_DEFAULT_MAX_USER_INSTANCES: i64 = 128;
/// Lower clamp of the RAM-derived `UCOUNT_INOTIFY_WATCHES` boot value.
pub const INOTIFY_MIN_MAX_USER_WATCHES: u64 = 8_192;
/// Upper clamp of the same.
pub const INOTIFY_MAX_MAX_USER_WATCHES: u64 = 1_048_576;
/// Bytes of kernel memory one watch is charged against when deriving the
/// default ceiling: the mark plus the two inode-sized allowances the pinned
/// inode is budgeted at.
const INOTIFY_WATCH_COST: u64 = 1_024;

/// Boot-time `max_user_watches`: 1% of addressable RAM divided by the per-watch
/// cost, clamped to [8192, 1048576]. Pure arithmetic so the clamp ends are
/// checkable without a machine of either size.
/// # C: O(1)
pub fn watches_max_for_ram(total_ram_bytes: u64) -> u64 {
    let raw = (total_ram_bytes / 100) / INOTIFY_WATCH_COST;
    raw.clamp(INOTIFY_MIN_MAX_USER_WATCHES, INOTIFY_MAX_MAX_USER_WATCHES)
}

/// `fanotify_max_queued_events` boot value.
pub const FANOTIFY_DEFAULT_MAX_EVENTS: i64 = 16_384;
/// `init_user_ns.ucount_max[UCOUNT_FANOTIFY_GROUPS]` boot value.
pub const FANOTIFY_DEFAULT_MAX_GROUPS: i64 = 128;
/// Lower clamp of the RAM-derived `UCOUNT_FANOTIFY_MARKS` boot value — the
/// legacy per-group mark limit, now applied per user.
pub const FANOTIFY_MIN_MAX_USER_MARKS: u64 = 8_192;
/// Upper clamp: the legacy per-group limit times the per-user group ceiling.
pub const FANOTIFY_MAX_MAX_USER_MARKS: u64 =
    FANOTIFY_MIN_MAX_USER_MARKS * FANOTIFY_DEFAULT_MAX_GROUPS as u64;
/// Bytes charged per fanotify mark when deriving its default ceiling: pinning
/// the marked inode dominates, budgeted at two VFS inodes.
const INODE_MARK_COST: u64 = 1_024;

/// Boot-time `fanotify.max_user_marks`, the same 1%-of-RAM rule as inotify's
/// watch ceiling but with its own clamp window. # C: O(1)
pub fn marks_max_for_ram(total_ram_bytes: u64) -> u64 {
    ((total_ram_bytes / 100) / INODE_MARK_COST)
        .clamp(FANOTIFY_MIN_MAX_USER_MARKS, FANOTIFY_MAX_MAX_USER_MARKS)
}

static MAX_QUEUED_EVENTS:   AtomicI64 = AtomicI64::new(INOTIFY_DEFAULT_MAX_QUEUED_EVENTS);
static MAX_USER_INSTANCES:  AtomicI64 = AtomicI64::new(INOTIFY_DEFAULT_MAX_USER_INSTANCES);
static MAX_USER_WATCHES:    AtomicI64 = AtomicI64::new(INOTIFY_MIN_MAX_USER_WATCHES as i64);
static FAN_MAX_QUEUED_EVENTS: AtomicI64 = AtomicI64::new(FANOTIFY_DEFAULT_MAX_EVENTS);
static FAN_MAX_USER_GROUPS:   AtomicI64 = AtomicI64::new(FANOTIFY_DEFAULT_MAX_GROUPS);
static FAN_MAX_USER_MARKS:    AtomicI64 = AtomicI64::new(FANOTIFY_MIN_MAX_USER_MARKS as i64);

/// `fs.fanotify.max_queued_events`. # C: O(1)
pub fn fanotify_max_queued_events() -> i64 { FAN_MAX_QUEUED_EVENTS.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_fanotify_max_queued_events(v: i64) { FAN_MAX_QUEUED_EVENTS.store(v, Ordering::Relaxed); }
/// `fs.fanotify.max_user_groups`. # C: O(1)
pub fn fanotify_max_user_groups() -> i64 { FAN_MAX_USER_GROUPS.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_fanotify_max_user_groups(v: i64) { FAN_MAX_USER_GROUPS.store(v, Ordering::Relaxed); }
/// `fs.fanotify.max_user_marks`. # C: O(1)
pub fn fanotify_max_user_marks() -> i64 { FAN_MAX_USER_MARKS.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_fanotify_max_user_marks(v: i64) { FAN_MAX_USER_MARKS.store(v, Ordering::Relaxed); }

/// `fs.inotify.max_queued_events`. # C: O(1)
pub fn max_queued_events() -> i64 { MAX_QUEUED_EVENTS.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_max_queued_events(v: i64) { MAX_QUEUED_EVENTS.store(v, Ordering::Relaxed); }
/// `fs.inotify.max_user_instances`. # C: O(1)
pub fn max_user_instances() -> i64 { MAX_USER_INSTANCES.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_max_user_instances(v: i64) { MAX_USER_INSTANCES.store(v, Ordering::Relaxed); }
/// `fs.inotify.max_user_watches`. # C: O(1)
pub fn max_user_watches() -> i64 { MAX_USER_WATCHES.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_max_user_watches(v: i64) { MAX_USER_WATCHES.store(v, Ordering::Relaxed); }

/// Seed `max_user_watches` from the machine's RAM once the PMM knows it.
/// # C: O(1)
pub fn init_watches_max_from_ram(total_ram_bytes: u64) {
    set_max_user_watches(watches_max_for_ram(total_ram_bytes) as i64);
    set_fanotify_max_user_marks(marks_max_for_ram(total_ram_bytes) as i64);
}

/// One user's live charges. Linux keys ucounts on `(user_ns, euid)`; a single
/// initial user namespace makes the euid the whole key.
struct UserCounts { uid: u32, instances: i64, watches: i64, groups: i64, marks: i64 }

static COUNTS: Spinlock<Vec<UserCounts>, TaskListClass> = Spinlock::new(Vec::new());

/// Which ceiling a charge is tested against. # C: O(1)
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Ucount { InotifyInstances, InotifyWatches, FanotifyGroups, FanotifyMarks }

fn limit_of(k: Ucount) -> i64 {
    match k {
        Ucount::InotifyInstances => max_user_instances(),
        Ucount::InotifyWatches   => max_user_watches(),
        Ucount::FanotifyGroups   => fanotify_max_user_groups(),
        Ucount::FanotifyMarks    => fanotify_max_user_marks(),
    }
}

/// `inc_ucount` / `inc_rlimit_ucounts`: charge one unit to `uid` and return
/// `false` — WITHOUT charging — when that would pass the ceiling. The ceiling
/// is a `>` test on the POST-increment value, so a limit of N admits exactly N
/// live charges and a limit of 0 admits none.
/// # C: O(N_users)
pub fn inc_ucount(uid: u32, kind: Ucount) -> bool {
    let max = limit_of(kind);
    let mut g = COUNTS.lock();
    let idx = match g.iter().position(|c| c.uid == uid) {
        Some(i) => i,
        None => { g.push(UserCounts { uid, instances: 0, watches: 0, groups: 0, marks: 0 }); g.len() - 1 }
    };
    let cell = cell_of(&mut g[idx], kind);
    if *cell + 1 > max { return false; }
    *cell += 1;
    true
}

/// `dec_ucount` for `n` units. Saturates at zero rather than wrapping, so a
/// double-release can never mint credit that would let a user pass the ceiling.
/// # C: O(N_users)
pub fn dec_ucount(uid: u32, kind: Ucount, n: i64) {
    if n <= 0 { return; }
    let mut g = COUNTS.lock();
    let Some(idx) = g.iter().position(|c| c.uid == uid) else { return };
    let cell = cell_of(&mut g[idx], kind);
    *cell = (*cell - n).max(0);
    let c = &g[idx];
    if c.instances == 0 && c.watches == 0 && c.groups == 0 && c.marks == 0 { g.remove(idx); }
}

fn cell_of(c: &mut UserCounts, kind: Ucount) -> &mut i64 {
    match kind {
        Ucount::InotifyInstances => &mut c.instances,
        Ucount::InotifyWatches   => &mut c.watches,
        Ucount::FanotifyGroups   => &mut c.groups,
        Ucount::FanotifyMarks    => &mut c.marks,
    }
}

/// Live charge for `uid`. # C: O(N_users)
pub fn ucount(uid: u32, kind: Ucount) -> i64 {
    let mut g = COUNTS.lock();
    match g.iter().position(|c| c.uid == uid) {
        Some(i) => *cell_of(&mut g[i], kind),
        None => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Distinct uids per test: the counter table is process-global and the
    // hosted harness runs tests concurrently.
    #[test]
    fn instance_ceiling_admits_exactly_the_limit() {
        let uid = 90_001;
        set_max_user_instances(3);
        for i in 0..3 { assert!(inc_ucount(uid, Ucount::InotifyInstances), "charge {i} must fit"); }
        assert!(!inc_ucount(uid, Ucount::InotifyInstances), "the 4th passes the ceiling");
        assert_eq!(ucount(uid, Ucount::InotifyInstances), 3, "the refused charge was not taken");
        dec_ucount(uid, Ucount::InotifyInstances, 1);
        assert!(inc_ucount(uid, Ucount::InotifyInstances), "a release frees exactly one slot");
        dec_ucount(uid, Ucount::InotifyInstances, 3);
        set_max_user_instances(INOTIFY_DEFAULT_MAX_USER_INSTANCES);
    }

    #[test]
    fn a_zero_ceiling_admits_nothing() {
        let uid = 90_002;
        set_max_user_watches(0);
        assert!(!inc_ucount(uid, Ucount::InotifyWatches));
        assert_eq!(ucount(uid, Ucount::InotifyWatches), 0);
        set_max_user_watches(INOTIFY_MIN_MAX_USER_WATCHES as i64);
    }

    #[test]
    fn charges_are_per_user() {
        let (a, b) = (90_003, 90_004);
        set_max_user_watches(1);
        assert!(inc_ucount(a, Ucount::InotifyWatches));
        assert!(!inc_ucount(a, Ucount::InotifyWatches));
        assert!(inc_ucount(b, Ucount::InotifyWatches), "b's budget is its own");
        dec_ucount(a, Ucount::InotifyWatches, 1);
        dec_ucount(b, Ucount::InotifyWatches, 1);
        set_max_user_watches(INOTIFY_MIN_MAX_USER_WATCHES as i64);
    }

    #[test]
    fn release_saturates_at_zero() {
        let uid = 90_005;
        dec_ucount(uid, Ucount::InotifyWatches, 5);
        assert_eq!(ucount(uid, Ucount::InotifyWatches), 0, "no negative credit");
    }

    #[test]
    fn watches_default_is_one_percent_of_ram_clamped() {
        assert_eq!(watches_max_for_ram(0), INOTIFY_MIN_MAX_USER_WATCHES, "tiny machine clamps up");
        assert_eq!(watches_max_for_ram(512 << 20), INOTIFY_MIN_MAX_USER_WATCHES,
                   "512 MiB yields 5242 raw, below the floor");
        assert_eq!(watches_max_for_ram(1 << 30), 10_485, "1 GiB sits between the clamps");
        assert_eq!(watches_max_for_ram(u64::MAX), INOTIFY_MAX_MAX_USER_WATCHES, "huge machine clamps down");
    }

    #[test]
    fn queue_depth_default_matches_the_boot_value() {
        assert_eq!(INOTIFY_DEFAULT_MAX_QUEUED_EVENTS, 16_384);
        assert_eq!(INOTIFY_DEFAULT_MAX_USER_INSTANCES, 128);
        assert_eq!(FANOTIFY_DEFAULT_MAX_EVENTS, 16_384);
        assert_eq!(FANOTIFY_DEFAULT_MAX_GROUPS, 128);
        // Legacy per-group mark limit times the per-user group ceiling.
        assert_eq!(FANOTIFY_MAX_MAX_USER_MARKS, 1_048_576);
    }

    #[test]
    fn fanotify_counters_are_independent_of_inotify_counters() {
        let uid = 90_006;
        set_fanotify_max_user_groups(1);
        assert!(inc_ucount(uid, Ucount::FanotifyGroups));
        assert!(!inc_ucount(uid, Ucount::FanotifyGroups));
        assert!(inc_ucount(uid, Ucount::InotifyInstances), "a group charge is not an instance charge");
        assert_eq!(ucount(uid, Ucount::FanotifyGroups), 1);
        assert_eq!(ucount(uid, Ucount::InotifyInstances), 1);
        dec_ucount(uid, Ucount::FanotifyGroups, 1);
        dec_ucount(uid, Ucount::InotifyInstances, 1);
        set_fanotify_max_user_groups(FANOTIFY_DEFAULT_MAX_GROUPS);
    }
}
