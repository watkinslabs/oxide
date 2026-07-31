// epoll RESOURCE ACCOUNTING — the `/proc/sys/fs/epoll/max_user_watches`
// tunable and the per-user interest counter it bounds.
//
// Lives in the shared VFS layer rather than beside the epoll code for the same
// reason `crate::fsnotify` does: procfs binds the sysctl leaf and cannot depend
// on the fs crate (fs already depends on procfs), so this is the only place
// both sides can reach.
//
// Deliberately free of any target gate so the admission arithmetic is
// hosted-testable.

use core::sync::atomic::{AtomicI64, Ordering};
use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};

/// Bytes one live interest is charged against when deriving the default
/// ceiling: the interest record plus the wait-queue entry it registers.
const EP_ITEM_COST: u64 = 128 + 72;

/// Fraction of addressable RAM a single user's interests may occupy: the top
/// 4% of low memory.
const EP_RAM_DIVISOR: u64 = 25;

/// Ceiling used until the PMM reports the machine's RAM.
pub const EPOLL_DEFAULT_MAX_USER_WATCHES: i64 = 4 * 1024 * 1024 / (EP_ITEM_COST as i64);

/// Boot-time `max_user_watches`: 4% of addressable RAM divided by the per-item
/// cost. Pure arithmetic so the derivation is checkable without a machine of
/// any given size. # C: O(1)
pub fn watches_max_for_ram(total_ram_bytes: u64) -> u64 {
    (total_ram_bytes / EP_RAM_DIVISOR) / EP_ITEM_COST
}

static MAX_USER_WATCHES: AtomicI64 = AtomicI64::new(EPOLL_DEFAULT_MAX_USER_WATCHES);

/// `fs.epoll.max_user_watches`. # C: O(1)
pub fn max_user_watches() -> i64 { MAX_USER_WATCHES.load(Ordering::Relaxed) }
/// # C: O(1)
pub fn set_max_user_watches(v: i64) { MAX_USER_WATCHES.store(v, Ordering::Relaxed); }

/// Seed the ceiling from the machine's RAM once the PMM knows it. # C: O(1)
pub fn init_watches_max_from_ram(total_ram_bytes: u64) {
    set_max_user_watches(watches_max_for_ram(total_ram_bytes) as i64);
}

/// One user's live interest charge. Linux keys the counter on the
/// `user_struct` behind the epoll file's creator.
struct UserWatches { uid: u32, watches: i64 }

static COUNTS: Spinlock<Vec<UserWatches>, TaskListClass> = Spinlock::new(Vec::new());

/// Charge one interest to `uid`, refusing — without charging — once the
/// ceiling is reached. The test is `>=` on the PRE-increment value, so a limit
/// of N admits exactly N live interests and a limit of 0 admits none.
/// # C: O(N_users)
pub fn charge_watch(uid: u32) -> bool {
    let max = max_user_watches();
    let mut g = COUNTS.lock();
    let idx = match g.iter().position(|c| c.uid == uid) {
        Some(i) => i,
        None => { g.push(UserWatches { uid, watches: 0 }); g.len() - 1 }
    };
    if g[idx].watches >= max { return false; }
    g[idx].watches += 1;
    true
}

/// Release `n` interests. Saturates at zero rather than wrapping, so a
/// double-release can never mint credit past the ceiling. # C: O(N_users)
pub fn release_watches(uid: u32, n: i64) {
    if n <= 0 { return; }
    let mut g = COUNTS.lock();
    let Some(idx) = g.iter().position(|c| c.uid == uid) else { return };
    g[idx].watches = (g[idx].watches - n).max(0);
    if g[idx].watches == 0 { g.remove(idx); }
}

/// Live interest charge for `uid`. # C: O(N_users)
pub fn watches(uid: u32) -> i64 {
    let g = COUNTS.lock();
    g.iter().find(|c| c.uid == uid).map(|c| c.watches).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Distinct uids per test: the counter table is process-global and the
    // hosted harness runs tests concurrently.
    #[test]
    fn the_ceiling_admits_exactly_the_limit() {
        let uid = 91_001;
        set_max_user_watches(3);
        for i in 0..3 { assert!(charge_watch(uid), "interest {i} must fit"); }
        assert!(!charge_watch(uid), "the 4th is refused (ENOSPC)");
        assert_eq!(watches(uid), 3, "the refused charge was not taken");
        release_watches(uid, 1);
        assert!(charge_watch(uid), "a removed interest frees exactly one slot");
        release_watches(uid, 3);
        set_max_user_watches(EPOLL_DEFAULT_MAX_USER_WATCHES);
    }

    #[test]
    fn a_zero_ceiling_admits_nothing() {
        let uid = 91_002;
        set_max_user_watches(0);
        assert!(!charge_watch(uid));
        assert_eq!(watches(uid), 0);
        set_max_user_watches(EPOLL_DEFAULT_MAX_USER_WATCHES);
    }

    #[test]
    fn charges_are_per_user() {
        let (a, b) = (91_003, 91_004);
        set_max_user_watches(1);
        assert!(charge_watch(a));
        assert!(!charge_watch(a));
        assert!(charge_watch(b), "b's budget is its own");
        release_watches(a, 1);
        release_watches(b, 1);
        set_max_user_watches(EPOLL_DEFAULT_MAX_USER_WATCHES);
    }

    #[test]
    fn release_saturates_at_zero() {
        let uid = 91_005;
        release_watches(uid, 5);
        assert_eq!(watches(uid), 0, "no negative credit");
    }

    #[test]
    fn the_default_is_four_percent_of_ram_over_the_item_cost() {
        assert_eq!(watches_max_for_ram(0), 0);
        // 4% of 1 GiB divided by the per-item cost.
        assert_eq!(watches_max_for_ram(1 << 30), ((1u64 << 30) / 25) / EP_ITEM_COST);
        assert!(watches_max_for_ram(4 << 30) > watches_max_for_ram(1 << 30));
    }
}
