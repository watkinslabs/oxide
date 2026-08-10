// `user_struct->locked_vm` — the per-USER page charge every kernel object that
// pins memory on a user's behalf is booked against. Reachable as
// `fs::locked_vm`; a mapped perf ring is one such object and an io_uring ring
// is another, and they share ONE account by design.
//
// The account is per uid, not per task and not per mapping: a user's whole
// `sysctl_perf_event_mlock` allowance is shared by every event they map, which
// is what stops one process opening unbounded pinned ring memory by opening
// more events. The same holds across object kinds — a second account beside
// this one would be a second allowance and therefore no ceiling at all.
// `sizing::calc_limits` decides how much of a perf mapping lands here; this
// module is only where the running total lives.
//
// The release side is the reason this is a ledger and not a counter: a charge
// with no matching release does not fail fast, it fails LATER — a process that
// cycles perf mappings walks the total up until every further `mmap` returns
// EPERM, long after the code that leaked it ran. `mmap_charge` and
// `mmap_release` are therefore one pair, driven by the mapped object's
// `vm_ops->open`/`->close` (`ring::mapping`).
//
// No target gate: every decision here is hosted-testable.

use alloc::vec::Vec;
use sync::{Spinlock, TaskList as TaskListClass};

/// One user's live perf locked-page charge.
struct UserLocked { uid: u32, pages: u64 }

static CHARGES: Spinlock<Vec<UserLocked>, TaskListClass> = Spinlock::new(Vec::new());

/// Add `pages` to `uid`'s account and report the new total.
/// # C: O(N_users)
pub fn charge(uid: u32, pages: u64) -> u64 { account(uid, pages as i64) }

/// Give back `pages` previously charged to `uid`; reports the new total.
/// Saturates at zero rather than wrapping — an over-release is a lost charge,
/// not a user who may pin the whole machine.
/// # C: O(N_users)
pub fn release(uid: u32, pages: u64) -> u64 { account(uid, -(pages as i64)) }

/// Add `pages` to `uid`'s account only if the result stays within `limit`,
/// reporting the new total; `Err` carries the unchanged total.
///
/// The comparison happens under the account's own lock because a caller that
/// read the total, compared it and then charged would let two concurrent
/// charges both pass and land the account past the ceiling — the ceiling would
/// hold for one caller at a time and for nobody under load.
/// # C: O(N_users)
pub fn charge_within(uid: u32, pages: u64, limit: u64) -> Result<u64, u64> {
    let mut g = CHARGES.lock();
    let cur = g.iter().find(|c| c.uid == uid).map(|c| c.pages).unwrap_or(0);
    match cur.checked_add(pages) {
        Some(new) if new <= limit => {}
        _ => return Err(cur),
    }
    Ok(account_locked(&mut g, uid, pages as i64))
}

/// `atomic_long_read(&user->locked_vm)` — what `calc_limits` reads.
/// # C: O(N_users)
pub fn charged(uid: u32) -> u64 {
    let g = CHARGES.lock();
    g.iter().find(|c| c.uid == uid).map(|c| c.pages).unwrap_or(0)
}

fn account(uid: u32, delta: i64) -> u64 {
    let mut g = CHARGES.lock();
    account_locked(&mut g, uid, delta)
}

fn account_locked(g: &mut Vec<UserLocked>, uid: u32, delta: i64) -> u64 {
    let idx = match g.iter().position(|c| c.uid == uid) {
        Some(i) => i,
        None => {
            if delta <= 0 { return 0; }
            if g.try_reserve(1).is_err() { return 0; }
            g.push(UserLocked { uid, pages: 0 });
            g.len() - 1
        }
    };
    let cur = g[idx].pages;
    g[idx].pages = if delta >= 0 { cur.saturating_add(delta as u64) }
                   else { cur.saturating_sub(delta.unsigned_abs()) };
    let total = g[idx].pages;
    // An account back at zero holds no state worth a row.
    if total == 0 { g.remove(idx); }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A uid nothing else in the suite uses, so a stray charge from another
    /// test cannot make one of these pass.
    fn uid(n: u32) -> u32 { 0x7000_0000 + n }

    #[test]
    fn a_charge_and_its_release_return_the_account_to_zero() {
        let u = uid(1);
        assert_eq!(charged(u), 0);
        assert_eq!(charge(u, 9), 9);
        assert_eq!(charge(u, 5), 14);
        assert_eq!(release(u, 9), 5);
        assert_eq!(release(u, 5), 0);
        assert_eq!(charged(u), 0);
    }

    #[test]
    fn accounts_are_per_user() {
        let (a, b) = (uid(2), uid(3));
        charge(a, 7);
        assert_eq!(charged(b), 0);
        charge(b, 3);
        assert_eq!(charged(a), 7);
        release(a, 7);
        assert_eq!(charged(b), 3);
        release(b, 3);
    }

    /// The bounded charge admits up to the ceiling inclusive, refuses past it,
    /// and a refusal leaves the account exactly as it was.
    #[test]
    fn a_bounded_charge_stops_at_the_ceiling_and_leaves_no_residue() {
        let u = uid(5);
        assert_eq!(charge_within(u, 8, 10), Ok(8));
        assert_eq!(charge_within(u, 2, 10), Ok(10));
        assert_eq!(charge_within(u, 1, 10), Err(10));
        assert_eq!(charged(u), 10);
        release(u, 10);
        assert_eq!(charged(u), 0);
        // A user with no row is refused without gaining one.
        assert_eq!(charge_within(u, 1, 0), Err(0));
        assert_eq!(charged(u), 0);
    }

    #[test]
    fn an_over_release_saturates_at_zero() {
        let u = uid(4);
        charge(u, 2);
        assert_eq!(release(u, 40), 0);
        assert_eq!(charged(u), 0);
    }
}
