// Where a ring's memory-lock charge meets the running task.
//
// The decision — who is charged, what the ceiling is, what a charge past it
// answers, and the pairing that gives it back — is
// [`crate::io_uring_abi::acct`], which is ungated and hosted-tested. This file
// is only the two lookups that need a live task: whose account a ring belongs
// to, and what that task's `RLIMIT_MEMLOCK` is (docs/53).

use core::sync::atomic::Ordering;

use syscall::errno::Errno;

use crate::io_uring_abi::acct::{limit_pages, pages_of, Charge, RingAcct};

/// The account a ring created now belongs to: the creator's REAL uid, or none
/// at all when the creator holds `CAP_IPC_LOCK`. Read ONCE, at setup — a ring
/// does not change ceilings when its creator's credentials later do.
/// # C: O(1)
pub fn of_current() -> RingAcct {
    let Some(cur) = sched::live::current() else { return RingAcct::UNCHARGED };
    RingAcct::of(cur.has_cap(sched::cap::IPC_LOCK), cur.creds.ruid.load(Ordering::Acquire))
}

/// The charging task's `RLIMIT_MEMLOCK` soft limit in pages. A charge with no
/// task behind it — teardown from a kernel context — is not admitted against
/// anything, because it is not a charge. # C: O(1)
fn ceiling() -> u64 {
    match sched::live::current() {
        Some(c) => limit_pages(c.rlimit(sched::rlimit::rlim::MEMLOCK).0),
        None => u64::MAX,
    }
}

/// Book the pages `bytes` occupies against `acct`. # C: O(N_users)
pub fn charge_bytes(acct: RingAcct, bytes: u64) -> Result<Charge, Errno> {
    Charge::take(acct, pages_of(bytes), ceiling())
}

/// Book `pages` against `acct` — the form a path that already counted its
/// frames uses, so an unaligned range is charged for the pages it really
/// pinned rather than the pages its length implies. # C: O(N_users)
pub fn charge_pages(acct: RingAcct, pages: u64) -> Result<Charge, Errno> {
    Charge::take(acct, pages, ceiling())
}
