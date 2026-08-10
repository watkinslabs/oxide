// The memory-lock charge a ring books for every page it pins.
//
// A ring pins memory on a user's behalf and keeps it pinned until the ring is
// torn down: the SQ/CQ rings, the SQE array, a registered memory region, a
// provided-buffer ring, a zero-copy receive refill queue, the caller's own
// pages for a ring built with caller-supplied memory, and every registered
// buffer. Unaccounted, an unprivileged caller creates rings until the machine
// runs out — no ceiling and no record of who took the memory.
//
// One account, per UID, shared with every other kernel object that pins pages
// on a user's behalf ([`fs::locked_vm`]). Per-uid rather than per-ring or
// per-task is the whole point: a caller that could open a second ring to get a
// second allowance would have no ceiling at all.
//
// Two things the charge is NOT:
//
//   * not per-mapping — the pages are pinned by the RING, from setup to
//     teardown, whether or not userspace maps them;
//   * not the mm's pinned-page total on its own — a registered buffer and a
//     receive area are the caller's OWN pages held by the kernel, so those two
//     paths book both accounts ([`Ledgers`]).
//
// The ceiling is `RLIMIT_MEMLOCK`, read from the charging task, and a caller
// holding `CAP_IPC_LOCK` when it creates the ring escapes it: the ring is
// built with no account at all, so nothing it pins is charged or refused, for
// its whole life. Past the ceiling the answer is `ENOMEM` — the request could
// not be given the memory — and not `EPERM`.
//
// [`Charge`] is an RAII token because the release side is where this fails
// silently: a charge with no matching release does not refuse anything today,
// it walks the user's account up as rings are cycled until every later ring
// setup returns ENOMEM, long after the code that leaked it ran. Holding the
// token inside the pinned object makes teardown give back exactly what setup
// took, with no path that can forget.
//
// No target gate: every decision here is hosted-testable.

use syscall::errno::Errno;

/// Pages the accounting counts in.
pub const PAGE_SHIFT: u32 = 12;
/// Bytes per accounted page.
pub const PAGE_BYTES: u64 = 1 << PAGE_SHIFT;

/// Pages a byte count occupies, rounded up. # C: O(1)
pub fn pages_of(bytes: u64) -> u64 { bytes.div_ceil(PAGE_BYTES) }

/// `RLIMIT_MEMLOCK` in pages — the ceiling a charge is compared against.
/// # C: O(1)
pub fn limit_pages(rlim_bytes: u64) -> u64 { rlim_bytes >> PAGE_SHIFT }

/// Which accounts a pinning path answers to.
///
/// A region the ring owns is the ring's memory and lands in the user account
/// alone. A registered buffer or a receive area is memory the CALLER already
/// has mapped and the kernel now holds down, so it lands in the mapping mm's
/// pinned-page total as well — the number `/proc/<pid>/status` reports as
/// pinned, distinct from the locked extents `mlock` creates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ledgers {
    /// The per-user account only.
    User,
    /// The per-user account and the mm's pinned-page total.
    UserAndMm,
}

/// Whose account a ring's pinned pages land in.
///
/// `None` is a ring created by a caller holding `CAP_IPC_LOCK`: it books
/// nothing and is refused nothing, which is the escape, and it is decided ONCE
/// at setup so a ring does not change ceilings when its creator's credentials
/// do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RingAcct { pub uid: Option<u32> }

impl RingAcct {
    /// The account for a creator with the given real uid. # C: O(1)
    pub fn of(has_ipc_lock: bool, uid: u32) -> Self {
        Self { uid: if has_ipc_lock { None } else { Some(uid) } }
    }
    /// A ring nothing is charged for. # C: O(1)
    pub const UNCHARGED: Self = Self { uid: None };
}

/// A booked charge, given back when it is dropped.
///
/// Every pinned object holds one. The token knows the uid and the page count
/// it took, so teardown cannot give back a different number than setup took
/// even if the object's size changed underneath it.
#[derive(Debug)]
pub struct Charge {
    uid: Option<u32>,
    pages: u64,
}

impl Charge {
    /// A token that owes nothing — the empty registered-buffer slot, and every
    /// object of a ring with no account. # C: O(1)
    pub fn none() -> Self { Self { uid: None, pages: 0 } }

    /// Book `pages` against `acct`, refusing past `limit_pages` with the errno
    /// a caller that could not be given the memory gets.
    ///
    /// The comparison and the addition happen together inside the ledger: a
    /// check outside it would let two concurrent setups both pass and land the
    /// account past the ceiling. # C: O(N_users)
    pub fn take(acct: RingAcct, pages: u64, limit_pages: u64) -> Result<Self, Errno> {
        let Some(uid) = acct.uid else { return Ok(Self { uid: None, pages }) };
        if pages == 0 { return Ok(Self { uid: None, pages: 0 }); }
        match fs::locked_vm::charge_within(uid, pages, limit_pages) {
            Ok(_)  => Ok(Self { uid: Some(uid), pages }),
            Err(_) => Err(Errno::Enomem),
        }
    }

    /// Pages this token booked. Zero for an uncharged ring, which is why the
    /// mm half asks the PAGE COUNT it pinned rather than this. # C: O(1)
    pub fn pages(&self) -> u64 { if self.uid.is_some() { self.pages } else { 0 } }
}

impl Drop for Charge {
    /// # C: O(N_users)
    fn drop(&mut self) {
        if let Some(uid) = self.uid {
            if self.pages != 0 { fs::locked_vm::release(uid, self.pages); }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A uid range nothing else in the suite uses, so a stray charge cannot
    /// make one of these pass.
    fn uid(n: u32) -> u32 { 0x7100_0000 + n }

    /// Pages of a full-page and a partial byte count.
    #[test]
    fn a_partial_page_still_costs_a_whole_one() {
        assert_eq!(pages_of(0), 0);
        assert_eq!(pages_of(1), 1);
        assert_eq!(pages_of(PAGE_BYTES), 1);
        assert_eq!(pages_of(PAGE_BYTES + 1), 2);
    }

    #[test]
    fn the_ceiling_is_the_rlimit_in_pages() {
        assert_eq!(limit_pages(0), 0);
        assert_eq!(limit_pages(PAGE_BYTES * 8), 8);
        // A byte count short of a page buys no page.
        assert_eq!(limit_pages(PAGE_BYTES - 1), 0);
    }

    /// The ceiling is inclusive: a charge that lands exactly on it is admitted
    /// and the next page is not.
    #[test]
    fn the_ceiling_is_inclusive() {
        let u = uid(7);
        let acct = RingAcct::of(false, u);
        let held = Charge::take(acct, 8, 8).expect("exactly the ceiling");
        assert_eq!(Charge::take(acct, 1, 8).unwrap_err(), Errno::Enomem);
        drop(held);
        assert_eq!(fs::locked_vm::charged(u), 0);
    }

    #[test]
    fn a_creator_holding_the_capability_gets_no_account() {
        assert_eq!(RingAcct::of(true, 7).uid, None);
        assert_eq!(RingAcct::of(false, 7).uid, Some(7));
    }

    /// The pair. Positive control: drop the `Drop` release and this goes red
    /// on the second assertion.
    #[test]
    fn a_charge_and_its_drop_return_the_account_to_zero() {
        let u = uid(1);
        let acct = RingAcct::of(false, u);
        let start = fs::locked_vm::charged(u);
        {
            let _c = Charge::take(acct, 6, 1000).expect("under the ceiling");
            assert_eq!(fs::locked_vm::charged(u), start + 6);
        }
        assert_eq!(fs::locked_vm::charged(u), start);
    }

    /// The failure this file exists to prevent: rings cycled in a loop must
    /// leave the account exactly where they found it, or setup number N
    /// refuses for memory nobody is holding.
    ///
    /// Positive control: drop the release side and the account climbs by 6
    /// per iteration, failing here on the first pass.
    #[test]
    fn cycling_rings_returns_the_account_to_its_starting_value() {
        let u = uid(2);
        let acct = RingAcct::of(false, u);
        let start = fs::locked_vm::charged(u);
        for _ in 0..64 {
            let rings = Charge::take(acct, 4, 64).expect("headroom");
            let sqes  = Charge::take(acct, 2, 64).expect("headroom");
            assert_eq!(fs::locked_vm::charged(u), start + 6);
            drop(sqes);
            drop(rings);
            assert_eq!(fs::locked_vm::charged(u), start);
        }
        assert_eq!(fs::locked_vm::charged(u), start);
    }

    /// Past the ceiling is ENOMEM, and the refused charge books nothing.
    #[test]
    fn a_charge_past_the_ceiling_is_enomem_and_books_nothing() {
        let u = uid(3);
        let acct = RingAcct::of(false, u);
        let held = Charge::take(acct, 8, 10).expect("under the ceiling");
        assert_eq!(Charge::take(acct, 3, 10).unwrap_err(), Errno::Enomem);
        assert_eq!(fs::locked_vm::charged(u), 8, "the refused charge left no residue");
        drop(held);
        assert_eq!(fs::locked_vm::charged(u), 0);
    }

    /// A zero limit refuses any charge at all, and a ring whose creator holds
    /// the capability is refused nothing at that same limit.
    #[test]
    fn the_capability_escapes_a_zero_ceiling() {
        let u = uid(4);
        assert_eq!(Charge::take(RingAcct::of(false, u), 1, 0).unwrap_err(), Errno::Enomem);
        let c = Charge::take(RingAcct::of(true, u), 4096, 0).expect("no account, no ceiling");
        assert_eq!(c.pages(), 0, "an uncharged ring owes the mm half nothing either");
        assert_eq!(fs::locked_vm::charged(u), 0);
    }

    /// An empty registered-buffer slot pins nothing and must not create an
    /// account row for a user that pinned nothing.
    #[test]
    fn a_zero_page_charge_touches_no_account() {
        let u = uid(5);
        let c = Charge::take(RingAcct::of(false, u), 0, 0).expect("nothing to book");
        assert_eq!(c.pages(), 0);
        assert_eq!(fs::locked_vm::charged(u), 0);
    }

    /// Two rings of one user share the account, which is what makes the
    /// ceiling a ceiling.
    #[test]
    fn a_second_ring_of_the_same_user_shares_the_ceiling() {
        let u = uid(6);
        let acct = RingAcct::of(false, u);
        let first = Charge::take(acct, 6, 8).expect("headroom");
        assert_eq!(Charge::take(acct, 6, 8).unwrap_err(), Errno::Enomem);
        drop(first);
        drop(Charge::take(acct, 6, 8).expect("the first ring gave its pages back"));
        assert_eq!(fs::locked_vm::charged(u), 0);
    }
}
