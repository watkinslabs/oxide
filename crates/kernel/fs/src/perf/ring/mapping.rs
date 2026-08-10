// MAPPING LIFETIME of a perf ring: how many VMAs map it, whose per-user page
// allowance it is booked against, and how many pages of it are pinned against
// the mapping mm's `RLIMIT_MEMLOCK` headroom.
//
// The charge `sizing::calc_limits` decides belongs to the BUFFER, not to any
// one VMA: a ring stays pinned while any mapping of it survives, so the pages
// are given back exactly when the last mapping goes away. Counting VMAs is what
// makes a split honest — a `munmap` of the middle leaves two fragments, and
// both must disappear before the ring is unpinned.
//
// Every `mmap(2)` of the ring adds its own charge, including one that merely
// aliases an already-attached buffer; that is what makes an alias loop walk the
// per-user allowance up until further mappings are refused, rather than being
// free. The RELEASE gives back the accumulated total in one step at the last
// unmap, so charge and release are a pair however many times the ring was
// mapped — pinned by `an_alias_loop_charges_each_time_and_gives_it_all_back`.
//
// No target gate: the whole open/close ladder is hosted-testable.

use sync::{PerfRing, Spinlock};

use super::locked_vm;

/// Live VMA count, the charged uid, and both halves of the charge.
#[derive(Default)]
struct Acct {
    /// Live VMAs mapping this buffer.
    count:         u64,
    /// The uid the charge was taken from, which is the one it goes back to
    /// even when another process performs the last unmap.
    uid:           u32,
    /// Charge recorded by an `mmap(2)` that has not opened its VMA yet.
    pending_user:  u64,
    pending_pin:   u64,
    /// Charge currently ADDED to the per-user ledger.
    applied_user:  u64,
    /// Pages currently pinned against the mapping mm.
    applied_pin:   u64,
}

/// Per-buffer mapping account. # C: O(1) per operation
pub struct MmapAccount { st: Spinlock<Acct, PerfRing> }

impl Default for MmapAccount {
    /// # C: O(1)
    fn default() -> Self { Self::new() }
}

impl MmapAccount {
    /// # C: O(1)
    pub fn new() -> Self { Self { st: Spinlock::new(Acct::default()) } }

    /// Record what one `mmap(2)`'s admission ladder decided. Every mapping of
    /// the ring records its own charge, so an alias adds to the total rather
    /// than riding the first mapping's booking for free.
    ///
    /// Recorded, not yet applied: an `mmap` that fails after the ring is
    /// allocated never opens a VMA, and a charge applied here would then have
    /// no close to release it. Deferring to the VMA open makes that case
    /// disappear instead of needing an error-path undo.
    /// # C: O(1)
    pub fn record(&self, uid: u32, user_pages: u64, pinned_pages: u64) {
        let mut g = self.st.lock();
        if g.applied_user == 0 && g.applied_pin == 0 { g.uid = uid; }
        g.pending_user = g.pending_user.saturating_add(user_pages);
        g.pending_pin  = g.pending_pin.saturating_add(pinned_pages);
    }

    /// One more VMA maps this buffer; applies whatever charge is pending.
    /// Returns the pages the caller must pin against the mapping mm — nonzero
    /// only when this open applied a pending pinned charge.
    /// # C: O(N_users)
    pub fn opened(&self) -> u64 {
        let mut g = self.st.lock();
        g.count += 1;
        let (u, p) = (g.pending_user, g.pending_pin);
        g.pending_user = 0;
        g.pending_pin  = 0;
        if u != 0 { locked_vm::charge(g.uid, u); g.applied_user = g.applied_user.saturating_add(u); }
        if p != 0 { g.applied_pin = g.applied_pin.saturating_add(p); }
        p
    }

    /// One VMA mapping this buffer is gone. `(true, n)` when that was the last
    /// one — the caller then detaches the buffer from its event and gives `n`
    /// pinned pages back to the mapping mm.
    ///
    /// The charge is released here and only here, so a map/unmap loop returns
    /// both ledgers to the values they started at however many times it runs.
    /// # C: O(N_users)
    pub fn closed(&self) -> (bool, u64) {
        let mut g = self.st.lock();
        if g.count == 0 { return (false, 0); }
        g.count -= 1;
        if g.count != 0 { return (false, 0); }
        if g.applied_user != 0 { locked_vm::release(g.uid, g.applied_user); g.applied_user = 0; }
        let p = g.applied_pin;
        g.applied_pin = 0;
        (true, p)
    }

    /// Live VMA count for this buffer. # C: O(1)
    pub fn count(&self) -> u64 { self.st.lock().count }

    /// Pages currently charged to the owning user for this buffer, zero when
    /// the buffer is unmapped. # C: O(1)
    pub fn charged_pages(&self) -> u64 { self.st.lock().applied_user }

    /// Pages currently pinned against the mapping mm for this buffer.
    /// # C: O(1)
    pub fn pinned_pages(&self) -> u64 { self.st.lock().applied_pin }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// uids outside anything the rest of the suite charges.
    fn uid(n: u32) -> u32 { 0x7100_0000 + n }

    const PAGES: u64 = 9;

    fn recorded(u: u32) -> MmapAccount {
        let a = MmapAccount::new();
        a.record(u, PAGES, 0);
        a
    }

    /// THE regression this module exists for: a charge with no release is
    /// invisible until a long-lived process has cycled enough mappings to
    /// exhaust the allowance, at which point every mapping of a perf ring
    /// fails. Drop the `locked_vm::release` in `closed` and this goes red on
    /// the second iteration.
    #[test]
    fn a_map_unmap_loop_returns_the_ledger_to_its_starting_value() {
        let u = uid(1);
        let start = locked_vm::charged(u);
        for _ in 0..64 {
            let a = recorded(u);
            assert_eq!(a.opened(), 0);
            assert_eq!(locked_vm::charged(u), start + PAGES);
            assert_eq!(a.closed(), (true, 0));
            assert_eq!(locked_vm::charged(u), start);
        }
        assert_eq!(locked_vm::charged(u), start);
    }

    /// A `munmap` of the middle of a mapping leaves two fragments (the tree
    /// opens both and closes the original), so the ring stays charged until
    /// BOTH fragments go. Releasing on the first close would unpin a buffer
    /// userspace still maps.
    #[test]
    fn a_split_holds_the_charge_until_the_last_fragment_goes() {
        let u = uid(2);
        let start = locked_vm::charged(u);
        let a = recorded(u);
        a.opened();                                   // the establishing mmap
        // munmap of the middle: two fragments open, the original closes.
        a.opened();
        a.opened();
        assert_eq!(a.closed(), (false, 0));
        assert_eq!(a.count(), 2);
        assert_eq!(locked_vm::charged(u), start + PAGES);
        // First fragment away — still mapped, still charged.
        assert_eq!(a.closed(), (false, 0));
        assert_eq!(locked_vm::charged(u), start + PAGES);
        // Last fragment away.
        assert_eq!(a.closed(), (true, 0));
        assert_eq!(locked_vm::charged(u), start);
        assert_eq!(a.charged_pages(), 0);
    }

    /// A VMA that is a COPY of an existing mapping (a split fragment) records
    /// nothing of its own, so it is counted and never charged again.
    #[test]
    fn a_vma_copy_is_counted_but_not_charged() {
        let u = uid(3);
        let start = locked_vm::charged(u);
        let a = recorded(u);
        a.opened();
        a.opened();
        assert_eq!(locked_vm::charged(u), start + PAGES);
        assert_eq!(a.closed(), (false, 0));
        assert_eq!(a.closed(), (true, 0));
        assert_eq!(locked_vm::charged(u), start);
    }

    /// A SECOND `mmap(2)` of the same ring records its own charge, so the
    /// per-user total climbs with each alias and the allowance can eventually
    /// refuse one — an alias is not a way to map a ring for free. The whole
    /// accumulated total comes back at the last unmap, so charge and release
    /// stay a pair.
    ///
    /// POSITIVE CONTROL: make `record` a no-op once anything is applied and
    /// the mid-loop assertion drops to `start + PAGES`.
    #[test]
    fn an_alias_loop_charges_each_time_and_gives_it_all_back() {
        let u = uid(6);
        let start = locked_vm::charged(u);
        let a = recorded(u);
        a.opened();
        for i in 1..8u64 {
            a.record(u, PAGES, 0);
            a.opened();
            assert_eq!(locked_vm::charged(u), start + PAGES * (i + 1),
                       "alias {i} took its own charge");
        }
        assert_eq!(a.charged_pages(), PAGES * 8);
        for _ in 0..7 { assert_eq!(a.closed(), (false, 0)); }
        assert_eq!(a.closed(), (true, 0));
        assert_eq!(locked_vm::charged(u), start, "the accumulated total came back");
    }

    /// A ring allocated for an `mmap` that then fails opens no VMA, so nothing
    /// was ever charged and nothing is left behind when it is dropped.
    #[test]
    fn a_buffer_that_never_gets_mapped_holds_no_charge() {
        let u = uid(4);
        let start = locked_vm::charged(u);
        let a = recorded(u);
        assert_eq!(locked_vm::charged(u), start);
        assert_eq!(a.charged_pages(), 0);
        // A close with no open is not a release.
        assert_eq!(a.closed(), (false, 0));
        assert_eq!(locked_vm::charged(u), start);
    }

    /// A control-page-only ring whose whole charge spilled into the pinned
    /// half books nothing per-user, and must still not release anything.
    #[test]
    fn a_zero_page_charge_is_never_applied() {
        let u = uid(5);
        let a = MmapAccount::new();
        a.record(u, 0, 0);
        a.opened();
        assert_eq!(locked_vm::charged(u), 0);
        assert_eq!(a.closed(), (true, 0));
        assert_eq!(locked_vm::charged(u), 0);
    }

    /// The pinned half is reported to the caller at exactly the two points it
    /// must act on: the open that applies it and the last close that gives it
    /// back. Before this existed the pinned ledger stayed at zero, so the
    /// `RLIMIT_MEMLOCK` half of the admission ladder compared every mapping
    /// against nothing and could never refuse one.
    #[test]
    fn the_pinned_half_is_reported_at_the_open_and_the_last_close() {
        let u = uid(7);
        let a = MmapAccount::new();
        a.record(u, 4, 6);
        assert_eq!(a.pinned_pages(), 0, "nothing pinned before the VMA opens");
        assert_eq!(a.opened(), 6, "the open reports the pages to pin");
        assert_eq!(a.pinned_pages(), 6);
        // A second mapping of the same ring pins its own share too.
        a.record(u, 4, 2);
        assert_eq!(a.opened(), 2);
        assert_eq!(a.pinned_pages(), 8);
        assert_eq!(a.closed(), (false, 0), "not the last mapping, nothing given back");
        assert_eq!(a.closed(), (true, 8), "the last close returns the whole pinned total");
        assert_eq!(a.pinned_pages(), 0);
        locked_vm::release(u, locked_vm::charged(u).min(8));
    }
}
