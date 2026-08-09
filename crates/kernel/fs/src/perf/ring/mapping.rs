// MAPPING LIFETIME of a perf ring — Linux `rb->mmap_count`, `rb->mmap_user`
// and `rb->mmap_locked`, driven by `perf_mmap_open`/`perf_mmap_close`.
//
// The charge `sizing::calc_limits` decides belongs to the BUFFER, not to any
// one VMA: a ring stays pinned while any mapping of it survives, so the
// per-user `locked_vm` pages are given back exactly when the last mapping goes
// away. Counting VMAs is what makes a split honest — `munmap` of a middle
// leaves two fragments, and both must disappear before the ring is unpinned.
//
// Deviation from the reference, deliberate and pinned by
// `an_aliasing_mmap_does_not_charge_twice`: upstream charges the full mapping
// again on every additional `mmap(2)` of an already-attached ring, while the
// release path runs once, so an alias loop walks `user->locked_vm` up until
// every further mmap returns EPERM. oxide charges once per BUFFER, which keeps
// the ladder's decisions identical for the single-mapping case every real
// profiler uses and makes charge and release a pair.
//
// No target gate: the whole open/close ladder is hosted-testable.

use sync::{PerfRing, Spinlock};

use super::locked_vm;

/// `rb->mmap_count` + `rb->mmap_user` + `rb->mmap_locked`.
#[derive(Default)]
struct Acct {
    /// Live VMAs mapping this buffer.
    count:      u64,
    /// `rb->mmap_user` — the uid the charge was taken from, which is the one
    /// it goes back to even when another process performs the last unmap.
    uid:        u32,
    /// Pages `calc_limits` booked against that user's `locked_vm`.
    user_pages: u64,
    /// Whether `user_pages` is currently ADDED to the ledger.
    applied:    bool,
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

    /// `rb->mmap_user = user; rb->mmap_locked = extra` — record what the
    /// admission ladder decided for the mapping that is creating this buffer.
    ///
    /// Recorded, not yet applied. An `mmap` that fails after the ring is
    /// allocated never opens a VMA, and a charge applied here would then have
    /// no close to release it — the reference has to undo that case by hand
    /// (`perf_mmap`'s error tail); deferring to the first open makes the case
    /// disappear.
    /// # C: O(1)
    pub fn record(&self, uid: u32, user_pages: u64) {
        let mut g = self.st.lock();
        if g.applied { return; }
        g.uid = uid;
        g.user_pages = user_pages;
    }

    /// Linux `perf_mmap_open`: one more VMA maps this buffer. The first one
    /// applies the recorded charge. Reports the new mapping count.
    /// # C: O(N_users)
    pub fn opened(&self) -> u64 {
        let mut g = self.st.lock();
        g.count += 1;
        if g.count == 1 && !g.applied && g.user_pages != 0 {
            locked_vm::charge(g.uid, g.user_pages);
            g.applied = true;
        }
        g.count
    }

    /// Linux `perf_mmap_close`: one VMA mapping this buffer is gone. `true`
    /// when that was the last one — the caller then detaches the buffer from
    /// its event, exactly as `ring_buffer_attach(event, NULL)` does.
    ///
    /// The charge is released here and only here, so a map/unmap loop returns
    /// the ledger to the value it started at however many times it runs.
    /// # C: O(N_users)
    pub fn closed(&self) -> bool {
        let mut g = self.st.lock();
        if g.count == 0 { return false; }
        g.count -= 1;
        if g.count != 0 { return false; }
        if g.applied {
            locked_vm::release(g.uid, g.user_pages);
            g.applied = false;
        }
        true
    }

    /// `refcount_read(&rb->mmap_count)`. # C: O(1)
    pub fn count(&self) -> u64 { self.st.lock().count }

    /// Pages currently charged to the owning user for this buffer, zero when
    /// the buffer is unmapped. # C: O(1)
    pub fn charged_pages(&self) -> u64 {
        let g = self.st.lock();
        if g.applied { g.user_pages } else { 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// uids outside anything the rest of the suite charges.
    fn uid(n: u32) -> u32 { 0x7100_0000 + n }

    const PAGES: u64 = 9;

    fn recorded(u: u32) -> MmapAccount {
        let a = MmapAccount::new();
        a.record(u, PAGES);
        a
    }

    /// THE regression this whole module exists for: a charge with no release
    /// is invisible until a long-lived process has cycled enough mappings to
    /// exhaust the allowance, at which point every `perf_event_open` mmap
    /// fails. Drop the `locked_vm::release` in `closed` and this goes red on
    /// the second iteration.
    #[test]
    fn a_map_unmap_loop_returns_the_ledger_to_its_starting_value() {
        let u = uid(1);
        let start = locked_vm::charged(u);
        for _ in 0..64 {
            let a = recorded(u);
            assert_eq!(a.opened(), 1);
            assert_eq!(locked_vm::charged(u), start + PAGES);
            assert!(a.closed());
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
        assert!(!a.closed());
        assert_eq!(a.count(), 2);
        assert_eq!(locked_vm::charged(u), start + PAGES);
        // First fragment away — still mapped, still charged.
        assert!(!a.closed());
        assert_eq!(locked_vm::charged(u), start + PAGES);
        // Last fragment away.
        assert!(a.closed());
        assert_eq!(locked_vm::charged(u), start);
        assert_eq!(a.charged_pages(), 0);
    }

    /// A fork copy of the mapping is another VMA on the same buffer: counted,
    /// never charged again.
    #[test]
    fn an_aliasing_mmap_does_not_charge_twice() {
        let u = uid(3);
        let start = locked_vm::charged(u);
        let a = recorded(u);
        a.opened();
        // A second `mmap(2)` of the same fd re-uses the buffer; `record` on an
        // already-charged account is a no-op.
        a.record(u, PAGES);
        a.opened();
        assert_eq!(locked_vm::charged(u), start + PAGES);
        assert!(!a.closed());
        assert!(a.closed());
        assert_eq!(locked_vm::charged(u), start);
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
        assert!(!a.closed());
        assert_eq!(locked_vm::charged(u), start);
    }

    /// A control-page-only ring whose whole charge spilled into the pinned
    /// half books nothing per-user, and must still not release anything.
    #[test]
    fn a_zero_page_charge_is_never_applied() {
        let u = uid(5);
        let a = MmapAccount::new();
        a.record(u, 0);
        a.opened();
        assert_eq!(locked_vm::charged(u), 0);
        assert!(a.closed());
        assert_eq!(locked_vm::charged(u), 0);
    }
}
