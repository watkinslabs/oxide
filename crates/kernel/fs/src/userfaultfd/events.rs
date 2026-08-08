// The cooperative half: announcing an address-space change to a monitor that
// tracks mappings, and refusing every resolve while such a change is in flight.
//
// Two facts make this correct and both are here:
//   * The charge is taken BEFORE the change becomes visible and released only
//     once the monitor has taken the announcement, so there is no window in
//     which a resolve lands in a layout the monitor has not been told about.
//   * The changing thread BLOCKS on the announcement. A monitor therefore never
//     races the change it is being told about — by the time it sees the
//     message, the change is complete and nothing else has moved.
//
// The decisions (which feature gates which event, what the message carries,
// which queue a reader drains first, what the refusal errno is) are in
// `policy::events`; this file is the queueing, the block and the wake.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

use vmm::{UffdEvent, UffdEventKind};

use super::policy;
use super::{PendingEvent, UfData};

impl UfData {
    /// Whether this monitor negotiated the feature reporting `kind`.
    /// # C: O(1)
    pub(crate) fn wants(&self, kind: UffdEventKind) -> bool {
        policy::wants_event(self.features.load(Ordering::Acquire), kind)
    }

    /// Charge one in-flight change. # C: O(1)
    pub(crate) fn charge_change(&self) { self.mmap_changing.fetch_add(1, Ordering::AcqRel); }

    /// Release a charge without announcing anything — the change did not
    /// happen. Leaving it charged would refuse every later resolve forever.
    /// # C: O(1)
    pub(crate) fn release_change(&self) { self.mmap_changing.fetch_sub(1, Ordering::AcqRel); }

    /// Changes in flight, the value the resolve ladder is refused against.
    /// # C: O(1)
    pub(crate) fn changes_in_flight(&self) -> u32 { self.mmap_changing.load(Ordering::Acquire) }

    /// Queue `ev`, wake the monitor, and BLOCK until it has read the message.
    ///
    /// The charge is released by whoever ENDS the announcement — normally the
    /// reader, at the moment it takes the message. That is the exact boundary
    /// the refusal needs: a monitor that has not yet read the announcement
    /// finds every resolve refused, and one that has just read it finds the
    /// context accepting again without having to wait for the changing thread
    /// to be scheduled back in.
    /// # C: O(1) enqueue + block
    pub(crate) fn announce(&self, ev: UffdEvent) {
        let (event, a0, a1, a2) = policy::event_msg(ev);
        let consumed = Arc::new(AtomicBool::new(false));
        let charge = Arc::new(AtomicBool::new(true));
        let fork_child = if event == super::uapi::UFFD_EVENT_FORK {
            self.state.lock().pending_forks.pop_front()
        } else { None };
        self.state.lock().events.push_back(PendingEvent {
            event, a0, a1, a2, fork_child,
            consumed: consumed.clone(), charge: charge.clone(),
        });
        self.read_waiters.wake_all();
        self.poll.notify();
        self.wait_for_reader(&consumed, &charge);
    }

    /// Block until the reader takes the message.
    ///
    /// A deliverable signal ends the wait, and the announcement is then WITHDRAWN
    /// and its charge released: the changing thread is inside a syscall the
    /// caller can be killed out of, and a monitor that has stopped reading must
    /// not make every unmap in the process unkillable — nor leave the context
    /// refusing resolves forever afterwards.
    /// # C: O(1) + block
    #[cfg(target_os = "oxide-kernel")]
    fn wait_for_reader(&self, consumed: &Arc<AtomicBool>, charge: &Arc<AtomicBool>) {
        loop {
            if consumed.load(Ordering::Acquire) { return; }
            if sched::live::deliverable_signals_self() != 0 { break; }
            // SAFETY: running task; preempt-off; park marks Sleeping + bumps the Arc before schedule, and the reader wakes change_waiters once it has taken the message.
            unsafe { self.change_waiters.park(); }
            // SAFETY: process ctx; runqueue installed; preempt-off; current Sleeping so schedule won't re-enqueue until the reader's wake fires.
            unsafe { sched::live::schedule::schedule(); }
        }
        self.state.lock().events.retain(|e| !Arc::ptr_eq(&e.consumed, consumed));
        self.release_once(charge);
    }

    /// Hosted counterpart: there is no scheduler to park on, so the caller
    /// returns with the announcement still queued and still charged — which is
    /// the state a live generator is in while it is parked, and the state every
    /// hosted assertion about the refusal is made against.
    /// # C: O(1)
    #[cfg(not(target_os = "oxide-kernel"))]
    fn wait_for_reader(&self, _consumed: &Arc<AtomicBool>, _charge: &Arc<AtomicBool>) {}

    /// Release a charge at most once, whichever side ends the announcement.
    /// Without the exchange a withdrawal racing a read would decrement twice
    /// and leave the counter wrapped — every later resolve refused forever.
    /// # C: O(1)
    fn release_once(&self, charge: &Arc<AtomicBool>) {
        if charge.swap(false, Ordering::AcqRel) { self.release_change(); }
    }

    /// Mark one announcement handed over, release its charge, and release its
    /// generator.
    /// # C: O(N_waiters)
    pub(crate) fn finish_event(&self, ev: &PendingEvent) {
        ev.consumed.store(true, Ordering::Release);
        self.release_once(&ev.charge);
        self.change_waiters.wake_all();
    }

    /// Mint the context the CHILD address space carries across a fork, record
    /// it for the announcement, and charge the fork.
    ///
    /// The child gets its OWN context, inheriting this one's flags and
    /// negotiated features: from the fork on, the two address spaces are
    /// resolved independently, and a resolve aimed at one must never reach the
    /// other. Sharing the parent's context would make every `UFFDIO_*` on the
    /// fd ambiguous between them.
    /// # C: O(1)
    pub(crate) fn dup_for_fork(&self, child_mm: alloc::sync::Weak<vmm::AddressSpace>)
        -> Arc<UfData> {
        let child = super::new_context(self.flags.load(Ordering::Acquire),
                                       self.features.load(Ordering::Acquire),
                                       child_mm);
        self.charge_change();
        self.state.lock().pending_forks.push_back(child.clone());
        child
    }
}
