// `kernel.core_pipe_limit`: how many crashing processes may have a collector
// running at the same time.
//
// The knob is a CONCURRENCY cap, not a rate or a total. Its reason to exist is
// that every dump piped to a helper costs a process and a copy of the dump, so
// a crash loop across a machine's worth of workers can start a helper per
// worker and finish the machine off. The cap bounds that.
//
// Zero means no cap, and carries a specific cost rather than being simply
// permissive: the dumping thread only WAITS for its helper when a cap is set,
// so with no cap the crashing process is reaped as soon as its dump is handed
// over and a helper that wanted to read the dying process's entry under the
// process filesystem may find it already gone. Setting any cap — even a
// generous one — turns that wait on.

use core::sync::atomic::{AtomicU32, Ordering};

/// The value that means "no cap".
pub const CORE_PIPE_UNLIMITED: u32 = 0;

/// Concurrency accounting for the pipe destination: the live cap and how many
/// dumps are being collected right now.
pub struct PipeCounter {
    limit: AtomicU32,
    in_flight: AtomicU32,
}

impl PipeCounter {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { limit: AtomicU32::new(CORE_PIPE_UNLIMITED), in_flight: AtomicU32::new(0) }
    }

    /// The cap as `/proc/sys/kernel/core_pipe_limit` reports it. # C: O(1)
    pub fn limit(&self) -> u32 { self.limit.load(Ordering::Acquire) }

    /// Install a new cap. Dumps already in flight are unaffected — the cap is
    /// consulted once, when a dump starts. # C: O(1)
    pub fn set_limit(&self, v: u32) { self.limit.store(v, Ordering::Release); }

    /// Dumps being collected right now. # C: O(1)
    pub fn in_flight(&self) -> u32 { self.in_flight.load(Ordering::Acquire) }

    /// Claim a collection slot.
    ///
    /// The claim is taken FIRST and released by the returned guard whatever the
    /// verdict, so a refused dump cannot leak a slot and wedge the cap at its
    /// ceiling for the life of the boot. Ask the guard whether the dump may
    /// proceed; do not infer it from the call succeeding.
    /// # C: O(1)
    pub fn claim(&self) -> PipeSlot<'_> {
        let position = self.in_flight.fetch_add(1, Ordering::AcqRel) + 1;
        let limit = self.limit();
        PipeSlot { counter: self, admitted: admits(limit, position), waits: limit != CORE_PIPE_UNLIMITED }
    }
}

impl Default for PipeCounter {
    /// # C: O(1)
    fn default() -> Self { Self::new() }
}

/// Whether the dump holding the `position`-th slot may proceed under `limit`.
/// `position` counts the claim itself, so the first concurrent dump holds
/// position 1 and a limit of 1 admits it.
/// # C: O(1)
pub fn admits(limit: u32, position: u32) -> bool {
    limit == CORE_PIPE_UNLIMITED || position <= limit
}

/// A claimed collection slot, released on drop.
pub struct PipeSlot<'a> {
    counter: &'a PipeCounter,
    admitted: bool,
    waits: bool,
}

impl PipeSlot<'_> {
    /// Whether the dump may be collected. False means the cap was already
    /// reached and this dump is skipped. # C: O(1)
    pub fn admitted(&self) -> bool { self.admitted }

    /// Whether the crashing process must stay alive until its helper finishes.
    /// True exactly when a cap is set — see the module note on what a zero cap
    /// costs. # C: O(1)
    pub fn waits_for_helper(&self) -> bool { self.waits }
}

impl Drop for PipeSlot<'_> {
    /// # C: O(1)
    fn drop(&mut self) { self.counter.in_flight.fetch_sub(1, Ordering::AcqRel); }
}

/// The live cap and counter every pipe destination consults.
static CORE_PIPE: PipeCounter = PipeCounter::new();

/// Claim a slot on the live counter. # C: O(1)
pub fn claim_pipe_slot() -> PipeSlot<'static> { CORE_PIPE.claim() }

/// `/proc/sys/kernel/core_pipe_limit` read hook. # C: O(1)
pub fn core_pipe_limit() -> i64 { CORE_PIPE.limit() as i64 }

/// `/proc/sys/kernel/core_pipe_limit` write hook. The procfs leaf clamps to a
/// non-negative int before this runs. # C: O(1)
pub fn set_core_pipe_limit(v: i64) { CORE_PIPE.set_limit(v.clamp(0, u32::MAX as i64) as u32); }

/// Bind the cap into the process filesystem at boot, so the file reports the
/// value dumps actually consult rather than a cell nothing reads. # C: O(1)
pub fn register_limit_hooks() {
    procfs::hooks::set_core_pipe_limit_hooks(core_pipe_limit, set_core_pipe_limit);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_zero_cap_admits_every_concurrent_dump() {
        for position in [1u32, 2, 100, u32::MAX] {
            assert!(admits(CORE_PIPE_UNLIMITED, position), "{position}");
        }
    }

    #[test]
    fn a_cap_admits_exactly_that_many_at_once() {
        assert!(admits(1, 1));
        assert!(!admits(1, 2));
        assert!(admits(4, 4));
        assert!(!admits(4, 5));
    }

    #[test]
    fn the_slot_is_released_even_when_the_dump_was_refused() {
        let c = PipeCounter::new();
        c.set_limit(1);
        let first = c.claim();
        assert!(first.admitted());
        assert_eq!(c.in_flight(), 1);
        {
            let second = c.claim();
            assert!(!second.admitted(), "the second concurrent dump is over the cap");
            assert_eq!(c.in_flight(), 2);
        }
        // The refused dump gave its slot back, so the cap is not wedged.
        assert_eq!(c.in_flight(), 1);
        drop(first);
        assert_eq!(c.in_flight(), 0);
        assert!(c.claim().admitted(), "a released cap admits the next dump");
    }

    #[test]
    fn slots_are_released_in_any_order() {
        let c = PipeCounter::new();
        c.set_limit(3);
        let a = c.claim();
        let b = c.claim();
        let d = c.claim();
        assert!(a.admitted() && b.admitted() && d.admitted());
        assert_eq!(c.in_flight(), 3);
        assert!(!c.claim().admitted());
        drop(b);
        assert_eq!(c.in_flight(), 2);
        assert!(c.claim().admitted());
        drop(a);
        drop(d);
        assert_eq!(c.in_flight(), 0);
    }

    #[test]
    fn only_a_set_cap_makes_the_dumper_wait_for_its_helper() {
        let c = PipeCounter::new();
        assert!(!c.claim().waits_for_helper(), "with no cap the dump is handed over and abandoned");
        c.set_limit(1);
        assert!(c.claim().waits_for_helper());
    }

    #[test]
    fn raising_the_cap_does_not_disturb_dumps_already_in_flight() {
        let c = PipeCounter::new();
        c.set_limit(1);
        let held = c.claim();
        assert!(held.admitted());
        c.set_limit(8);
        assert!(c.claim().admitted());
        drop(held);
        assert_eq!(c.in_flight(), 0);
    }
}
