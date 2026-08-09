// The per-target call-function queue, modelled on the reference's
// `call_single_queue` llist plus its per-descriptor `csd_lock`.
//
// SHAPE. One slot per (sender, target) ORDERED PAIR, exactly as the
// reference gives each sender its own per-target call descriptor. That is
// what replaces this port's previous single global in-flight shootdown
// slot: two CPUs can now have calls outstanding to a third at the same
// time, and an acknowledgement can never be credited to the wrong request
// because a slot has exactly one possible owner. The round-id bookkeeping
// the single-slot protocol needed to fake that property is gone with it.
//
// PROTOCOL.
//   * `lock_slot` — the sender takes its own (sender, target) slot,
//     spinning until a previous call on that slot has completed. Only the
//     sender moves a slot Idle -> Locked; only the target moves it back.
//   * `push` — fill kind/arg, prepend to the target's list with a release
//     compare-exchange. Returns whether the list was EMPTY before, which is
//     the reference's rule for when an IPI is actually needed: a target
//     with work already queued will drain this entry too.
//   * `drain` — detach the whole list with one acquire swap, reverse it so
//     entries run in the order they were pushed, then for each entry read
//     its successor, run the handler, and only then release the slot. The
//     release AFTER the handler is the entire point: a sender that observes
//     its slot Idle knows the handler RAN, so it may free whatever the
//     handler was told to stop using.
//   * `is_complete` — the sender's side of that acquire/release pair.
//
// REENTRANCY. `drain` detaches before it runs anything, so a handler that
// re-enters `drain` on the same CPU (the spin-relax hook does exactly this)
// finds either an empty list or strictly newer entries — never the entries
// the outer drain is midway through.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use crate::MAX_CPUS;

/// Slot-index encoding in a queue head / `next` link: `index + 1`, so `0`
/// can mean "end of list" without stealing a real index.
const EMPTY: u32 = 0;

/// Slot lifecycle. Only two states are needed: the sender owns the slot from
/// `lock_slot` until the target finishes running the handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SlotState {
    /// Free for its sender to claim; the previous call on it has completed.
    Idle = 0,
    /// Claimed by its sender — filled, queued, or mid-execution on the target.
    Locked = 1,
}

/// One (sender, target) call descriptor.
struct Slot {
    state: AtomicU32,
    /// Next slot in the target's list, `EMPTY`-encoded.
    next: AtomicU32,
    /// Opaque call kind. The queue never interprets it.
    kind: AtomicU32,
    /// Opaque call argument.
    arg: AtomicU64,
}

impl Slot {
    const fn new() -> Self {
        Self {
            state: AtomicU32::new(SlotState::Idle as u32),
            next: AtomicU32::new(EMPTY),
            kind: AtomicU32::new(0),
            arg: AtomicU64::new(0),
        }
    }
}

/// Number of (sender, target) slots.
const NR_SLOTS: usize = MAX_CPUS * MAX_CPUS;

/// The whole cross-CPU call state: one slot per ordered CPU pair, one list
/// head per target.
pub struct CallQueues {
    slots: [Slot; NR_SLOTS],
    heads: [AtomicU32; MAX_CPUS],
}

impl Default for CallQueues {
    fn default() -> Self { Self::new() }
}

impl CallQueues {
    /// All slots idle, all lists empty.
    /// # C: O(1) — const-evaluated
    pub const fn new() -> Self {
        Self {
            slots: [const { Slot::new() }; NR_SLOTS],
            heads: [const { AtomicU32::new(EMPTY) }; MAX_CPUS],
        }
    }

    /// Slot index for an ordered pair. Out-of-range ids clamp, matching the
    /// clamp every caller of `current_cpu()` in this kernel already applies,
    /// so a slot a CPU writes is the slot it later reads back.
    /// # C: O(1)
    #[inline]
    fn idx(sender: usize, target: usize) -> usize {
        sender.min(MAX_CPUS - 1) * MAX_CPUS + target.min(MAX_CPUS - 1)
    }

    /// Current state of the sender's slot for `target`.
    /// # C: O(1)
    pub fn state(&self, sender: usize, target: usize) -> SlotState {
        match self.slots[Self::idx(sender, target)].state.load(Ordering::Acquire) {
            0 => SlotState::Idle,
            _ => SlotState::Locked,
        }
    }

    /// True once the target has finished running the sender's queued call.
    ///
    /// Acquire-paired with the target's release in `drain`, so everything the
    /// handler did is visible to the sender when this first returns true.
    /// # C: O(1)
    #[inline]
    pub fn is_complete(&self, sender: usize, target: usize) -> bool {
        self.state(sender, target) == SlotState::Idle
    }

    /// Claim the sender's slot for `target`, running `relax` while a previous
    /// call on that slot is still outstanding.
    ///
    /// `relax` is where the caller services its OWN queue: without it two
    /// CPUs each waiting to send to the other, with interrupts masked, never
    /// make progress.
    /// # C: O(1) uncontended
    pub fn lock_slot(&self, sender: usize, target: usize, mut relax: impl FnMut()) {
        let s = &self.slots[Self::idx(sender, target)];
        while s
            .state
            .compare_exchange(
                SlotState::Idle as u32,
                SlotState::Locked as u32,
                Ordering::Acquire,
                Ordering::Relaxed,
            )
            .is_err()
        {
            relax();
        }
    }

    /// Fill the sender's slot and prepend it to the target's list.
    ///
    /// Returns TRUE when the target's list was empty beforehand, meaning the
    /// caller must send the IPI. A false return is not a dropped call: the
    /// target already has an un-drained entry and will run this one in the
    /// same drain.
    ///
    /// # SAFETY-ADJACENT: the caller must hold the slot via `lock_slot`.
    /// # C: O(1) uncontended
    pub fn push(&self, sender: usize, target: usize, kind: u32, arg: u64) -> bool {
        let i = Self::idx(sender, target);
        let s = &self.slots[i];
        s.kind.store(kind, Ordering::Relaxed);
        s.arg.store(arg, Ordering::Relaxed);
        let head = &self.heads[target.min(MAX_CPUS - 1)];
        let mut cur = head.load(Ordering::Relaxed);
        loop {
            s.next.store(cur, Ordering::Relaxed);
            // Release publishes kind/arg/next to the target's acquire swap in
            // `drain`. A relaxed store here would let the target observe the
            // link and read a slot that has not been filled yet.
            match head.compare_exchange_weak(
                cur,
                (i as u32) + 1,
                Ordering::Release,
                Ordering::Relaxed,
            ) {
                Ok(_) => return cur == EMPTY,
                Err(seen) => cur = seen,
            }
        }
    }

    /// Run every call queued for `target`, oldest first, releasing each slot
    /// only after its handler returns.
    ///
    /// Idempotent and reentrant: a target with nothing queued does nothing,
    /// and the list is detached before any handler runs.
    /// # C: O(queued entries)
    pub fn drain(&self, target: usize, mut exec: impl FnMut(u32, u64)) {
        let head = &self.heads[target.min(MAX_CPUS - 1)];
        let taken = head.swap(EMPTY, Ordering::AcqRel);
        if taken == EMPTY { return; }

        // Reverse the prepend-built chain so entries run in push order. The
        // chain is detached, so rewriting `next` here races with nobody.
        let mut prev = EMPTY;
        let mut cur = taken;
        while cur != EMPTY {
            let s = &self.slots[(cur - 1) as usize];
            let nxt = s.next.load(Ordering::Acquire);
            s.next.store(prev, Ordering::Relaxed);
            prev = cur;
            cur = nxt;
        }

        let mut cur = prev;
        while cur != EMPTY {
            let s = &self.slots[(cur - 1) as usize];
            // Read the successor BEFORE releasing: once the slot is Idle its
            // sender may re-lock and re-link it, which would send this walk
            // into the new list.
            let nxt = s.next.load(Ordering::Relaxed);
            let kind = s.kind.load(Ordering::Relaxed);
            let arg = s.arg.load(Ordering::Relaxed);
            exec(kind, arg);
            // Release AFTER the handler ran. This is the ordering a caller
            // relies on to free a resource the handler was told to drop.
            s.state.store(SlotState::Idle as u32, Ordering::Release);
            cur = nxt;
        }
    }

    /// Release a slot the sender queued but could not deliver to (no
    /// hardware id for the target). Nothing ran, so nothing may be inferred
    /// from it — but leaving it Locked would hang the sender forever.
    ///
    /// The slot is unlinked by draining the target's list is NOT possible
    /// here (the target may be unreachable), so this is only correct for a
    /// slot that was never pushed.
    /// # C: O(1)
    pub fn abandon_unpushed(&self, sender: usize, target: usize) {
        self.slots[Self::idx(sender, target)]
            .state
            .store(SlotState::Idle as u32, Ordering::Release);
    }
}
