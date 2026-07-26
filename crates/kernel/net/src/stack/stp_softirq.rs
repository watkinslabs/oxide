// Bridge STP as a softirq (Linux runs it from a `timer_list`, i.e.
// TIMER_SOFTIRQ) instead of directly in the hard-IRQ timer tick.
//
// `bridge_stp_tick` ages the forwarding database, runs the port state machine,
// and emits BPDUs — it takes the bridge's `state` lock and each interface's
// `inner` lock, allocates, and transmits through virtio. None of that is legal
// in a hard-IRQ handler: those locks are taken plainly by process context, so a
// tick landing on a CPU that already holds one wedges that CPU (`06§3.1`).
// lockdep reported it as the `Timer`-adjacent `Socket` class (`skizm.md`
// 3.1 #5).
//
// The tick now only raises the slot, which is one atomic OR. The work runs at
// the next `irq_exit` softirq drain or in `ksoftirqd` — still promptly, but in
// a context where taking those locks and allocating is allowed.
//
// This closes the hard-IRQ half of the violation. The process side must still
// take `Socket`-class locks with `spin_lock_bh` (`Spinlock::lock_bh`, built in
// `F705`) so a softirq drain cannot interrupt a holder; that sweep spans ~83
// sites across `net` and is tracked separately as Step 3e-bh.

use softirq::Slot;

/// Softirq handler: run one STP tick in bottom-half context.
/// # C: O(bridges * ports)
fn stp_softirq() {
    crate::global_stack().bridge_stp_tick(crate::stack::monotonic_ns_safe());
}

/// Install the STP softirq handler. Boot path, once, before the timer tick
/// starts raising the slot; an unraised slot with no handler is inert, so the
/// ordering is not load-bearing.
/// # C: O(1)
pub fn init() { softirq::set_handler(Slot::BridgeStp, stp_softirq); }

/// Raise the STP slot on this CPU. Called from the timer tick — one atomic OR,
/// with no lock and no allocation, which is all a hard-IRQ handler may do here.
/// # C: O(1)
/// # Ctx: hard IRQ
pub fn raise_from_tick() { softirq::raise(Slot::BridgeStp); }
