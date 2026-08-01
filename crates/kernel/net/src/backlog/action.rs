// The NET_RX bottom half itself: handler installation, one drain pass, and the
// process-context entry point every socket call now uses in place of an inline
// receive traversal.

use core::sync::atomic::{AtomicBool, Ordering};

static INSTALLED: AtomicBool = AtomicBool::new(false);

/// Claim the NET_RX softirq slot for [`net_rx_action`]. Idempotent, and called
/// from every path that can raise the slot, so no boot ordering can leave a
/// raise with no handler behind it. # C: O(1)
pub fn install() {
    if INSTALLED.swap(true, Ordering::AcqRel) { return; }
    softirq::set_handler(softirq::Slot::NetRx, net_rx_action);
}

/// True once [`install`] has claimed the slot. # C: O(1)
pub fn installed() -> bool { INSTALLED.load(Ordering::Acquire) }

/// One drain pass over every RX source: registered device polls, then the
/// per-CPU backlog fed by the loopback poll list. Returns true when work
/// remains — the budget or the poll list ran out before the queues did.
/// # Ctx: NET_RX bottom half (or the hosted equivalent)
/// # C: O(NETDEV_BUDGET frames + registered polls)
pub fn net_rx_run() -> bool {
    super::napi::poll_all();
    crate::global_stack().do_net_rx()
}

/// NET_RX softirq handler. Re-raises itself when the pass ran out of budget,
/// which hands the remainder to this CPU's next drain (or its ksoftirqd) rather
/// than letting one drain monopolize the CPU.
/// # C: O(one drain pass)
pub fn net_rx_action() {
    if net_rx_run() { softirq::raise(softirq::Slot::NetRx); }
}

/// Publish pending receive work and let the bottom half take it — the sole
/// replacement for the old inline loopback drain.
///
/// Called from process context all over the socket layer (send, recv, poll,
/// shutdown, setsockopt, socket teardown). It must therefore stay cheap and
/// must not itself walk the receive path: the whole point is that the frame
/// traversal happens on the bottom half's stack, not the sender's.
/// # Ctx: process context; safe while bottom halves are disabled (the work
/// then runs at the outermost `local_bh_enable`, as the reference does).
/// # C: O(1) + the drain, which is bounded by `NETDEV_BUDGET`
pub fn net_rx_schedule() {
    install();
    super::bh::schedule();
}
