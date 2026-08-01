// How pending RX work reaches the bottom half. The kernel and the hosted test
// build differ here and nowhere else, so the difference is isolated to this
// file rather than scattered through the drain logic (`08§7`, module-boundary
// rule for compiler-gated code).

/// Kernel: raise NET_RX on this CPU, then bracket a `local_bh_disable` /
/// `local_bh_enable` pair. The enable is what drains, and it drains through
/// the softirq handler table — an indirect call, which is precisely what keeps
/// the receive subtree off the calling (transmit) path's static call graph.
/// A caller already inside a bottom-half-disabled region leaves the work
/// pending for its own outermost enable, exactly as the reference does.
/// # C: O(1) + the drain
#[cfg(target_os = "oxide-kernel")]
pub(super) fn schedule() {
    softirq::raise(softirq::Slot::NetRx);
    let _bh = sched::bh::BhGuard::new();
}

/// Hosted: run the drain directly.
///
/// The per-CPU pending mask cannot be used here. Every hosted thread reports
/// CPU 0, so two `cargo test` threads share one pending bit: one thread's
/// claim of the mask would swallow the other's raise and the second thread's
/// packet would sit queued past the `recv` that expects it. Calling the pass
/// directly keeps the queue, budget, and delivery logic under test and drops
/// only the raise, whose purpose (severing a static call edge in a linked
/// kernel) has no hosted meaning.
/// # C: O(1) + the drain
#[cfg(not(target_os = "oxide-kernel"))]
pub(super) fn schedule() {
    // Bounded like the softirq restart gate: a drain that re-raises itself
    // because it exhausted its budget gets a fixed number of further passes,
    // never an unbounded loop.
    for _ in 0..HOSTED_MAX_PASSES {
        if !super::action::net_rx_run() { break; }
    }
}

#[cfg(not(target_os = "oxide-kernel"))]
const HOSTED_MAX_PASSES: usize = 10;
