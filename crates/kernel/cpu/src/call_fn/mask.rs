// Target-set computation and stuck-wait bookkeeping for the cross-CPU call.
//
// Both are pure decisions with no LAPIC in scope, so they live here rather
// than in the arch driver where a test would compile out.

/// CPUs a call actually goes to: the caller's requested set, intersected
/// with the online set, minus the calling CPU.
///
/// Each term closes a real failure. A CPU that never loaded the mm has no
/// stale state to fix, so the requested set is the mm's `cpumask` and not
/// every CPU. A not-yet-online AP can never acknowledge, so waiting on one
/// is a guaranteed hang. And the caller runs its own side directly (the
/// reference's `SCF_RUN_LOCAL`), so including itself would deadlock a
/// waiting call against its own un-drained queue.
/// # C: O(1)
pub fn targets_for(requested: crate::CpuMask, online: crate::CpuMask, this_cpu: usize) -> crate::CpuMask {
    requested.intersect(online).without(crate::CpuMask::of(this_cpu))
}

/// Drop a target that could not be reached (its logical id has no hardware
/// id) from the pending set. It was never told to do anything, so waiting on
/// it is a hang for an acknowledgement that cannot arrive; and it cannot
/// hold stale state for an mm it was never able to run, because a CPU with
/// no hardware id is not a CPU this kernel ever scheduled on.
/// # C: O(1)
pub fn drop_unreachable(mut pending: crate::CpuMask, cpu: u32) -> crate::CpuMask {
    pending.remove(cpu as usize);
    pending
}

/// Whether the stuck-wait escalation is due. The reference's stuck-call
/// detection keys purely on a monotonic clock; this port also has to survive
/// the window where the TSC is not yet calibrated and `monotonic_ns()`
/// reports 0, so the spin count is the fallback measure. Losing the
/// diagnostic entirely is the one outcome the escalation exists to prevent.
/// # C: O(1)
pub fn escalation_due(now_ns: u64, next_warn_ns: u64, spins: u64, next_warn_spins: u64) -> bool {
    if now_ns != 0 { now_ns.wrapping_sub(next_warn_ns) as i64 >= 0 } else { spins >= next_warn_spins }
}

/// Gap before the NEXT escalation, given how many have already fired. The
/// reference backs its repeat off proportionally to the escalation count so
/// a genuinely wedged peer keeps naming itself without turning the console
/// into the reason it is wedged. Saturating, so a very long wait cannot wrap
/// the deadline backwards and fire every iteration.
/// # C: O(1)
pub fn escalation_gap(base_ns: u64, fired: u32) -> u64 {
    base_ns.saturating_mul(fired as u64 + 1)
}
