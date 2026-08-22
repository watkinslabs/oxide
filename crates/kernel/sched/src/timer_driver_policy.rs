//! Process-context timer-driver wake policy.

/// Maximum idle scan interval when no registered timer needs an earlier run.
pub const FALLBACK_NS: u64 = 100_000_000;

/// Deadline for the timer kthread's next park. A registered timer shortens
/// the bounded fallback; an already-due timer makes the predicate immediately
/// true rather than sleeping through work.
/// # C: O(1)
pub fn park_deadline(now_ns: u64, earliest_ns: Option<u64>) -> u64 {
    let fallback = now_ns.saturating_add(FALLBACK_NS);
    earliest_ns.map_or(fallback, |deadline| deadline.max(now_ns).min(fallback))
}

#[cfg(test)]
#[path = "timer_driver_policy/tests.rs"]
mod tests;
