// Priority-class dispatch order for requests that could not be started
// immediately. This is the deadline scheduler's I/O-priority arm: requests are
// bucketed into three classes, higher classes are dispatched first, and a
// starvation guard promotes an older request from a lower class once it has
// waited past an aging bound.
//
// Ungated on purpose — the selection rule is the whole contract and it is
// hosted-tested here, not in a driver where it cannot be reached.

use sched::ioprio;

/// Dispatch classes, ordered most urgent first. Numerically lower is more
/// urgent, so the ordering is the enum discriminant.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum DispatchPrio {
    /// Real-time class.
    Rt = 0,
    /// Best-effort class. Also where an unset priority lands.
    Be = 1,
    /// Idle class — dispatched only when nothing else is waiting, subject to
    /// the aging guard.
    Idle = 2,
}

/// Number of dispatch classes.
pub const PRIO_COUNT: usize = 3;

/// How long a non-real-time request may wait before the aging guard promotes
/// it ahead of a higher class, in nanoseconds. Without it a saturating stream
/// of real-time I/O starves everything below it indefinitely.
pub const PRIO_AGING_EXPIRE_NS: u64 = 10_000_000_000;

/// Map a packed I/O priority onto its dispatch class. An unset class is
/// best-effort, as is anything outside the three defined classes.
/// # C: O(1)
pub fn dispatch_prio(packed: i32) -> DispatchPrio {
    match ioprio::prio_class(packed) {
        ioprio::CLASS_RT => DispatchPrio::Rt,
        ioprio::CLASS_IDLE => DispatchPrio::Idle,
        _ => DispatchPrio::Be,
    }
}

/// One waiting request, as far as dispatch order is concerned.
#[derive(Clone, Copy, Debug)]
pub struct Waiting {
    /// Packed I/O priority stamped at submission.
    pub ioprio: i32,
    /// Monotonic nanosecond timestamp of when the request started waiting.
    pub queued_ns: u64,
}

/// Pick the index of the next request to start from a queue of waiting ones.
///
/// Two rules, in order. First the aging guard: when requests from more than
/// one class are waiting, the oldest request outside the real-time class that
/// has waited longer than `aging_ns` is started next, so a real-time stream
/// cannot starve the classes below it forever. Otherwise strict class order:
/// the oldest request of the most urgent class present.
///
/// Ties within a class are broken by arrival order, so a queue whose requests
/// all share one priority dispatches in the order it received them.
/// # C: O(N_waiting)
pub fn select(queue: &[Waiting], now_ns: u64, aging_ns: u64) -> Option<usize> {
    if queue.is_empty() { return None; }
    let mut classes = [false; PRIO_COUNT];
    for w in queue { classes[dispatch_prio(w.ioprio) as usize] = true; }
    if classes.iter().filter(|p| **p).count() >= 2 {
        let cutoff = now_ns.saturating_sub(aging_ns);
        let mut aged: Option<(usize, DispatchPrio, u64)> = None;
        for (i, w) in queue.iter().enumerate() {
            let p = dispatch_prio(w.ioprio);
            if p == DispatchPrio::Rt || w.queued_ns > cutoff { continue; }
            // Most urgent aged class first, oldest within it.
            let better = match aged {
                None => true,
                Some((_, bp, bt)) => p < bp || (p == bp && w.queued_ns < bt),
            };
            if better { aged = Some((i, p, w.queued_ns)); }
        }
        if let Some((i, _, _)) = aged { return Some(i); }
    }
    let mut best: Option<(usize, DispatchPrio, u64)> = None;
    for (i, w) in queue.iter().enumerate() {
        let p = dispatch_prio(w.ioprio);
        let better = match best {
            None => true,
            Some((_, bp, bt)) => p < bp || (p == bp && w.queued_ns < bt),
        };
        if better { best = Some((i, p, w.queued_ns)); }
    }
    best.map(|(i, _, _)| i)
}

/// The effective I/O priority to stamp on a request being submitted.
///
/// A request that already names a class keeps it — a caller that deliberately
/// set one is not overridden. Anything still unset inherits the submitting
/// task's effective priority, which is where an `ioprio_set(2)` value actually
/// reaches the queue.
/// # C: O(1)
pub fn stamp(current: i32, submitter: i32) -> i32 {
    if ioprio::prio_class(current) == ioprio::CLASS_NONE { submitter } else { current }
}

#[cfg(test)]
mod tests;
