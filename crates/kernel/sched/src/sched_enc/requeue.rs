// Where a still-runnable task re-enters its priority queue.
//
// A running task here is NOT on its runqueue: `pick_next_task` pops it off and
// `put_prev_task` pushes it back. That makes the push POSITION a real policy
// decision, and pushing to the tail unconditionally silently broke SCHED_FIFO:
// a FIFO task involuntarily preempted by anything at all — a wake at a higher
// priority, a tick on another class — went behind its equal-priority peers and
// came back only after they had each run. FIFO's one guarantee is that a task
// runs until it blocks or yields, and that it resumes ahead of peers it never
// yielded to.
//
// Upstream expresses this as a flag on the enqueue rather than a property of
// the task, because the same task requeues to different ends depending on WHY:
// a fresh wakeup joins at the tail (it is a newcomer at that level), a
// preempted task rejoins at the head (it never gave up its turn), and a task
// that exhausted its round-robin quantum or called `sched_yield` goes to the
// tail (it did give up its turn). Ungated so all three cases are tested.

/// End of the priority queue a task is placed at.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RequeuePos {
    /// Front — resumes before equal-priority peers.
    Head,
    /// Back — yields its turn to equal-priority peers.
    Tail,
}

/// Position for a task re-entering the queue from `put_prev_task`, i.e. one
/// that was running and is still runnable.
///
/// `gave_up_turn` is the task's pending "requeue to the tail" request: set by
/// the tick when a `SCHED_RR` quantum runs out, and by `sched_yield`. Without
/// it the task was preempted against its will and keeps its place.
///
/// Only the real-time policies distinguish the two ends. The fair class is
/// ordered by virtual runtime, not by queue position, so its answer is
/// unused — the caller does not consult this for a fair task.
/// # C: O(1)
pub fn put_prev_pos(gave_up_turn: bool) -> RequeuePos {
    if gave_up_turn { RequeuePos::Tail } else { RequeuePos::Head }
}

/// Position for a task entering the queue from a WAKEUP rather than a
/// preemption. Always the tail: a task that just became runnable has not been
/// waiting at that priority level and must not jump the queue.
/// # C: O(1)
pub const fn wake_pos() -> RequeuePos { RequeuePos::Tail }

/// Whether the periodic tick should mark a task for a tail requeue.
///
/// Only `SCHED_RR` ever does: it is the sole policy with a quantum, and the
/// mark is what turns quantum exhaustion into an actual rotation. `SCHED_FIFO`
/// has no quantum, so it is never marked and never rotates — which is the
/// whole difference between the two policies.
///
/// A task alone at its priority is not marked: rotating it against an empty
/// peer set is pure work, and it would still be picked next.
/// # C: O(1)
pub fn tick_gives_up_turn(policy: u32, slice_left: u32, has_peer: bool) -> bool {
    policy == super::SCHED_RR && slice_left <= 1 && has_peer
}

#[cfg(test)]
mod tests;
