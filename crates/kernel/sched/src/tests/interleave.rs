// Deterministic interleaving for hosted tests.
//
// A race between two kernel paths is only testable if the test can PIN the
// order of the two paths' internal steps. Wall-clock sleeps and
// `thread::yield_now` cannot: they make one ordering likely, not certain, so a
// test built on them passes on the ordering it happened to get and says
// nothing about the other one. Every concurrent test in this crate before this
// module was of that shape.
//
// The facility here is a rendezvous over NAMED checkpoints. Production code
// carries `interleave::point("name")` calls at the seams a race can open at;
// those calls are `#[cfg(test)]` so no kernel build contains them and no
// running kernel pays for them. A test declares a SCHEDULE — an ordered list of
// `(actor, checkpoint)` pairs — and each participating thread declares its
// actor label. A thread reaching a checkpoint blocks until the schedule's
// cursor names exactly that (actor, checkpoint), then advances the cursor and
// releases whoever is next. Checkpoints the schedule does not mention are free.
//
// The result is one deterministic, repeatable execution per declared order, so
// the mirror image of a race is a second schedule rather than a second run of
// the same test hoping for different luck.
//
// Not loom: loom explores interleavings of code written against `loom`'s own
// atomics and locks. Nothing in `sched` is, and shadowing `Task`'s atomics,
// the registry spinlocks and the zombie list to make it so is a larger and
// less faithful change than pinning the two orders we can name. `loom` stays
// where it already is (`net`, `network-namespace`), on data structures written
// for it.

extern crate std;

use alloc::vec::Vec;
use std::string::String;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::time::Duration;

/// One declared step: which actor must reach which checkpoint, and when.
pub(crate) type Step = (&'static str, &'static str);

/// A schedule that never completes is a hung test, not a slow one. The wait is
/// a failsafe, never the ordering mechanism — a passing run never reaches it.
const STALL: Duration = Duration::from_secs(10);

struct State {
    steps: Vec<Step>,
    cursor: usize,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);
static PROGRESS: Condvar = Condvar::new();

/// Only one schedule at a time: the checkpoints live in process-global
/// production code, so two concurrent schedules would consume each other's
/// steps.
fn schedule_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

std::thread_local! {
    static ACTOR: std::cell::Cell<Option<&'static str>> = const { std::cell::Cell::new(None) };
}

/// Bind the calling thread to an actor label. A thread with no label ignores
/// every checkpoint, so unrelated test threads and the harness's own thread do
/// not consume schedule steps.
pub(crate) fn actor(label: &'static str) {
    ACTOR.with(|a| a.set(Some(label)));
}

/// Install `steps` and hold the schedule until the guard drops.
pub(crate) fn schedule(steps: &[Step]) -> ScheduleGuard {
    let lock = schedule_lock();
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    *state = Some(State { steps: steps.to_vec(), cursor: 0 });
    drop(state);
    ScheduleGuard { _lock: lock }
}

pub(crate) struct ScheduleGuard {
    _lock: MutexGuard<'static, ()>,
}

impl ScheduleGuard {
    /// Steps consumed so far. A schedule that did not run to its end means the
    /// test never exercised the ordering it declared, which is exactly the
    /// silent pass this module exists to prevent — assert on it.
    pub(crate) fn reached(&self) -> usize {
        let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.as_ref().map_or(0, |s| s.cursor)
    }

    /// Total declared steps.
    pub(crate) fn declared(&self) -> usize {
        let state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        state.as_ref().map_or(0, |s| s.steps.len())
    }

    /// Every declared step was reached, in the declared order.
    pub(crate) fn assert_complete(&self) {
        let (reached, declared) = (self.reached(), self.declared());
        assert_eq!(reached, declared,
            "schedule stopped after {reached} of {declared} steps: the declared interleaving never ran");
    }
}

impl Drop for ScheduleGuard {
    fn drop(&mut self) {
        let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        *state = None;
        drop(state);
        // Release anything still parked so a failing test unwinds instead of
        // hanging its worker threads.
        PROGRESS.notify_all();
    }
}

/// A checkpoint in production code. No schedule, no actor label, or a
/// checkpoint this schedule does not name: returns immediately.
///
/// Reaching a checkpoint ENDS the actor's turn, and its next turn only starts
/// when the schedule names it again. So an actor runs exclusively between two
/// of its OWN consecutive checkpoints: every other actor is parked at a
/// checkpoint of its own for that whole span. Advancing the cursor without also
/// parking the arriving actor is not enough — an actor released at a seam then
/// races everyone through the code after it, which is how the first version of
/// this module let a publication-after-wake defect pass.
///
/// An actor with no checkpoint left ahead of the cursor runs free to
/// completion; otherwise it would park after its last step and never finish.
pub(crate) fn point(name: &'static str) {
    let Some(label) = ACTOR.with(|a| a.get()) else { return };
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    // Wait for this exact arrival to be the schedule's next step.
    loop {
        let Some(inner) = state.as_ref() else { return };
        if inner.cursor >= inner.steps.len() { return; }
        if inner.steps[inner.cursor] == (label, name) { break; }
        if !inner.steps[inner.cursor..].iter().any(|s| *s == (label, name)) { return; }
        state = park(state, label, name);
    }
    {
        let inner = state.as_mut().expect("checked above");
        inner.cursor += 1;
    }
    drop(state);
    PROGRESS.notify_all();
    // Wait for this actor's next turn.
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        let Some(inner) = state.as_ref() else { return };
        if inner.cursor >= inner.steps.len() { return; }
        if !inner.steps[inner.cursor..].iter().any(|s| s.0 == label) { return; }
        if inner.steps[inner.cursor].0 == label { return; }
        state = park(state, label, name);
    }
}

fn park<'a>(state: MutexGuard<'a, Option<State>>, label: &str, name: &str)
    -> MutexGuard<'a, Option<State>>
{
    let expected = state.as_ref().map(|s| s.steps.get(s.cursor).copied());
    let (guard, timeout) = PROGRESS.wait_timeout(state, STALL)
        .unwrap_or_else(|e| e.into_inner());
    if timeout.timed_out() {
        let detail: String = std::format!(
            "interleave stalled {STALL:?} at ({label}, {name}); schedule expects {expected:?}");
        panic!("{detail}");
    }
    guard
}

/// Spawn a labelled actor thread.
pub(crate) fn spawn<T, F>(label: &'static str, body: F) -> std::thread::JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    std::thread::spawn(move || { actor(label); body() })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property every test below rests on: a schedule pins the order of two
    /// threads' steps, and the MIRROR schedule pins the opposite order, with no
    /// sleep and no dependence on which thread got a CPU first.
    #[test]
    fn a_schedule_pins_both_orders_of_the_same_two_steps() {
        let orders = [
            [("a", "go"), ("a", "done"), ("b", "go"), ("b", "done")],
            [("b", "go"), ("b", "done"), ("a", "go"), ("a", "done")],
        ];
        for order in orders {
            let guard = schedule(&order);
            let seen: std::sync::Arc<Mutex<Vec<&'static str>>> =
                std::sync::Arc::new(Mutex::new(Vec::new()));
            let body = |tag: &'static str, sink: std::sync::Arc<Mutex<Vec<&'static str>>>| {
                move || { point("go"); sink.lock().unwrap().push(tag); point("done"); }
            };
            let a = spawn("a", body("a", std::sync::Arc::clone(&seen)));
            let b = spawn("b", body("b", std::sync::Arc::clone(&seen)));
            a.join().unwrap();
            b.join().unwrap();
            guard.assert_complete();
            assert_eq!(seen.lock().unwrap()[0], order[0].0,
                "the schedule's first actor must run its whole span first");
        }
    }

    /// A checkpoint the schedule does not name must not block: production code
    /// carries checkpoints for every seam, and one test names a few of them.
    #[test]
    fn an_unnamed_checkpoint_is_free() {
        let guard = schedule(&[("a", "named")]);
        let a = spawn("a", || { point("unnamed"); point("named"); point("unnamed"); });
        a.join().unwrap();
        guard.assert_complete();
    }

    /// An unlabelled thread — every test thread that is not an actor — must not
    /// consume steps.
    #[test]
    fn an_unlabelled_thread_ignores_checkpoints() {
        let guard = schedule(&[("a", "one")]);
        point("one");
        assert_eq!(guard.reached(), 0, "the harness thread has no actor label");
        spawn("a", || point("one")).join().unwrap();
        guard.assert_complete();
    }
}
