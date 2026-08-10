// The submission-polling thread's LOOP, with no thread behind it.
//
// [`super::sweep`] says what one pass decides; this says what the thread then
// DOES with that decision, and in what order. The two are different things and
// only the first of them used to be checkable: a loop that reaped after it
// submitted, that submitted to the ring next door, that woke nobody after
// making room, or that fell out while a ring still had work would decide every
// pass correctly and still be wrong.
//
// The order inside one pass is the reference's and each step of it is load
// bearing:
//
//   1. reap first, submit second — a pass that submitted first would poll for
//      transfers it had just handed to a backend, which cannot have finished,
//      while the ones that were already outstanding wait another pass;
//   2. wake the submitters parked for SQ room only after the entries are
//      drained, because room is what they are waiting for;
//   3. re-arm the idle window on any pass that did work, reaping included —
//      an idle window that only submission re-armed would close under a
//      polled ring whose transfers the thread is the only reaper of.
//
// The environment is a trait so the loop can be driven without a thread, a
// ring, an address space or a scheduler.

use super::{sweep, Pass, PollState, RingView, RingWork};

/// What the loop drives.
pub trait SqEnv {
    /// The rings still alive, pruning any that are gone. An empty answer ends
    /// the loop: there is nothing left to drain and nobody to report to.
    /// # C: O(N_rings)
    fn live_rings(&mut self) -> usize;
    /// What ring `i` looks like to this pass. # C: O(1)
    fn view(&mut self, i: usize) -> RingView;
    /// Somebody asked the thread to exit. # C: O(1)
    fn stop(&self) -> bool;
    /// Somebody asked the thread to stand down. # C: O(1)
    fn park_requested(&self) -> bool;
    /// # C: O(1)
    fn now_ns(&mut self) -> u64;
    /// Stand down until every park request is released. # C: O(N_parks)
    fn do_park(&mut self);
    /// Drive ring `i`'s backends and post what they finished. # C: O(N_queued)
    fn reap(&mut self, i: usize);
    /// Drain `n` entries from ring `i`. # C: O(n)
    fn submit(&mut self, i: usize, n: u32);
    /// Rouse whoever is blocked waiting for ring `i` to have SQ room.
    /// # C: O(N_waiters)
    fn wake_sq_waiters(&mut self, i: usize);
    /// Publish the doorbells, re-read the tails and sleep if still empty.
    /// # C: O(N_rings)
    fn idle(&mut self, views: &[RingView]);
    /// Give up the processor without leaving the loop. # C: O(1)
    fn spin(&mut self);
}

/// The poll thread's loop. Returns when the thread should exit — a stop
/// request, or the last ring going away.
/// # C: unbounded — runs for the rings' lives
/// # Sleeps: whenever every ring it serves is idle
pub fn poll_loop<E: SqEnv>(env: &mut E, idle_ns: u64) {
    let mut st = PollState::new(idle_ns);
    let mut views: alloc::vec::Vec<RingView> = alloc::vec::Vec::new();
    loop {
        let n = env.live_rings();
        if n == 0 { return; }
        views.clear();
        if views.try_reserve(n).is_err() { return; }
        for i in 0..n { let v = env.view(i); views.push(v); }

        let now = env.now_ns();
        match sweep(&st, &views, env.stop(), env.park_requested(), now) {
            Pass::Stop => return,
            Pass::Park => env.do_park(),
            Pass::Take(work) => { run_pass(env, &work); let now = env.now_ns(); st.touch(now); }
            Pass::Idle => { env.idle(&views); let now = env.now_ns(); st.touch(now); }
            Pass::Spin => env.spin(),
        }
    }
}

/// One pass's work, ring by ring, reap before submit. # C: O(N_rings)
fn run_pass<E: SqEnv>(env: &mut E, work: &[RingWork]) {
    for (i, w) in work.iter().enumerate() {
        if w.reap { env.reap(i); }
        if w.submit == 0 { continue; }
        env.submit(i, w.submit);
        // Room was made and completions may have been posted.
        env.wake_sq_waiters(i);
    }
}

#[cfg(test)]
#[path = "thread_tests.rs"]
mod tests;
