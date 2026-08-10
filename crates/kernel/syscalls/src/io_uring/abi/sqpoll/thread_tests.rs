// The poll thread's LOOP driven end to end, with no thread behind it.
//
// The fixture is a set of rings whose submission queues hold entries and whose
// backends park transfers, plus a recorded log of every step the loop took.
// The properties under test are ORDERINGS and TERMINATIONS — what the loop
// does and in what sequence — which is exactly what a per-decision test of
// `sweep` cannot see.

use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;

use super::super::{RingView, SQPOLL_CAP_ENTRIES};
use super::{poll_loop, SqEnv};

/// One ring the fake thread serves.
#[derive(Clone, Copy, Default)]
struct Ring {
    /// Entries published and not drained.
    sq: u32,
    /// Transfers this ring's backend owes a result for.
    queued: u32,
    /// Transfers the backend has finished and nobody has reaped.
    ready: u32,
    disabled: bool,
    /// Every drained entry queues a transfer on the backend — a polled ring.
    polled: bool,
}

/// A poll thread with the clock, the rings and the wake-ups all in hand.
struct Env {
    rings: Vec<Ring>,
    log: Vec<String>,
    now: u64,
    stop: bool,
    park: bool,
    /// Passes left before the fixture forces a stop, so a loop that fails to
    /// terminate fails the test rather than hanging it.
    budget: u32,
    /// Completions reaped over the whole run.
    posted: u32,
    /// The loop went to sleep this many times.
    slept: u32,
    /// Set once the thread has slept: the rings a real submitter would then
    /// publish to are published here instead, so a sleep that should not have
    /// happened is visible as work stranded behind it.
    sleep_strands: u32,
}

impl Env {
    fn new(rings: &[Ring]) -> Self {
        Self { rings: rings.to_vec(), log: Vec::new(), now: 0, stop: false, park: false,
               budget: 64, posted: 0, slept: 0, sleep_strands: 0 }
    }
    fn spent(&mut self) -> bool {
        if self.budget == 0 { self.stop = true; return true; }
        self.budget -= 1;
        false
    }
    fn logged(&self, s: &str) -> bool { self.log.iter().any(|e| e == s) }
    fn count(&self, s: &str) -> usize { self.log.iter().filter(|e| *e == s).count() }
    /// Index of the first log entry equal to `s`. # C: O(N_log)
    fn at(&self, s: &str) -> Option<usize> { self.log.iter().position(|e| e == s) }
}

impl SqEnv for Env {
    fn live_rings(&mut self) -> usize {
        if self.spent() { return self.rings.len(); }
        self.rings.len()
    }
    fn view(&mut self, i: usize) -> RingView {
        let r = self.rings[i];
        RingView { sq_ready: r.sq, disabled: r.disabled, iopoll_outstanding: r.queued > 0 }
    }
    fn stop(&self) -> bool { self.stop }
    fn park_requested(&self) -> bool { self.park }
    fn now_ns(&mut self) -> u64 { self.now += 1; self.now }
    fn do_park(&mut self) { self.log.push("park".to_string()); self.park = false; }
    fn reap(&mut self, i: usize) {
        self.log.push(format!("reap{i}"));
        let r = &mut self.rings[i];
        self.posted += r.ready;
        r.queued -= r.ready;
        r.ready = 0;
    }
    fn submit(&mut self, i: usize, n: u32) {
        self.log.push(format!("submit{i}:{n}"));
        let r = &mut self.rings[i];
        r.sq -= n;
        // A polled ring's entries do not complete inside the submission that
        // issued them: they are handed to a backend and become outstanding.
        if r.polled { r.queued += n; r.ready += n; }
    }
    fn wake_sq_waiters(&mut self, i: usize) { self.log.push(format!("wake{i}")); }
    fn idle(&mut self, _views: &[RingView]) {
        self.log.push("idle".to_string());
        self.slept += 1;
        // Anything still owed when the thread sleeps is stranded: on a polled
        // ring nothing else will ever look for it.
        self.sleep_strands += self.rings.iter().map(|r| r.queued).sum::<u32>();
        self.stop = true;
    }
    fn spin(&mut self) { self.log.push("spin".to_string()); }
}

fn ring(sq: u32) -> Ring { Ring { sq, ..Default::default() } }
fn polled(sq: u32) -> Ring { Ring { sq, polled: true, ..Default::default() } }

// --- termination --------------------------------------------------------

// No rings is the same as a stop: nothing to drain, nobody to report to.
#[test]
fn a_loop_returns_when_the_ring_set_is_empty() {
    let mut e = Env::new(&[]);
    poll_loop(&mut e, 0);
    assert!(e.log.is_empty(), "an empty set does no work at all");
}

// A stop request leaves the loop without doing the pass it was about to do.
#[test]
fn a_stop_request_ends_the_loop_before_any_work() {
    let mut e = Env::new(&[ring(4)]);
    e.stop = true;
    poll_loop(&mut e, 0);
    assert!(e.log.is_empty(), "a stopped thread submits nothing");
}

// --- the ordering inside one pass ---------------------------------------

// Reap BEFORE submit, on the same ring, in the same pass. A pass that
// submitted first would poll for transfers it had just queued — which cannot
// have finished — and leave the ones already outstanding for another pass.
#[test]
fn a_pass_reaps_before_it_submits() {
    let mut e = Env::new(&[Ring { sq: 2, queued: 1, ready: 1, polled: true, ..Default::default() }]);
    e.budget = 1;
    poll_loop(&mut e, 0);
    let reap = e.at("reap0").expect("the outstanding transfer was reaped");
    let submit = e.at("submit0:2").expect("the published entries were drained");
    assert!(reap < submit, "reap precedes submit in one pass: {:?}", e.log);
}

// Room is made by the drain, so the submitters waiting for it are woken
// after it and not before.
#[test]
fn a_pass_wakes_sq_waiters_after_the_drain() {
    let mut e = Env::new(&[ring(3)]);
    e.budget = 1;
    poll_loop(&mut e, 0);
    let submit = e.at("submit0:3").expect("drained");
    let wake = e.at("wake0").expect("woken");
    assert!(submit < wake, "the wake follows the drain: {:?}", e.log);
}

// Nothing drained means nobody to wake: a ring that only had a transfer to
// reap does not pretend it made room.
#[test]
fn a_reap_only_pass_wakes_nobody() {
    let mut e = Env::new(&[Ring { queued: 1, ready: 1, polled: true, ..Default::default() }]);
    e.budget = 1;
    poll_loop(&mut e, 0);
    assert!(e.logged("reap0"), "the transfer was reaped: {:?}", e.log);
    assert!(!e.logged("wake0"), "no room was made, so nobody is woken: {:?}", e.log);
}

// --- several rings ------------------------------------------------------

// Each ring's work goes to THAT ring. A thread serving several that submitted
// one ring's entries against another would be wrong here and nowhere else.
#[test]
fn a_pass_submits_each_ring_its_own_entries() {
    let mut e = Env::new(&[ring(2), ring(3), ring(1)]);
    e.budget = 1;
    poll_loop(&mut e, 0);
    assert!(e.logged("submit0:2") && e.logged("submit1:3") && e.logged("submit2:1"),
            "every ring drained its own count: {:?}", e.log);
}

// A ring with a full queue takes a bounded share, so its neighbours are not
// held behind it.
#[test]
fn a_busy_ring_cannot_starve_its_neighbour() {
    let mut e = Env::new(&[ring(1000), ring(1)]);
    e.budget = 1;
    poll_loop(&mut e, 0);
    assert!(e.logged(&format!("submit0:{SQPOLL_CAP_ENTRIES}")), "capped: {:?}", e.log);
    assert!(e.logged("submit1:1"), "the neighbour still ran in the same pass: {:?}", e.log);
}

// A disabled ring's ENTRIES are not the thread's to consume — but a transfer
// it published before it was disabled is still outstanding, and still has
// nobody else to reap it.
#[test]
fn a_disabled_ring_is_not_drained_but_is_still_reaped() {
    let mut e = Env::new(&[Ring { sq: 4, queued: 1, ready: 1, disabled: true, polled: true,
                                  ..Default::default() }]);
    e.budget = 1;
    poll_loop(&mut e, 0);
    assert!(e.logged("reap0"), "outstanding work is reaped: {:?}", e.log);
    assert!(!e.log.iter().any(|s| s.starts_with("submit")), "nothing drained: {:?}", e.log);
}

// --- the polled ring, end to end ----------------------------------------

// The whole submit-then-poll chain on a ring whose submitter never enters the
// kernel: the thread drains the entries, the backend parks them, and the SAME
// thread is what finds the completions. Without the reap the transfers sit
// outstanding forever and the loop sleeps on top of them.
#[test]
fn a_polled_ring_completes_without_its_submitter_entering() {
    let mut e = Env::new(&[polled(3)]);
    poll_loop(&mut e, 0);
    assert_eq!(e.posted, 3, "every transfer was completed by the thread: {:?}", e.log);
    assert_eq!(e.sleep_strands, 0, "nothing was left outstanding across a sleep");
}

// The thread does not sleep while a polled ring owes results. Nothing would
// wake it: on a polled backend there is no interrupt, which is the whole point
// of the mode.
#[test]
fn the_thread_does_not_sleep_on_outstanding_polled_work() {
    let mut e = Env::new(&[Ring { queued: 2, ready: 0, polled: true, ..Default::default() }]);
    e.budget = 8;
    poll_loop(&mut e, 0);
    assert_eq!(e.slept, 0, "a ring owing results kept the thread awake: {:?}", e.log);
    assert!(e.count("reap0") > 1, "it kept polling for them: {:?}", e.log);
}

// With nothing published and nothing outstanding, the thread does sleep —
// otherwise the rule above would be indistinguishable from a thread that never
// sleeps at all.
#[test]
fn an_idle_ring_does_let_the_thread_sleep() {
    let mut e = Env::new(&[ring(0)]);
    poll_loop(&mut e, 0);
    assert_eq!(e.slept, 1, "an idle thread sleeps: {:?}", e.log);
}

// The idle window is re-armed by a REAP as well as by a drain. A window only
// submission re-armed would close under a polled ring whose transfers are the
// thread's alone to find.
#[test]
fn reaping_re_arms_the_idle_window() {
    let mut e = Env::new(&[Ring { queued: 1, ready: 0, polled: true, ..Default::default() }]);
    e.budget = 4;
    poll_loop(&mut e, 4);
    assert_eq!(e.slept, 0, "the window never closed: {:?}", e.log);
}

// --- parking ------------------------------------------------------------

// A park request is honoured before any of the pass's work, so the parker can
// touch state the thread also touches.
#[test]
fn a_park_request_pre_empts_the_pass() {
    let mut e = Env::new(&[ring(4)]);
    e.park = true;
    e.budget = 2;
    poll_loop(&mut e, 0);
    assert_eq!(e.at("park"), Some(0), "the park came first: {:?}", e.log);
    assert!(e.logged("submit0:4"), "and the work happened after it: {:?}", e.log);
}
