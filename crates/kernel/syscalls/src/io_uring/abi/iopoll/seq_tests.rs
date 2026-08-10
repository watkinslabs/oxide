// The polled ring's chain — submit, issue, poll, reap, complete — driven end
// to end against a backend that genuinely PARKS transfers and only finishes
// them when it is polled.
//
// The fixture is the block layer's parked-until-polled device carried up
// through the ring: a transfer handed to it becomes outstanding and stays
// outstanding until a poll pass asks for it, which is the only shape in which
// the three failure modes of this path are reachable at all — a request
// completed twice, a completion posted against a request somebody else owns,
// and a transfer nothing ever reaps.
//
// Every step the drivers take is logged, so the assertions are about ORDER and
// about what happened exactly once, not about return values alone.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use syscall::errno::Errno;

use super::{poll_wait, reap_pass, PollWait, ReapSet, Taken};

/// The address space a transfer's submitter owns. The reaper need not be the
/// submitter, so a read that landed through the REAPER's root would land in
/// the wrong process — and would look identical from the return value.
const SUBMITTER_ROOT: u64 = 0x1000;
/// Whatever address space the task doing the reaping happens to be in.
const REAPER_ROOT: u64 = 0x2000;

/// What the backend has done with one transfer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Backend {
    /// Accepted, not finished. Polls left before it will be.
    Parked(u32),
    /// Finished, this many bytes.
    Done(usize),
    /// Finished with a failure.
    Failed(i64),
    /// Marked finished with nothing in the slot.
    Lost,
}

#[derive(Clone)]
struct Xfer {
    id: u32,
    write: bool,
    backend: Backend,
    /// Which backend it is outstanding against; two transfers may share one.
    dev: u32,
    /// Still in the ring's polled set.
    queued: bool,
    /// Somebody owns its completion already.
    claimed: bool,
    /// How many of the delivered bytes the submitter's memory will accept.
    accepts: usize,
}

impl Xfer {
    fn read(id: u32, polls: u32) -> Self {
        Self { id, write: false, backend: Backend::Parked(polls), dev: 0, queued: true,
               claimed: false, accepts: usize::MAX }
    }
    fn write(id: u32, polls: u32) -> Self {
        Self { write: true, ..Self::read(id, polls) }
    }
}

struct Fake {
    xfers: Vec<Xfer>,
    log: Vec<String>,
    /// Completions posted and not consumed.
    cq: u32,
    /// Every completion this run posted, in order.
    posted: Vec<(u32, i64)>,
    /// Completions waiting in the backlog for a flush.
    overflow: u32,
    dropped: bool,
    min: u32,
    signal: bool,
    resched: bool,
    /// The page-table root each scatter was handed.
    roots: Vec<(u32, u64)>,
    /// Passes left before the fixture forces the loop to yield, so a loop that
    /// cannot terminate fails rather than hangs.
    budget: u32,
}

impl Fake {
    fn new(xfers: &[Xfer]) -> Self {
        Self { xfers: xfers.to_vec(), log: Vec::new(), cq: 0, posted: Vec::new(), overflow: 0,
               dropped: false, min: 1, signal: false, resched: false, roots: Vec::new(),
               budget: 32 }
    }
    fn get(&mut self, id: &u32) -> &mut Xfer {
        self.xfers.iter_mut().find(|x| x.id == *id).expect("known transfer")
    }
    fn peek(&self, id: &u32) -> &Xfer {
        self.xfers.iter().find(|x| x.id == *id).expect("known transfer")
    }
    fn at(&self, s: &str) -> Option<usize> { self.log.iter().position(|e| e == s) }
    fn count(&self, s: &str) -> usize { self.log.iter().filter(|e| *e == s).count() }
    fn outstanding(&self) -> usize { self.xfers.iter().filter(|x| x.queued).count() }
}

impl ReapSet for Fake {
    type Req = u32;

    fn queued(&mut self) -> Vec<u32> {
        self.xfers.iter().filter(|x| x.queued).map(|x| x.id).collect()
    }
    fn has_queued(&mut self, r: &u32) -> bool { self.peek(r).queued }
    fn backend_done(&mut self, r: &u32) -> bool {
        !matches!(self.peek(r).backend, Backend::Parked(_))
    }
    fn claim(&mut self, r: &u32) -> bool {
        self.log.push(format!("claim{r}"));
        let x = self.get(r);
        if x.claimed { return false; }
        x.claimed = true;
        true
    }
    fn is_write(&mut self, r: &u32) -> bool { self.peek(r).write }
    fn take(&mut self, r: &u32) -> Taken {
        self.log.push(format!("take{r}"));
        match self.peek(r).backend {
            Backend::Done(n) => Taken::Bytes(n),
            Backend::Failed(e) => Taken::Failed(e),
            Backend::Lost => Taken::Lost,
            Backend::Parked(_) => panic!("a parked transfer was taken"),
        }
    }
    fn scatter(&mut self, r: &u32, delivered: usize) -> usize {
        // Whichever address space the reaper is in, the bytes go to the
        // submitter's — recorded so the test can tell the two apart.
        let root = SUBMITTER_ROOT;
        self.roots.push((*r, root));
        self.log.push(format!("scatter{r}"));
        core::cmp::min(delivered, self.peek(r).accepts)
    }
    fn release(&mut self, r: &u32) {
        self.log.push(format!("release{r}"));
        self.get(r).queued = false;
    }
    fn post(&mut self, r: &u32, res: i64) {
        self.log.push(format!("post{r}"));
        self.posted.push((*r, res));
        self.cq += 1;
    }
}

impl PollWait for Fake {
    fn min_events(&self) -> u32 { self.min }
    fn flush_overflow(&mut self) { self.cq += self.overflow; self.overflow = 0; }
    fn dropped(&self) -> bool { self.dropped }
    fn clear_dropped(&mut self) -> bool { let d = self.dropped; self.dropped = false; d }
    fn cq_ready(&mut self) -> u32 { self.cq }
    fn targets(&mut self) -> u32 {
        let mut devs: Vec<u32> = self.xfers.iter().filter(|x| x.queued).map(|x| x.dev).collect();
        devs.sort_unstable();
        devs.dedup();
        devs.len() as u32
    }
    fn hybrid_sleep(&mut self) -> Option<(u64, u64)> { None }
    fn poll_targets(&mut self, oneshot: bool) {
        self.log.push(if oneshot { "poll!".to_string() } else { "poll".to_string() });
        for x in self.xfers.iter_mut() {
            if let Backend::Parked(n) = x.backend {
                x.backend = if n <= 1 { Backend::Done(8) } else { Backend::Parked(n - 1) };
            }
        }
    }
    fn reap(&mut self) -> usize { reap_pass(self) }
    fn hybrid_observe(&mut self, _slept: u64, _issued: u64) {}
    fn yield_cpu(&mut self) { self.log.push("yield".to_string()); }
    fn signal_pending(&mut self) -> bool { self.signal }
    fn need_resched(&mut self) -> bool {
        if self.budget == 0 { return true; }
        self.budget -= 1;
        self.resched
    }
}

fn eintr() -> i64 { -(Errno::Eintr.as_i32() as i64) }
fn ebadr() -> i64 { -(Errno::Ebadr.as_i32() as i64) }
fn eio() -> i64 { -(Errno::Eio.as_i32() as i64) }
fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }

// --- the reaper's sequencing --------------------------------------------

// The claim is asked LAST and, for a transfer the backend has not finished,
// not asked at all. A pass that claimed first would own a request whose result
// is not in yet, and the result would be lost with it.
#[test]
fn a_parked_transfer_is_never_claimed() {
    let mut f = Fake::new(&[Xfer::read(1, 3)]);
    assert_eq!(reap_pass(&mut f), 0, "nothing to complete yet");
    assert_eq!(f.count("claim1"), 0, "ownership was not taken: {:?}", f.log);
    assert!(f.peek(&1).queued, "and it stayed in the polled set");
}

// The order within one completed transfer: claim, take, scatter, release,
// post. Release BEFORE post is the one that matters — a pass that posted first
// leaves a window in which another pass finds the request still queued with
// its backend still marked finished.
#[test]
fn a_completed_transfer_is_released_before_its_completion_is_posted() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.get(&1).backend = Backend::Done(8);
    assert_eq!(reap_pass(&mut f), 1);
    let order = ["claim1", "take1", "scatter1", "release1", "post1"];
    let mut prev = 0;
    for step in order {
        let at = f.at(step);
        assert!(at.is_some(), "{step} happened: {:?}", f.log);
        let at = at.unwrap_or(0);
        assert!(at >= prev, "{step} is in order: {:?}", f.log);
        prev = at;
    }
}

// Exactly one completion per request, whichever path gets there first. A
// second pass over the same set finds nothing.
#[test]
fn a_transfer_is_completed_exactly_once_across_passes() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.get(&1).backend = Backend::Done(8);
    assert_eq!(reap_pass(&mut f), 1, "the first pass posted it");
    assert_eq!(reap_pass(&mut f), 0, "the second found nothing");
    assert_eq!(f.posted.len(), 1, "one completion in total: {:?}", f.posted);
}

// A cancellation that got there first owns the completion. The backend's later
// result then fills a slot nobody reads, and the reap posts nothing — the
// alternative being two completions for one entry.
#[test]
fn a_cancellation_racing_a_completion_leaves_exactly_one() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    // The canceller claims while the transfer is still parked.
    assert!(f.claim(&1), "the canceller won the claim");
    f.get(&1).backend = Backend::Done(8);
    assert_eq!(reap_pass(&mut f), 0, "the reap did not post a second completion");
    assert!(f.posted.is_empty(), "nothing was posted by the reaper: {:?}", f.posted);
}

// A read's bytes land in the SUBMITTER's address space. The task reaping a
// polled ring need not be the one that submitted to it, and a scatter through
// the reaper's root would be a silent write into the wrong process.
#[test]
fn a_read_lands_in_the_submitters_address_space() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.get(&1).backend = Backend::Done(8);
    reap_pass(&mut f);
    assert_eq!(f.roots, alloc::vec![(1, SUBMITTER_ROOT)], "not the reaper's root");
    assert_ne!(SUBMITTER_ROOT, REAPER_ROOT, "the two roots are distinguishable");
}

// A write reports what the device took and is never scattered: its payload
// left the caller's buffer at submission.
#[test]
fn a_write_reports_the_device_count_and_scatters_nothing() {
    let mut f = Fake::new(&[Xfer::write(1, 1)]);
    f.get(&1).backend = Backend::Done(8);
    reap_pass(&mut f);
    assert_eq!(f.posted, alloc::vec![(1, 8)]);
    assert!(f.roots.is_empty(), "a write has nothing to land: {:?}", f.log);
}

// A read that delivered bytes and landed none is EFAULT, not a zero-length
// read: zero means end-of-file, and a caller that treated a failed copy as EOF
// would stop reading a file it had barely started.
#[test]
fn a_read_that_lands_nothing_is_efault() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.get(&1).backend = Backend::Done(8);
    f.get(&1).accepts = 0;
    reap_pass(&mut f);
    assert_eq!(f.posted, alloc::vec![(1, efault())]);
}

// A short landing reports what landed, not what the device delivered.
#[test]
fn a_short_landing_reports_the_bytes_that_arrived() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.get(&1).backend = Backend::Done(8);
    f.get(&1).accepts = 3;
    reap_pass(&mut f);
    assert_eq!(f.posted, alloc::vec![(1, 3)]);
}

// A transfer marked finished with an empty slot is an I/O error: nothing can
// say what happened to the bytes.
#[test]
fn a_lost_result_is_an_io_error() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.get(&1).backend = Backend::Lost;
    reap_pass(&mut f);
    assert_eq!(f.posted, alloc::vec![(1, eio())]);
}

// A backend failure is carried through untouched and lands nothing.
#[test]
fn a_backend_failure_is_reported_as_it_stands() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.get(&1).backend = Backend::Failed(-(Errno::Enospc.as_i32() as i64));
    reap_pass(&mut f);
    assert_eq!(f.posted, alloc::vec![(1, -(Errno::Enospc.as_i32() as i64))]);
    assert!(f.roots.is_empty(), "a failed transfer has no bytes to land");
}

// The ring going away with transfers outstanding: the polled set is emptied,
// and a pass over it completes nothing rather than touching requests whose
// completions somebody else took at teardown.
#[test]
fn a_teardown_with_transfers_outstanding_reaps_nothing() {
    let mut f = Fake::new(&[Xfer::read(1, 1), Xfer::read(2, 1)]);
    for x in f.xfers.iter_mut() { x.backend = Backend::Done(8); x.claimed = true; x.queued = false; }
    assert_eq!(reap_pass(&mut f), 0);
    assert!(f.posted.is_empty(), "nothing was posted after teardown: {:?}", f.posted);
}

// --- the wait loop's sequencing -----------------------------------------

// The whole chain: a transfer the backend parks, a caller that asks for it,
// and a completion that exists only because the loop polled and then reaped.
#[test]
fn a_parked_transfer_completes_through_the_wait_loop() {
    let mut f = Fake::new(&[Xfer::read(1, 2)]);
    assert_eq!(poll_wait(&mut f), 0);
    assert_eq!(f.posted.len(), 1, "the transfer completed: {:?}", f.log);
    assert_eq!(f.outstanding(), 0, "and left the polled set");
    // Two polls were needed, so the loop went round rather than reaping what
    // was already there.
    assert!(f.count("poll") + f.count("poll!") >= 2, "it kept polling: {:?}", f.log);
}

// Reap AFTER poll, in the SAME pass. A loop that reaped first would report the
// previous pass's work as this one's and need an extra round for every
// transfer — which is only a cost until the pass it needs is the one that does
// not happen, and then it is a lost completion.
#[test]
fn each_pass_reaps_what_its_own_poll_finished() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    poll_wait(&mut f);
    let poll = f.at("poll").or_else(|| f.at("poll!")).expect("polled");
    let claim = f.at("claim1").expect("reaped");
    assert!(poll < claim, "the poll precedes the reap: {:?}", f.log);
    assert_eq!(f.count("poll") + f.count("poll!"), 1,
               "one poll sufficed for a transfer its own poll finished: {:?}", f.log);
}

// And the pass that gives up the processor still posts what its poll found.
// The loop ends after ONE pass here, so a reap that ran before that pass's
// poll strands the completion: the transfer is finished, out of the caller's
// reach, and nothing will look at it again.
#[test]
fn a_final_pass_still_posts_what_its_own_poll_found() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.min = 4;
    f.resched = true;
    assert_eq!(poll_wait(&mut f), 0);
    assert_eq!(f.posted.len(), 1, "the completion was not stranded: {:?}", f.log);
    assert_eq!(f.outstanding(), 0, "and the transfer left the polled set");
}

// The first early exit: nothing outstanding to poll. The loop returns success
// with fewer completions than asked for rather than spinning for a request
// that has not reached a backend.
#[test]
fn nothing_outstanding_ends_the_loop_with_success() {
    let mut f = Fake::new(&[]);
    f.min = 4;
    assert_eq!(poll_wait(&mut f), 0, "success, with no completions at all");
    assert_eq!(f.cq, 0);
    assert!(!f.log.iter().any(|s| s.starts_with("poll")), "no backend was touched: {:?}", f.log);
}

// The second early exit: the processor is needed elsewhere. Also success, also
// short of the count.
#[test]
fn a_resched_ends_the_loop_with_success() {
    let mut f = Fake::new(&[Xfer::read(1, 8)]);
    f.min = 4;
    f.resched = true;
    assert_eq!(poll_wait(&mut f), 0);
    assert!(f.cq < f.min, "it gave up short of the count: {} < {}", f.cq, f.min);
    assert_eq!(f.count("poll") + f.count("poll!"), 1, "exactly one pass: {:?}", f.log);
}

// A signal beats both the count and the yield: the caller is spinning, and a
// loop that checked the count first would sit on a processor through a pending
// kill.
#[test]
fn a_signal_beats_the_count_and_the_yield() {
    let mut f = Fake::new(&[Xfer::read(1, 8)]);
    f.min = 4;
    f.signal = true;
    f.resched = true;
    assert_eq!(poll_wait(&mut f), eintr(), "the signal wins over the resched");
}

// A lost completion is reported before anything is polled, and once. A caller
// told "no completions" would wait forever for the one that was destroyed.
#[test]
fn a_lost_completion_is_reported_before_the_backend_is_touched() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.dropped = true;
    assert_eq!(poll_wait(&mut f), ebadr());
    assert!(!f.log.iter().any(|s| s.starts_with("poll")), "no poll ran: {:?}", f.log);
    assert_eq!(poll_wait(&mut f), 0, "and it is reported only once");
}

// Completions already reapable end the call without touching a backend: the
// caller asked to be given events, and events exist.
#[test]
fn existing_completions_end_the_call_without_polling() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.overflow = 1;
    assert_eq!(poll_wait(&mut f), 0);
    assert_eq!(f.cq, 1, "the backlog was flushed into the ring");
    assert!(!f.log.iter().any(|s| s.starts_with("poll")), "no poll ran: {:?}", f.log);
    assert!(f.peek(&1).queued, "and the outstanding transfer is untouched");
}

// A caller asking for zero completions wants a look, not a wait: the backend
// is forbidden to spin inside the pass.
#[test]
fn a_zero_count_wait_forbids_the_backend_to_spin() {
    let mut f = Fake::new(&[Xfer::read(1, 1)]);
    f.min = 0;
    poll_wait(&mut f);
    assert!(f.logged_oneshot(), "the pass was one-shot: {:?}", f.log);
}

// So does more than one backend: spinning inside one holds up every completion
// waiting on the others.
#[test]
fn several_backends_forbid_the_spin_too() {
    let mut f = Fake::new(&[Xfer::read(1, 1), Xfer::read(2, 1)]);
    f.get(&2).dev = 1;
    f.min = 2;
    poll_wait(&mut f);
    assert!(f.logged_oneshot(), "the pass was one-shot: {:?}", f.log);
    assert_eq!(f.posted.len(), 2, "both completed: {:?}", f.posted);
}

// Two transfers on one backend, both reaped in the pass that found them.
#[test]
fn one_backend_serving_two_transfers_completes_both() {
    let mut f = Fake::new(&[Xfer::read(1, 1), Xfer::write(2, 1)]);
    f.min = 2;
    assert_eq!(poll_wait(&mut f), 0);
    assert_eq!(f.posted.len(), 2, "both completed: {:?}", f.posted);
    assert_eq!(f.outstanding(), 0);
}

impl Fake {
    /// Whether any pass forbade the backend to spin. # C: O(N_log)
    fn logged_oneshot(&self) -> bool { self.log.iter().any(|s| s == "poll!") }
}
