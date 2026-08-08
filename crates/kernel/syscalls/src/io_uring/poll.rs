// Armed polls, and the retry that keeps a worker out of a wait it does not
// need to be in.
//
// Two things arm a poll. `IORING_OP_POLL_ADD` is a poll and nothing else. And
// any operation that reported EAGAIN against a description that can be polled
// did not fail — it said "not yet" — so instead of reporting that to the
// submitter, the request goes back to waiting on the readiness it needs and is
// re-issued when it arrives. That second use is what `IORING_FEAT_FAST_POLL`
// promises, and it is why a ring full of idle sockets does not consume a
// worker thread each.

use alloc::sync::{Arc, Weak};

use core::sync::atomic::{AtomicU32, Ordering};

use syscall::errno::Errno;

use crate::io_uring_abi::poll::*;

use super::defer::Armed;
use super::iowq::run;
use super::req::IoReq;

/// Subscription ids for armed polls. The two other subscribers on a
/// description key themselves by epoll instance id and by
/// `0x8000_0000 | tid`; these sit above both so no unsubscribe can remove
/// somebody else's registration.
static NEXT_ID: AtomicU32 = AtomicU32::new(1);

/// # C: O(1)
fn next_id() -> u32 { 0xC000_0000 | (NEXT_ID.fetch_add(1, Ordering::Relaxed) & 0x3FFF_FFFF) }

/// The readiness callback one armed request is registered with. It holds the
/// request weakly: a description outliving the ring must not keep a finished
/// request alive.
pub struct PollWaker {
    req: Weak<IoReq>,
    pub id: u32,
}

impl vfs::EpollNotify for PollWaker {
    /// Readiness arrived: hand the request to a worker, which re-reads the
    /// description rather than trusting the wake to have told the truth.
    /// # C: O(1)
    fn notify(&self) {
        let Some(req) = self.req.upgrade() else { return };
        if req.is_done() { return; }
        super::iowq::WQ.queue(req);
    }
}

/// The description an entry polls: the registered file it names, or the
/// descriptor it names. # C: O(1)
fn file_of(req: &Arc<IoReq>) -> Option<Arc<vfs::File>> {
    use crate::io_uring_abi::ops::IOSQE_FIXED_FILE;
    if req.sqe.flags & IOSQE_FIXED_FILE != 0 {
        let g = req.ring.reg.lock();
        let files = g.files.as_ref()?;
        return files.get(req.sqe.fd as usize)?.file.clone();
    }
    let cur = sched::live::current()?;
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let fdt = unsafe { cur.fd_table_ref() }?.clone();
    fdt.get(req.sqe.fd).ok()
}

/// Decode `IORING_OP_POLL_ADD` and resolve its description, in the submitting
/// task. # C: O(1)
pub fn prepare(req: &Arc<IoReq>) -> Result<(), Errno> {
    let p = prep_poll_add(&req.sqe)?;
    let file = file_of(req).ok_or(Errno::Ebadf)?;
    let mut g = req.inner.lock();
    g.poll_events = p.events;
    g.poll_multi = p.multishot;
    g.poll_subs = file.poll_subscribers();
    g.poll_file = Some(file);
    Ok(())
}

/// Register the request on its description and report anything already ready.
/// # C: O(N_subs)
pub fn arm(req: &Arc<IoReq>) -> Armed {
    let (subs, events) = { let g = req.inner.lock(); (g.poll_subs.clone(), g.poll_events) };
    let Some(subs) = subs else { return Armed::Failed(Errno::Einval) };
    let waker = Arc::new(PollWaker { req: Arc::downgrade(req), id: next_id() });
    let weak: Weak<dyn vfs::EpollNotify> = Arc::downgrade(&(Arc::clone(&waker) as Arc<dyn vfs::EpollNotify>));
    subs.subscribe_mask(waker.id, weak, events);
    req.inner.lock().poll_waker = Some(waker);
    req.ring.track(req);
    // Readiness that arrived before the registration would otherwise never be
    // reported: nothing is going to change again to wake us.
    service(req);
    Armed::Waiting
}

/// Drop the registration a request holds on its description. # C: O(N_subs)
pub fn disarm(req: &Arc<IoReq>) {
    let (subs, waker) = {
        let mut g = req.inner.lock();
        g.poll_events = 0;
        (g.poll_subs.take(), g.poll_waker.take())
    };
    if let (Some(subs), Some(w)) = (subs, waker) { subs.unsubscribe(w.id); }
}

/// The readiness the description reports now. # C: O(1)
fn ready_now(req: &Arc<IoReq>) -> u32 {
    let f = req.inner.lock().poll_file.clone();
    f.map(|f| f.poll()).unwrap_or(POLL_NVAL)
}

/// An armed poll was woken. Report the readiness it asked about; a repeating
/// poll stays armed unless the description has hung up or errored, which it
/// would go on reporting forever. # C: O(1)
pub fn service(req: &Arc<IoReq>) {
    let (events, multi, retry) = {
        let g = req.inner.lock();
        (g.poll_events, g.poll_multi, g.poll_retry)
    };
    if retry { return reissue(req); }
    if events == 0 { return; }
    let Some(hit) = poll_hit(ready_now(req), events) else { return };
    if !req.claim() { return; }
    if poll_rearms(multi, hit) {
        run::post_more(req, hit as i64, 0);
        req.rearm();
        return;
    }
    disarm(req);
    run::complete(req, hit as i64, 0);
}

/// A punted operation whose description became ready: run it again.
/// # C: one operation
fn reissue(req: &Arc<IoReq>) {
    if !req.claim() { return; }
    disarm(req);
    { let mut g = req.inner.lock(); g.poll_retry = false; }
    req.rearm();
    super::iowq::WQ.queue(Arc::clone(req));
}

/// An operation reported EAGAIN. If its description can be polled, arm it
/// against the readiness it needs and report that the request is waiting
/// rather than that it failed. Returns whether it was re-armed.
/// # C: O(N_subs)
pub fn retry(req: &Arc<IoReq>) -> bool {
    use crate::io_uring_abi::ops::*;
    // A retry that has already been retried once is left to report EAGAIN:
    // a description that keeps saying "ready" and then "not yet" would
    // otherwise re-arm forever without the submitter ever hearing about it.
    if req.inner.lock().poll_retry { return false; }
    let Some(file) = file_of(req) else { return false };
    let Some(subs) = file.poll_subscribers() else { return false };
    let reads = matches!(req.opcode(),
        IORING_OP_READ | IORING_OP_READV | IORING_OP_READ_FIXED | IORING_OP_RECV
        | IORING_OP_RECVMSG | IORING_OP_ACCEPT);
    let waker = Arc::new(PollWaker { req: Arc::downgrade(req), id: next_id() });
    let weak: Weak<dyn vfs::EpollNotify> = Arc::downgrade(&(Arc::clone(&waker) as Arc<dyn vfs::EpollNotify>));
    let mask = retry_mask(reads);
    subs.subscribe_mask(waker.id, weak, mask);
    {
        let mut g = req.inner.lock();
        g.poll_events = mask;
        g.poll_retry = true;
        g.poll_subs = Some(subs);
        g.poll_file = Some(file);
        g.poll_waker = Some(waker);
    }
    req.ring.track(req);
    req.rearm();
    true
}

/// Cancel or re-arm an armed `IORING_OP_POLL_ADD` by `user_data`.
/// # C: O(N_inflight)
pub fn update(ring: &Arc<super::ctx::IoUringInode>, u: &PollUpdate) -> Result<(), Errno> {
    use crate::io_uring_abi::ops::IORING_OP_POLL_ADD;
    let Some(req) = ring.inflight_reqs().into_iter()
        .find(|r| r.opcode() == IORING_OP_POLL_ADD && r.user_data() == u.target)
    else { return Err(Errno::Enoent) };
    if req.state() != super::req::st::ARMED { return Err(Errno::Ealready); }
    if u.is_removal() {
        if !req.claim() { return Err(Errno::Ealready); }
        disarm(&req);
        run::complete(&req, -(Errno::Ecanceled.as_i32() as i64), 0);
        return Ok(());
    }
    if !req.claim() { return Err(Errno::Ealready); }
    disarm(&req);
    {
        let mut g = req.inner.lock();
        if let Some(e) = u.events { g.poll_events = e; }
        g.poll_multi = u.multishot;
    }
    if let Some(d) = u.user_data { req.set_user_data(d); }
    req.rearm();
    if let Some(file) = file_of(&req) {
        let mut g = req.inner.lock();
        g.poll_subs = file.poll_subscribers();
        g.poll_file = Some(file);
    }
    match arm(&req) { Armed::Waiting => Ok(()), _ => Err(Errno::Ecanceled) }
}
