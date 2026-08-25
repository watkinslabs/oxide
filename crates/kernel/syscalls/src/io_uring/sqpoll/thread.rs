use super::*;
use super::super::iowq::owner::Borrow;

/// The live thread's side of [`crate::io_uring_abi::sqpoll::thread::SqEnv`].
///
/// The ring set is re-read per pass and cached here for that pass alone: the
/// driver indexes rings by position, and a set that changed underneath between
/// the sweep and the work would submit to the wrong one.
struct LiveEnv<'a> { sqd: &'a SqData, rings: Vec<Arc<IoUringInode>> }

impl<'a> crate::io_uring_abi::sqpoll::thread::SqEnv for LiveEnv<'a> {
    /// # C: O(N_rings)
    fn live_rings(&mut self) -> usize { self.rings = self.sqd.live(); self.rings.len() }
    /// # C: O(N_queued)
    fn view(&mut self, i: usize) -> RingView { view(&self.rings[i]) }
    /// # C: O(1)
    fn stop(&self) -> bool { self.sqd.stop.load(Ordering::Acquire) }
    /// # C: O(1)
    fn park_requested(&self) -> bool { self.sqd.park_pending.load(Ordering::Acquire) != 0 }
    /// # C: O(1)
    fn now_ns(&mut self) -> u64 { super::iowq::worker::now_ns() }
    /// # C: O(N_parks)
    fn do_park(&mut self) { do_park(self.sqd); }
    /// # C: O(N_queued)
    fn reap(&mut self, i: usize) { super::iopoll::drive(&self.rings[i]); }
    /// # C: O(n)
    fn submit(&mut self, i: usize, n: u32) { super::submit::submit_sqes(&self.rings[i], n); }
    /// # C: O(N_waiters)
    fn wake_sq_waiters(&mut self, _i: usize) { self.sqd.sq_wait.wake_all(); }
    /// # C: O(N_rings)
    fn idle(&mut self, _views: &[RingView]) { idle(self.sqd, &self.rings); }
    /// # C: O(1)
    fn spin(&mut self) {
        // SAFETY: running poll thread in process context on its own CPU holding no lock; schedule re-enqueues this still-runnable task.
        unsafe { sched::live::schedule(); }
    }
}

/// The poll loop. Returns once the ring is gone or a stop was requested.
///
/// The loop is [`crate::io_uring_abi::sqpoll::thread::poll_loop`]; what is here
/// is the borrow it runs under and the live environment it drives.
/// # C: unbounded — runs for the ring's life
/// # Sleeps: whenever the rings it serves are idle
fn run(sqd: &SqData) {
    // Borrowed once and held: this thread has no address space, no descriptor
    // table and no credentials of its own, and every entry it runs belongs to
    // the task that created the ring.
    // SAFETY: the running task is a freshly spawned kernel thread in process context on its own CPU with no address space, no descriptor table and no lock held.
    let _borrow = unsafe { Borrow::install(&sqd.owner) };
    crate::io_uring_abi::sqpoll::thread::poll_loop(
        &mut LiveEnv { sqd, rings: Vec::new() }, sqd.idle_ns);
}

/// The thread. `arg` is the `Arc<SqData>` its creator leaked for exactly this
/// thread and nobody else.
/// # C: unbounded
extern "C" fn sq_thread(arg: usize) -> ! {
    // SAFETY: `arg` is the one `Arc::into_raw(Arc<SqData>)` this thread's creator produced for it and handed to no other thread; reclaiming it here balances that leak exactly once.
    let sqd: Arc<SqData> = unsafe { Arc::from_raw(arg as *const SqData) };
    run(&sqd);
    sqd.exited.store(true, Ordering::Release);
    // A submitter parked on an empty ring must not wait on a thread that is
    // gone: leave every doorbell up so its next submission enters the kernel.
    for ring in sqd.live() { update_sq_flags(&ring, arm_need_wakeup); }
    sqd.sq_wait.wake_all();
    sqd.park_wait.wake_all();
    drop(sqd);
    // SAFETY: running kernel thread on its own CPU, holding no lock, owning no in-flight I/O — every borrow was released by `run` returning.
    unsafe { sched::live::kthread_exit(0) }
}

