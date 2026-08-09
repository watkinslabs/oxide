// `IORING_SETUP_SQPOLL`: one kernel thread per ring that drains the SQ ring
// without the submitter entering the kernel at all.
//
// The thread is the ring's only submitter for its whole life. It borrows the
// creating task's address space, descriptor table and credentials once, at
// start, and keeps them: an entry naming a buffer address or a descriptor
// number means on this thread exactly what it meant to the task that published
// it, which is what lets a polled ring run entries that name ordinary
// descriptors rather than only registered ones.
//
// Everything that decides — the idle window, the pin-CPU ladder, the loop's
// transitions and the `IORING_SQ_NEED_WAKEUP` handshake — is in
// `crate::io_uring_abi::sqpoll`, which is NOT target-gated, so it is unit
// tested. This file is the machinery those decisions drive.
//
// Lifetime: the thread dies with the ring. Its handle on the ring is weak, so
// it never keeps a closed ring alive; the ring's last descriptor closing sets
// the stop request and wakes it, and it exits on its own thread rather than
// making `close(2)` wait for it.

use alloc::sync::{Arc, Weak};

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use syscall::errno::Errno;

use sync::{Spinlock, TaskList as SqLockClass};

use crate::io_uring_abi::layout::{RING_SQ_FLAGS, RING_SQ_HEAD, RING_SQ_TAIL};
use crate::io_uring_abi::sqpoll::{
    arm_need_wakeup, disarm_need_wakeup, sleeps_after_arm, sq_cpu, sq_full, sq_ready,
    sq_thread_idle_ns, step, Observed, PollState, Step,
};
use crate::io_uring_abi::uapi::{Params, IORING_SETUP_SQPOLL};

use super::ctx::{state, IoUringInode};
use super::iowq::owner::{Borrow, Owner};

/// One ring's poll thread and the state both sides of the handshake read.
///
/// Linux keeps this in `struct io_sq_data`, shared by every ring attached to
/// one thread. Nothing here shares a thread — `IORING_SETUP_ATTACH_WQ` is
/// refused — so it is one per ring, and `shared` is correspondingly always
/// false in the loop's `Observed`.
pub struct SqData {
    /// The ring this thread serves. Weak: a closed ring must not be held alive
    /// by the thread that was draining it.
    ring: Weak<IoUringInode>,
    /// The thread sleeps here; `io_uring_enter(IORING_ENTER_SQ_WAKEUP)` and
    /// every state change wake it.
    wait: sched::live::WaitList,
    /// Submitters blocked in `io_uring_enter(IORING_ENTER_SQ_WAIT)` waiting
    /// for the thread to make SQ room.
    sq_wait: sched::live::WaitList,
    /// Threads waiting for the poll thread to observe a park request.
    park_wait: sched::live::WaitList,
    /// The thread itself, once it exists.
    task: Spinlock<Option<Arc<sched::Task>>, SqLockClass>,
    /// Outstanding park requests. Nested, so two parkers cannot release each
    /// other's — the thread stays down until the last one lets it up.
    park_pending: AtomicU32,
    /// The thread has observed the park request and is standing down.
    parked: AtomicBool,
    stop: AtomicBool,
    /// The thread has left its loop.
    exited: AtomicBool,
    idle_ns: u64,
    /// What the thread borrows to run this ring's entries.
    owner: Arc<Owner>,
}

impl SqData {
    /// Rouse the thread. # C: O(1)
    pub fn wake(&self) { self.wait.wake_all(); }

    /// Has the thread left its loop? An `io_uring_enter` on a ring whose poll
    /// thread is gone reports `EOWNERDEAD` rather than pretending to submit.
    /// # C: O(1)
    pub fn dead(&self) -> bool { self.exited.load(Ordering::Acquire) }

    /// Ask the thread to exit and wake it. Does not wait: this runs from the
    /// ring's last `close(2)`, which must not block on another thread's loop.
    /// # C: O(1)
    pub fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.park_pending.store(0, Ordering::Release);
        self.park_wait.wake_all();
        self.wait.wake_all();
    }

    /// Linux `io_sq_thread_park`: stand the thread down and wait until it has
    /// actually stood down, so the caller may touch ring state the thread also
    /// touches.
    ///
    /// # SAFETY: process context on the caller's own CPU, holding no lock the
    /// poll thread takes, and the caller must not be the poll thread itself.
    /// # C: O(1) + the wait
    /// # Sleeps: until the thread parks
    pub unsafe fn park(&self) {
        self.park_pending.fetch_add(1, Ordering::AcqRel);
        self.wait.wake_all();
        while !self.parked.load(Ordering::Acquire) && !self.dead() {
            // SAFETY: per this fn's contract — process context, runqueue installed; the poll thread's park publication is this list's only waker and takes no lock the caller holds.
            let out = unsafe {
                sched::live::wait_event(
                    &self.park_wait, sched::task::WaitState::Killable, 0,
                    || 0, || self.parked.load(Ordering::Acquire) || self.dead(),
                )
            };
            if matches!(out, sched::task::WaitOutcome::Ready) { break; }
        }
    }

    /// Linux `io_sq_thread_unpark`: release one park request. # C: O(1)
    pub fn unpark(&self) {
        if self.park_pending.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                                          |n| if n == 0 { None } else { Some(n - 1) }).is_err() {
            return;
        }
        self.park_wait.wake_all();
        self.wait.wake_all();
    }

    /// Pin the thread to `mask`, or release it to every processor when `mask`
    /// is zero. # C: O(1)
    pub fn set_cpus_allowed(&self, mask: u64) {
        let t = self.task.lock().clone();
        let Some(t) = t else { return };
        t.cpus_allowed.store(if mask == 0 { u64::MAX } else { mask }, Ordering::Release);
    }
}

/// The `sq_flags` word, read and written under the ring lock like every other
/// header word. # C: O(1)
fn update_sq_flags(ring: &IoUringInode, f: impl FnOnce(u32) -> u32) {
    let r = ring.ring.lock();
    let cur = r.hdr_load(RING_SQ_FLAGS);
    r.hdr_store(RING_SQ_FLAGS, f(cur));
}

/// Entries userspace has published and the kernel has not consumed. # C: O(1)
fn ready(ring: &IoUringInode) -> u32 {
    let r = ring.ring.lock();
    sq_ready(r.hdr_load(RING_SQ_TAIL), r.hdr_load(RING_SQ_HEAD))
}

/// Whether the SQ ring has room for another entry. # C: O(1)
pub fn has_sq_room(ring: &IoUringInode) -> bool {
    let r = ring.ring.lock();
    !sq_full(r.hdr_load(RING_SQ_TAIL), r.hdr_load(RING_SQ_HEAD), r.sq_entries)
}

/// What the loop sees right now. # C: O(1)
fn observe(sqd: &SqData, ring: &Arc<IoUringInode>) -> Observed {
    Observed {
        stop: sqd.stop.load(Ordering::Acquire),
        park: sqd.park_pending.load(Ordering::Acquire) != 0,
        disabled: ring.test_state(state::DISABLED),
        sq_ready: ready(ring),
        shared: false,
        now_ns: super::iowq::worker::now_ns(),
    }
}

/// Stand down until every park request is released. # C: O(N_parks)
/// # Sleeps: while parked
fn do_park(sqd: &SqData) {
    sqd.parked.store(true, Ordering::Release);
    sqd.park_wait.wake_all();
    while sqd.park_pending.load(Ordering::Acquire) != 0 && !sqd.stop.load(Ordering::Acquire) {
        // SAFETY: running poll thread in process context on its own CPU holding no lock; `unpark`/`stop` wake this list after clearing the request, and the matching schedule yields immediately per the WaitList contract.
        unsafe {
            sqd.wait.park();
            if sqd.park_pending.load(Ordering::Acquire) == 0 || sqd.stop.load(Ordering::Acquire) {
                sqd.wait.cancel_current_park();
                break;
            }
            sched::live::schedule();
        }
    }
    sqd.parked.store(false, Ordering::Release);
}

/// The idle half of one pass: publish the doorbell, re-read the tail across a
/// full barrier, and sleep only if the ring is still empty.
///
/// The registration comes FIRST, before the doorbell goes up: a wake that
/// lands between publishing the flag and registering would find nothing on the
/// list and be dropped, which is the same hang from the other direction.
/// # C: O(1)
/// # Sleeps: until woken
fn idle(sqd: &SqData, ring: &Arc<IoUringInode>) {
    // SAFETY: running poll thread in process context on its own CPU holding no lock; every waker (`wake`, `stop`, `unpark`) wakes this list, and the matching schedule yields immediately per the WaitList contract.
    unsafe { sqd.wait.park(); }
    update_sq_flags(ring, arm_need_wakeup);
    // Separates the doorbell store from the tail load below. The submitter's
    // side of this pair is its own store-tail / load-flags barrier.
    core::sync::atomic::fence(Ordering::SeqCst);
    if sleeps_after_arm(&observe(sqd, ring)) {
        // SAFETY: registered on `wait` above, holding no lock, in process context on this thread's own CPU.
        unsafe { sched::live::schedule(); }
    } else {
        sqd.wait.cancel_current_park();
    }
    update_sq_flags(ring, disarm_need_wakeup);
}

/// The poll loop. Returns once the ring is gone or a stop was requested.
/// # C: unbounded — runs for the ring's life
/// # Sleeps: whenever the ring is idle
fn run(sqd: &SqData) {
    // Borrowed once and held: this thread has no address space, no descriptor
    // table and no credentials of its own, and every entry it runs belongs to
    // the task that created the ring.
    // SAFETY: the running task is a freshly spawned kernel thread in process context on its own CPU with no address space, no descriptor table and no lock held.
    let _borrow = unsafe { Borrow::install(&sqd.owner) };

    let mut st = PollState::new(sqd.idle_ns);
    loop {
        let Some(ring) = sqd.ring.upgrade() else { return };
        let o = observe(sqd, &ring);
        match step(&st, &o) {
            Step::Stop => return,
            Step::Park => do_park(sqd),
            Step::Submit(n) => {
                super::submit::submit_sqes(&ring, n);
                // Room was made and completions may have been posted.
                sqd.sq_wait.wake_all();
                st.touch(super::iowq::worker::now_ns());
            }
            Step::Spin => {
                // SAFETY: running poll thread in process context on its own CPU holding no lock; schedule re-enqueues this still-runnable task.
                unsafe { sched::live::schedule(); }
            }
            Step::Idle => {
                idle(sqd, &ring);
                st.touch(super::iowq::worker::now_ns());
            }
        }
    }
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
    // gone: leave the doorbell up so its next submission enters the kernel.
    if let Some(ring) = sqd.ring.upgrade() { update_sq_flags(&ring, arm_need_wakeup); }
    sqd.sq_wait.wake_all();
    sqd.park_wait.wake_all();
    drop(sqd);
    // SAFETY: running kernel thread on its own CPU, holding no lock, owning no in-flight I/O — every borrow was released by `run` returning.
    unsafe { sched::live::kthread_exit(0) }
}

/// Processors the creating task may itself run on. Linux tests
/// `p->sq_thread_cpu` against `cpuset_cpus_allowed(current)`, so a confined
/// task cannot place a poll thread outside its own confinement. # C: O(1)
fn creator_cpus() -> u64 {
    let active = crate::affinity_common::active_cpu_mask();
    match sched::live::current() {
        Some(t) => t.cpus_allowed.load(Ordering::Acquire) & active,
        None => active,
    }
}

/// Linux `io_sq_offload_create`: build the ring's poll thread, if it asked for
/// one. Runs in the creating task's context, from `io_uring_setup`, after the
/// regions exist and before the descriptor is installed — so a failure here
/// leaks nothing.
/// # C: O(stack_size)
pub fn offload_create(ring: &Arc<IoUringInode>, p: &Params) -> Result<(), Errno> {
    let cpu = sq_cpu(p.flags, p.sq_thread_cpu, creator_cpus())?;
    if p.flags & IORING_SETUP_SQPOLL == 0 { return Ok(()); }

    let sqd = Arc::new(SqData {
        ring: Arc::downgrade(ring),
        wait: sched::live::WaitList::new(),
        sq_wait: sched::live::WaitList::new(),
        park_wait: sched::live::WaitList::new(),
        task: Spinlock::new(None),
        park_pending: AtomicU32::new(0),
        parked: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        exited: AtomicBool::new(false),
        idle_ns: sq_thread_idle_ns(p.sq_thread_idle),
        // Captured HERE, in the creating task, which is the whole point: the
        // thread must run entries as the task that published them.
        owner: ring.owner_ctx(),
    });

    let tid = sched::live::next_tid();
    let raw = Arc::into_raw(Arc::clone(&sqd)) as usize;
    // SAFETY: called from the syscall path with the runqueue installed; entry is a 'static extern "C" fn and the argument is the Arc raw pointer reclaimed by exactly that function.
    let task = match unsafe { sched::live::spawn_kernel_thread(tid, "iou-sqp", sq_thread, raw) } {
        Ok(t) => t,
        Err(_) => {
            // SAFETY: the thread never started, so nobody else holds this raw pointer; reclaiming it here releases the reference `into_raw` leaked.
            drop(unsafe { Arc::from_raw(raw as *const SqData) });
            return Err(Errno::Enomem);
        }
    };
    if let Some(c) = cpu { task.cpus_allowed.store(1u64 << c, Ordering::Release); }
    *sqd.task.lock() = Some(task);
    *ring.sq.lock() = Some(sqd);
    Ok(())
}

/// The ring's poll thread, if it has one. # C: O(1)
pub fn of(ring: &IoUringInode) -> Option<Arc<SqData>> { ring.sq.lock().clone() }

/// Linux `io_sq_thread_finish`: end the poll thread when the ring's last
/// descriptor goes away. # C: O(1)
pub fn finish(ring: &IoUringInode) {
    let sqd = ring.sq.lock().take();
    if let Some(sqd) = sqd { sqd.stop(); }
}

/// Linux `io_sqpoll_wait_sq`: block until the poll thread has consumed enough
/// of the SQ ring for the caller to publish another entry.
/// # C: O(N_wakeups)
/// # Sleeps: until the ring has room
pub fn wait_sq_room(sqd: &SqData, ring: &Arc<IoUringInode>) {
    if has_sq_room(ring) { return; }
    sqd.wake();
    // SAFETY: process context in the syscall path on the running task's own CPU, holding no spinlock and no submission lock.
    let _ = unsafe {
        sched::live::wait_event(
            &sqd.sq_wait, sched::task::WaitState::Interruptible, 0,
            super::iowq::worker::now_ns, || has_sq_room(ring) || sqd.dead(),
        )
    };
}
