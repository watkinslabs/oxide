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
// Lifetime: the thread dies with the LAST ring it serves. Its handles on the
// rings are weak, so it never keeps a closed ring alive; a ring's last
// descriptor closing drops it from the thread's set, and the set going empty
// sets the stop request. The thread exits on its own rather than making
// `close(2)` wait for it.
//
// `IORING_SETUP_ATTACH_WQ` is why the set is a set: a ring may join the poll
// thread of a ring in its own thread group instead of starting a second one.
// The thread then sweeps every ring it serves per pass, capped per ring so a
// busy one cannot starve the others.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use syscall::errno::Errno;

use sync::{Spinlock, TaskList as SqLockClass};

use crate::io_uring_abi::layout::{RING_SQ_FLAGS, RING_SQ_HEAD, RING_SQ_TAIL};
use crate::io_uring_abi::sqpoll::{
    arm_need_wakeup, attach_admit, disarm_need_wakeup, shares, sleeps_after_arm,
    sq_cpu, sq_full, sq_ready, sq_thread_idle_ns, sweep, Attach, Observed, Pass,
    Peer, PollState, RingView,
};
use crate::io_uring_abi::uapi::Params;

use super::ctx::{state, IoUringInode};
use super::iowq::owner::{Borrow, Owner};

/// One poll thread and the state both sides of the handshake read. Shared by
/// every ring attached to it.
pub struct SqData {
    /// The rings this thread serves. Weak: a closed ring must not be held
    /// alive by the thread that was draining it. More than one only through
    /// `IORING_SETUP_ATTACH_WQ`.
    rings: Spinlock<Vec<Weak<IoUringInode>>, SqLockClass>,
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
    /// The thread group whose rings may attach to this thread.
    tgid: u32,
    /// What the thread borrows to run its rings' entries.
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

    /// Add a ring to this thread's set. # C: O(N_rings)
    fn join(&self, ring: &Arc<IoUringInode>) -> Result<(), Errno> {
        let mut g = self.rings.lock();
        if g.try_reserve(1).is_err() { return Err(Errno::Enomem); }
        g.push(Arc::downgrade(ring));
        Ok(())
    }

    /// Drop a ring from this thread's set, and report whether the set is now
    /// empty — which is the thread's cue to exit. # C: O(N_rings)
    fn leave(&self, ring: &IoUringInode) -> bool {
        let mut g = self.rings.lock();
        g.retain(|w| match w.upgrade() {
            Some(r) => !core::ptr::eq(Arc::as_ptr(&r), ring as *const _),
            None => false,
        });
        g.is_empty()
    }

    /// The rings still alive, as owning handles. Prunes the ones that are
    /// gone, so a thread whose last ring was dropped without a close notices.
    /// # C: O(N_rings)
    fn live(&self) -> Vec<Arc<IoUringInode>> {
        let mut g = self.rings.lock();
        g.retain(|w| w.strong_count() > 0);
        let mut out = Vec::new();
        if out.try_reserve(g.len()).is_err() { return out; }
        for w in g.iter() { if let Some(r) = w.upgrade() { out.push(r); } }
        out
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

/// What one ring looks like to a sweep. # C: O(1)
fn view(ring: &Arc<IoUringInode>) -> RingView {
    RingView { sq_ready: ready(ring), disabled: ring.test_state(state::DISABLED) }
}

/// What decides stop / park / spin / sleep once a sweep has found nothing to
/// do. # C: O(1)
fn observe_idle(sqd: &SqData, sq_ready: u32, n_rings: u32) -> Observed {
    Observed {
        stop: sqd.stop.load(Ordering::Acquire),
        park: sqd.park_pending.load(Ordering::Acquire) != 0,
        disabled: false,
        sq_ready,
        shared: shares(n_rings),
        now_ns: super::iowq::worker::now_ns(),
    }
}

/// Entries published across every ring this thread serves. # C: O(N_rings)
fn total_ready(rings: &[Arc<IoUringInode>]) -> u32 {
    let mut n: u32 = 0;
    for r in rings { if !r.test_state(state::DISABLED) { n = n.saturating_add(ready(r)); } }
    n
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
fn idle(sqd: &SqData, rings: &[Arc<IoUringInode>]) {
    // SAFETY: running poll thread in process context on its own CPU holding no lock; every waker (`wake`, `stop`, `unpark`) wakes this list, and the matching schedule yields immediately per the WaitList contract.
    unsafe { sqd.wait.park(); }
    // Every ring the thread serves raises its own doorbell: a submitter reads
    // the word of the ring it is publishing to and nothing else.
    for r in rings { update_sq_flags(r, arm_need_wakeup); }
    // Separates the doorbell stores from the tail loads below. The submitter's
    // side of this pair is its own store-tail / load-flags barrier.
    core::sync::atomic::fence(Ordering::SeqCst);
    let o = observe_idle(sqd, total_ready(rings), rings.len() as u32);
    if sleeps_after_arm(&o) {
        // SAFETY: registered on `wait` above, holding no lock, in process context on this thread's own CPU.
        unsafe { sched::live::schedule(); }
    } else {
        sqd.wait.cancel_current_park();
    }
    for r in rings { update_sq_flags(r, disarm_need_wakeup); }
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
        let rings = sqd.live();
        // Every ring gone is the same as a stop: there is nothing left to
        // drain and nobody left to report to.
        if rings.is_empty() { return; }
        let n = rings.len() as u32;

        // One sweep: each ring gets a bounded share of the pass, so a ring
        // with a full SQ cannot hold the thread while its neighbours wait.
        let mut views: Vec<RingView> = Vec::new();
        if views.try_reserve(rings.len()).is_err() { return; }
        for r in &rings { views.push(view(r)); }

        match sweep(&st, &views,
                    sqd.stop.load(Ordering::Acquire),
                    sqd.park_pending.load(Ordering::Acquire) != 0,
                    super::iowq::worker::now_ns()) {
            Pass::Stop => return,
            Pass::Park => do_park(sqd),
            Pass::Take(take) => {
                for (ring, n) in rings.iter().zip(take) {
                    if n == 0 { continue; }
                    super::submit::submit_sqes(ring, n);
                    // Room was made and completions may have been posted.
                    sqd.sq_wait.wake_all();
                }
                st.touch(super::iowq::worker::now_ns());
            }
            Pass::Idle => { idle(sqd, &rings); st.touch(super::iowq::worker::now_ns()); }
            Pass::Spin => {
                // SAFETY: running poll thread in process context on its own CPU holding no lock; schedule re-enqueues this still-runnable task.
                unsafe { sched::live::schedule(); }
            }
        }
        let _ = n;
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
    // gone: leave every doorbell up so its next submission enters the kernel.
    for ring in sqd.live() { update_sq_flags(&ring, arm_need_wakeup); }
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
    // The descriptor `IORING_SETUP_ATTACH_WQ` names is validated whether or
    // not this ring has a poll thread to place.
    let peer = peer_of(p.wq_fd);
    match attach_admit(p.flags, &peer)? {
        Attach::Validate => return Ok(()),
        Attach::Join => return join_peer(ring, p.wq_fd),
        Attach::Own => {}
    }

    let sqd = Arc::new(SqData {
        rings: Spinlock::new(alloc::vec![Arc::downgrade(ring)]),
        wait: sched::live::WaitList::new(),
        sq_wait: sched::live::WaitList::new(),
        park_wait: sched::live::WaitList::new(),
        task: Spinlock::new(None),
        park_pending: AtomicU32::new(0),
        parked: AtomicBool::new(false),
        stop: AtomicBool::new(false),
        exited: AtomicBool::new(false),
        idle_ns: sq_thread_idle_ns(p.sq_thread_idle),
        // The thread group a later `IORING_SETUP_ATTACH_WQ` must match: the
        // thread borrows this task's address space and descriptor table, so a
        // ring from another process would not mean on it what it means here.
        tgid: sched::live::current().map(|c| c.tgid.load(Ordering::Acquire)).unwrap_or(0),
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

/// What the creator can tell about the descriptor `IORING_SETUP_ATTACH_WQ`
/// names. Every field is answered independently, so the admission ladder — not
/// this lookup — decides which one matters first. # C: O(1)
fn peer_of(wq_fd: u32) -> Peer {
    let Some(cur) = sched::live::current() else { return Peer::default() };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Peer::default() };
    let Ok(file) = fdt.clone().get(wq_fd as i32) else { return Peer::default() };
    let present = true;
    let Ok(inode) = super::ring::ring_of(&file) else { return Peer { present, ..Peer::default() } };
    let is_ring = true;
    let Some(peer) = super::ring::ring_ctx(&inode) else {
        return Peer { present, is_ring, ..Peer::default() };
    };
    let sqd = peer.sq.lock().clone();
    match sqd {
        None => Peer { present, is_ring, ..Peer::default() },
        Some(sqd) => Peer {
            present, is_ring, has_thread: true,
            same_group: sqd.tgid == cur.tgid.load(Ordering::Acquire),
            dead: sqd.dead(),
        },
    }
}

/// Join the poll thread of the ring `wq_fd` names. The thread's set is what
/// keeps it alive, so the ring is added to it before the ring adopts the
/// thread: a thread that observed an empty set in between would exit under a
/// ring that had already taken it. # C: O(N_rings)
fn join_peer(ring: &Arc<IoUringInode>, wq_fd: u32) -> Result<(), Errno> {
    let Some(cur) = sched::live::current() else { return Err(Errno::Enxio) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of the fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(Errno::Enxio) };
    let file = fdt.clone().get(wq_fd as i32).map_err(|_| Errno::Enxio)?;
    let inode = super::ring::ring_of(&file)?;
    let peer = super::ring::ring_ctx(&inode).ok_or(Errno::Einval)?;
    let sqd = peer.sq.lock().clone().ok_or(Errno::Einval)?;
    if sqd.dead() { return Err(Errno::Enxio); }
    sqd.join(ring)?;
    *ring.sq.lock() = Some(Arc::clone(&sqd));
    // The new ring may already have entries published.
    sqd.wake();
    Ok(())
}

/// End this ring's relationship with its poll thread when its last descriptor
/// goes away. The thread stops only when it has no rings left: another ring
/// may have attached to it and still need it. # C: O(N_rings)
pub fn finish(ring: &IoUringInode) {
    let sqd = ring.sq.lock().take();
    let Some(sqd) = sqd else { return };
    if sqd.leave(ring) { sqd.stop(); } else { sqd.wake(); }
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
