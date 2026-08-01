// The helper threads and the caller's completion.
//
// Helpers run on threads of their own rather than on the shared deferred-work
// pool, for two reasons. The exec cannot run on the submitting task's page
// tables — loading an image writes through the NEW address space's user
// addresses, so it needs a thread that owns no address space of its own. And a
// `UMH_WAIT_PROC` request blocks until the helper program terminates, which on
// a shared worker would stall every other piece of deferred work behind it for
// as long as that program runs.
//
// There is more than ONE such thread, and the count grows on demand: a request
// that blocks must not block a pending one. `pool` states why, and owns the
// growth rule; this module is where a thread applies it — the thread that takes
// a request starts a replacement first, so an idle servicer is always waiting
// behind whatever the busy ones are doing.
//
// A waiting caller blocks on its own request's completion, so two helpers
// started at once do not wake each other.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};

use sched::live::WaitList;
use sync::Spinlock;
use syscall::errno::Errno;

use crate::backend::HelperRun;
use crate::info::SubprocessInfo;
use crate::pool::{Grow, Pool};
use crate::uapi::{UMH_KILLABLE, UMH_NO_WAIT, UMH_WAIT_PROC};

use super::arch;

/// Pending-request list. A strict leaf: held only to move one pointer on or off
/// the list, never across an exec or a wait.
struct UmhQueue;
impl sync::LockClass for UmhQueue {
    fn rank() -> u16 { 96 }
    fn name() -> &'static str { "UmhQueue" }
}

/// Interrupt gate for the pending list. A `UMH_NO_WAIT` submission is allowed
/// from a context that must not sleep, including an interrupt handler, so the
/// process-context side masks interrupts while it holds the list.
#[cfg(target_arch = "x86_64")]
type UmhIrq = hal_x86_64::X86IrqGate;
#[cfg(target_arch = "aarch64")]
type UmhIrq = hal_aarch64::ArmIrqGate;

/// Requests that may be outstanding at once. A submission beyond this reports a
/// failure rather than growing without bound from an interrupt handler.
const QUEUE_DEPTH: usize = 32;

/// Servicing threads the pool will start. Every request the queue can hold may
/// be one that blocks for as long as its program runs, so the ceiling matches
/// the queue depth: nothing that fits on the queue can be stuck behind another
/// request rather than behind its own helper.
const MAX_SERVICERS: u32 = QUEUE_DEPTH as u32;

/// `arg` of the thread boot starts, which is the one that runs the self-test.
/// Threads the pool grows into carry `GROWN_SERVICER` and skip it.
const INITIAL_SERVICER: usize = 1;
const GROWN_SERVICER: usize = 0;

static PENDING: Spinlock<VecDeque<usize>, UmhQueue> = Spinlock::new(VecDeque::new());
static PENDING_WAIT: WaitList = WaitList::new();
static POOL: Pool = Pool::new(MAX_SERVICERS);

/// Missed-wakeup backstop for both the helper thread's idle park and a caller's
/// completion wait.
const BACKSTOP_NS: u64 = 100_000_000;

/// One in-flight request, shared between the submitting task and the helper
/// thread.
struct Req {
    /// The request record, owned by whichever side last swapped it out. The
    /// helper thread takes it, fills `retval`, and puts it back for a waiting
    /// caller; under `UMH_NO_WAIT` it releases the record instead.
    info: AtomicPtr<SubprocessInfo>,
    done: AtomicBool,
    wq: WaitList,
}

impl Drop for Req {
    fn drop(&mut self) {
        // A caller whose wait was cut short leaves the record for whichever side
        // holds the last reference; releasing it here is what keeps that case
        // from leaking the request and its `cleanup`.
        let p = self.info.swap(core::ptr::null_mut(), Ordering::AcqRel);
        if p.is_null() { return; }
        // SAFETY: the slot holds a Box raw pointer published by `submit` or `put`; this is the last reference to the request, so no other side can observe it.
        unsafe { Box::from_raw(p) }.free();
    }
}

/// Submit a request. `UMH_NO_WAIT` returns as soon as the request is queued;
/// every other mode blocks until the helper thread has a result.
/// # C: O(helper)
pub fn submit(info: Box<SubprocessInfo>) -> HelperRun {
    let wait = info.wait;
    let req = Arc::new(Req {
        info: AtomicPtr::new(Box::into_raw(info)),
        done: AtomicBool::new(false),
        wq: WaitList::new(),
    });
    let arg = Arc::into_raw(Arc::clone(&req)) as usize;
    if !enqueue(arg) {
        // Too many helpers are already outstanding. Reclaim both the reference
        // we prepared and the request, and report the failure — dropping it
        // silently would be a helper the caller believes ran.
        // SAFETY: `arg` is the raw form of the Arc cloned above and was never queued, so nobody else will reclaim it.
        drop(unsafe { Arc::from_raw(arg as *const Req) });
        let mut back = take(&req).unwrap_or_else(|| SubprocessInfo::new(None, &[], &[], None, None, 0));
        back.retval = -(Errno::Eagain.as_i32());
        return HelperRun::Done(back);
    }
    if wait == UMH_NO_WAIT { return HelperRun::Detached; }

    await_completion(&req, wait & UMH_KILLABLE != 0);
    match take(&req) {
        Some(back) => HelperRun::Done(back),
        // The record is only left behind for a detached request, which this is
        // not; report a failure rather than a zero result.
        None => {
            let mut back = SubprocessInfo::new(None, &[], &[], None, None, 0);
            back.retval = -(Errno::Eintr.as_i32());
            HelperRun::Done(back)
        }
    }
}

/// Block until the helper thread publishes a result.
///
/// The wait is UNINTERRUPTIBLE unless the caller asked otherwise, because the
/// most important caller is a process that is already dying of a fatal signal:
/// a wait that a pending signal aborts would never deliver its core dump at
/// all. `UMH_KILLABLE` is how a caller opts into the other behaviour.
fn await_completion(req: &Req, killable: bool) {
    while !req.done.load(Ordering::Acquire) {
        if killable && fatal_signal_pending() { return; }
        // SAFETY: process context on the submitting task with the runqueue installed and no lock held; the deadline bounds the park so a wake that lands before it cannot be lost for long.
        unsafe {
            req.wq.park_with_deadline(arch::now_ns() + BACKSTOP_NS);
            sched::live::schedule();
        }
    }
}

fn fatal_signal_pending() -> bool {
    let Some(cur) = sched::live::current() else { return false };
    let forced = sched::Signum::Sigkill.bit() | sched::Signum::Sigstop.bit();
    cur.pending_signals() & forced != 0
}

fn enqueue(arg: usize) -> bool {
    {
        let mut q = PENDING.lock_irqsave::<UmhIrq>();
        if q.len() >= QUEUE_DEPTH { return false; }
        q.push_back(arg);
    }
    // Wake outside the list lock: the helper thread's first act is to take it.
    PENDING_WAIT.wake_one();
    true
}

fn take(req: &Req) -> Option<Box<SubprocessInfo>> {
    let p = req.info.swap(core::ptr::null_mut(), Ordering::AcqRel);
    if p.is_null() { return None; }
    // SAFETY: the slot holds a Box raw pointer published by whoever last stored it, and the swap makes this the only side that observes it non-null.
    Some(unsafe { Box::from_raw(p) })
}

fn put(req: &Req, info: Box<SubprocessInfo>) {
    req.info.store(Box::into_raw(info), Ordering::Release);
}

/// A servicing thread. Owns no address space, so it is free to install a
/// helper's while loading its image, and free to block for as long as a helper
/// runs — which is why taking a request starts a replacement first.
/// # C: O(queued helpers)
extern "C" fn khelper(arg: usize) -> ! {
    #[cfg(feature = "debug-umh")]
    if arg == INITIAL_SERVICER { super::selftest::run(); }
    let _ = arg;
    POOL.ready();
    loop {
        let next = PENDING.lock_irqsave::<UmhIrq>().pop_front();
        match next {
            Some(req) => {
                // Before running anything: this thread may now block for the
                // whole lifetime of a helper program, so hand the queue a
                // successor rather than leaving the next request behind it.
                if POOL.claim() == Grow::Spawn { start_servicer(GROWN_SERVICER); }
                run_one(req);
                POOL.released();
            }
            // SAFETY: running kthread with no lock held; the deadline bounds the park so a submission landing between the check and the park is not lost.
            None => unsafe {
                PENDING_WAIT.park_with_deadline(arch::now_ns() + BACKSTOP_NS);
                sched::live::schedule();
            },
        }
    }
}

/// Start one servicing thread against a slot the pool has already reserved.
/// A failure releases the reservation, so a later claim retries rather than
/// believing the pool is bigger than it is. # C: O(1)
fn start_servicer(arg: usize) {
    let tid = sched::live::next_tid();
    // SAFETY: process context with the runqueues installed; `khelper` is a 'static extern "C" fn pointer.
    let started = unsafe { sched::live::spawn_kernel_thread(tid, "khelper", khelper, arg) };
    if started.is_err() { POOL.spawn_failed(); }
}

/// Start the first servicing thread. # C: O(1)
pub fn spawn_helper_thread() -> Result<(), sched::live::SpawnError> {
    if !POOL.reserve() { return Err(sched::live::SpawnError::Again); }
    let tid = sched::live::next_tid();
    // SAFETY: boot path after the runqueues are installed; `khelper` is a 'static extern "C" fn pointer.
    let r = unsafe { sched::live::spawn_kernel_thread(tid, "khelper", khelper, INITIAL_SERVICER) };
    if let Err(e) = r { POOL.spawn_failed(); return Err(e); }
    Ok(())
}

/// Run one request to whatever depth its wait mode asks for, then either hand
/// it back or release it.
fn run_one(arg: usize) {
    // SAFETY: `arg` is the raw form of the Arc `submit` prepared, and this is its single matching reclaim.
    let req = unsafe { Arc::from_raw(arg as *const Req) };
    let Some(mut info) = take(&req) else { return };
    let pending_child = run_inline(&mut info);

    if info.wait == UMH_NO_WAIT { info.free(); } else {
        put(&req, info);
        req.done.store(true, Ordering::Release);
        req.wq.wake_all();
    }

    // Release the caller first, then collect the helper: this thread is its
    // parent, and a helper nobody reaps stays queued as a terminated process
    // forever. A system that runs a helper per crash would accumulate them.
    if let Some(vpid) = pending_child { let _ = super::reap::wait_for(vpid); }
}

/// Start the helper and fill `info.retval` per its wait mode. Returns the
/// helper still needing collection, if the mode did not already wait for it.
/// Runs ON the helper thread — never on a submitting task, whose page tables
/// the image load would otherwise displace.
/// # C: O(helper)
pub(super) fn run_inline(info: &mut SubprocessInfo) -> Option<u32> {
    let started = super::child::start(info);
    let child = started.as_ref().ok().map(|t| t.vtid.load(Ordering::Acquire));
    let wants_status = info.wait & UMH_WAIT_PROC != 0;
    // `UMH_WAIT_PROC` reports the finished helper's status, so it waits here.
    // Every other mode reports only whether the image was loaded.
    info.retval = match (started, wants_status) {
        // The exec failed and no process was ever created, so the negated errno
        // is the answer for every mode; a `UMH_WAIT_PROC` caller tells it from a
        // status by its sign.
        (Err(rc), _) => rc,
        (Ok(_), false) => 0,
        (Ok(_), true) => super::reap::wait_for(child.unwrap_or(0)),
    };
    if wants_status { None } else { child }
}

/// Sleep roughly a millisecond. Used by the gate's drain loop, which must let
/// in-flight helpers make progress while it waits for them.
/// # C: O(1)
pub fn yield_one_ms() {
    const ONE_MS_NS: u64 = 1_000_000;
    static IDLE: WaitList = WaitList::new();
    // SAFETY: process context with the runqueue installed and no lock held; the park is deadline-bounded so no waker is required.
    unsafe {
        IDLE.park_with_deadline(arch::now_ns() + ONE_MS_NS);
        sched::live::schedule();
    }
}
