//! The two kernel threads: starting them, their loops, and stopping them.
//!
//! Each is the same shape — park with a deadline and a condition, run one
//! pass, sleep for whatever the pass said. The pass itself is in `round` and
//! needs no scheduler, so the only thing this file owns is the parking, and
//! the only thing that can be wrong here is the parking.
//!
//! The thread holds a WEAK reference to the mount. A strong one would be a
//! cycle: the mount owns the state the thread parks on, so the mount could
//! never be dropped and the unmount that is supposed to stop the thread would
//! never run. Weak also makes a mount dropped without a stop safe rather than
//! fatal — the next upgrade fails and the thread winds up.

use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;

use crate::mount::F2fs;

use crate::bg::round;

/// Nanoseconds in a millisecond, the unit the policy states intervals in.
const NS_PER_MS: u64 = 1_000_000;

/// The clock a park deadline is measured against. # C: O(1)
fn now_ns() -> u64 { timekeeper::monotonic_ns() }

/// Start the cleaner and the discard thread for `fs`.
///
/// A read-only mount gets neither: cleaning writes, and a discard announces
/// space a read-only mount never freed.
/// # C: O(1)
pub fn start(fs: &Arc<F2fs>) {
    if !fs.is_writable() { return; }
    let bg = fs.bg();
    if bg.stopping() { return; }
    if !bg.gc_running.swap(true, Ordering::AcqRel) && !spawn(fs, "f2fs_gc", gc_thread) {
        bg.gc_running.store(false, Ordering::Release);
    }
    if !bg.discard_running.swap(true, Ordering::AcqRel)
        && !spawn(fs, "f2fs_discard", discard_thread) {
        bg.discard_running.store(false, Ordering::Release);
    }
    // Only where the mount asked for it. A thread nobody hands work to would
    // park for ever, and the option is what says whether anybody will.
    if fs.merges_checkpoints()
        && !bg.ckpt_running.swap(true, Ordering::AcqRel)
        && !spawn(fs, "f2fs_ckpt", ckpt_thread) {
        bg.ckpt_running.store(false, Ordering::Release);
    }
}

/// Hand one thread a weak reference to the mount and let the scheduler have
/// it. # C: O(1)
fn spawn(fs: &Arc<F2fs>, name: &'static str, entry: extern "C" fn(usize) -> !) -> bool {
    let weak = Arc::downgrade(fs);
    let arg = Weak::into_raw(weak) as usize;
    let tid = sched::live::next_tid();
    // SAFETY: called from the mount path in process context after the
    // runqueue is installed; `entry` is a 'static extern "C" fn and `arg` is a
    // leaked `Weak<F2fs>` raw pointer that the thread reclaims and drops on
    // exit, so the reference is owned by exactly one side at all times.
    let started = unsafe { sched::live::spawn_kernel_thread(tid, name, entry, arg) }.is_ok();
    if !started {
        // SAFETY: the pointer came from `Weak::into_raw` immediately above and
        // no thread took ownership of it, so this is the only reclaim.
        drop(unsafe { Weak::from_raw(arg as *const F2fs) });
    }
    started
}

/// Stop both threads and wait for them to finish the pass they are in.
///
/// Waiting matters: a pass holds the volume lock while it moves blocks, and
/// tearing the mount down under one would free the volume a thread is still
/// reading.
/// # C: O(one pass of each thread)
pub fn stop(fs: &F2fs) {
    let bg = fs.bg();
    bg.stopping.store(true, Ordering::Release);
    bg.waits.wake_gc();
    bg.waits.wake_discard();
    bg.waits.wake_ckpt();
    bg.waits.wake_foreground();
    while bg.gc_running.load(Ordering::Acquire) || bg.discard_running.load(Ordering::Acquire)
        || bg.ckpt_running.load(Ordering::Acquire) {
        // SAFETY: unmount runs in process context holding no volume lock; the
        // threads being waited for need the CPU to observe the stop flag.
        unsafe { sched::live::schedule(); }
    }
}

/// Longest a caller blocked in the balance path waits for the cleaner before
/// giving up and cleaning itself, in nanoseconds. A pass that has taken this
/// long is stuck on something the caller cannot see, and blocking a write on
/// it forever is worse than doing the work twice.
const FGGC_WAIT_NS: u64 = 5 * 1_000_000_000;

/// Hand a cleaning pass to the cleaner thread and wait for it.
///
/// Answers whether the pass was handed over at all. Without a running thread
/// there is nobody to hand it to and the caller must clean for itself.
/// # C: O(1) plus the wait
pub fn delegate_gc(fs: &Arc<F2fs>) -> bool {
    let bg = fs.bg();
    if !bg.gc_running.load(Ordering::Acquire) || bg.stopping() { return false; }
    let deadline = now_ns().saturating_add(FGGC_WAIT_NS);
    // Read the generation BEFORE asking, so a pass that finishes between the
    // ask and the park is seen as done rather than waited out.
    let seen = bg.foreground_gen();
    bg.wake_gc();
    // SAFETY: process context in the write path holding no volume lock; the
    // condition reads one atomic and the wake comes from the cleaner's pass.
    let _ = unsafe {
        sched::live::wait_event_uninterruptible_until(&bg.waits.foreground, deadline, now_ns,
            || bg.foreground_gen() != seen || bg.stopping())
    };
    true
}

/// Longest a caller waits for the merge thread before writing the checkpoint
/// itself, in nanoseconds.
///
/// The same reasoning as the cleaner's wait: a thread that has taken this long
/// is stuck on something the caller cannot see, and blocking a durability
/// promise on it for ever is worse than making the promise twice.
const CKPT_WAIT_NS: u64 = 5 * 1_000_000_000;

/// Hand a checkpoint to the merge thread and wait for the write that serves it.
///
/// `None` means it was not handed over and the caller keeps the write. `Some`
/// carries the result of the ONE write that served this caller and every other
/// caller enrolled with it.
/// # C: O(1) plus the wait
pub fn delegate_checkpoint(fs: &Arc<F2fs>) -> Option<vfs::KResult<()>> {
    let bg = fs.bg();
    if !bg.ckpt_running.load(Ordering::Acquire) || bg.stopping() { return None; }
    let deadline = now_ns().saturating_add(CKPT_WAIT_NS);
    // Enrol BEFORE parking, and wait for the batch counter to move rather than
    // for a flag: a write that completes between the enrolment and the park is
    // then seen as done instead of waited out.
    let seen = bg.enrol_checkpoint();
    // SAFETY: process context in a sync path holding no volume lock; the
    // condition takes only the short request lock, which no waker holds across
    // its wake.
    let _ = unsafe {
        sched::live::wait_event_uninterruptible_until(&bg.waits.ckpt, deadline, now_ns,
            || bg.checkpoint_served(seen) || bg.stopping())
    };
    // A caller released by the stop rather than by a write has not been served,
    // and must not report the previous batch's result as its own.
    if !bg.checkpoint_served(seen) { return None; }
    Some(bg.checkpoint_result())
}

/// Whether this thread should wind up. # C: O(1)
fn winding_up(weak: &Weak<F2fs>) -> bool {
    match weak.upgrade() {
        None => true,
        Some(fs) => fs.bg().stopping(),
    }
}

/// Park until `wait_ms` has passed or something asks for a pass sooner.
/// # C: O(1) plus the sleep
fn park(fs: &Arc<F2fs>, gc: bool, wait_ms: u32) {
    let bg = fs.bg();
    let deadline = now_ns().saturating_add(u64::from(wait_ms).saturating_mul(NS_PER_MS));
    let wq = if gc { &bg.waits.gc } else { &bg.waits.discard };
    let cond = || {
        if bg.stopping() { return true; }
        if gc { bg.gc.lock().gc_wake || bg.foreground_waiting() } else { bg.dcc.lock().wake }
    };
    // SAFETY: running kernel thread in process context holding no volume or
    // background lock; the condition takes only the short knob locks, which no
    // waker holds across its wake.
    let _ = unsafe {
        sched::live::wait_event_uninterruptible_until(wq, deadline, now_ns, cond)
    };
}

extern "C" fn gc_thread(arg: usize) -> ! {
    // SAFETY: `arg` is the `Weak<F2fs>` this thread was spawned with, leaked
    // by `spawn` and owned by this thread alone until it is dropped below.
    let weak = unsafe { Weak::from_raw(arg as *const F2fs) };
    let mut wait_ms = crate::bg::gc::DEF_GC_THREAD_MIN_SLEEP_TIME;
    while !winding_up(&weak) {
        let Some(fs) = weak.upgrade() else { break };
        park(&fs, true, wait_ms);
        if fs.bg().stopping() { break; }
        wait_ms = round::gc_pass(&fs).wait_ms;
    }
    if let Some(fs) = weak.upgrade() {
        fs.bg().gc_running.store(false, Ordering::Release);
    }
    drop(weak);
    // SAFETY: this thread holds no lock and owns nothing further; the weak
    // reference it was given has been dropped above.
    unsafe { sched::live::kthread_exit(0) }
}

extern "C" fn ckpt_thread(arg: usize) -> ! {
    // SAFETY: `arg` is the `Weak<F2fs>` this thread was spawned with, leaked
    // by `spawn` and owned by this thread alone until it is dropped below.
    let weak = unsafe { Weak::from_raw(arg as *const F2fs) };
    while !winding_up(&weak) {
        let Some(fs) = weak.upgrade() else { break };
        park_ckpt(&fs);
        if fs.bg().stopping() { break; }
        // Linux applies ckpt_thread_ioprio to the merge task. The block layer
        // stamps every request submitted by that task from this value, so the
        // priority reaches the queue without a second f2fs-only flag path.
        if let Some(task) = sched::live::current() {
            task.set_ioprio(fs.bg().checkpoint_ioprio().packed());
        }
        round::ckpt_pass(&fs);
    }
    // Anybody still enrolled is released rather than left parked: the mount is
    // going away and the caller writes its own.
    if let Some(fs) = weak.upgrade() {
        fs.bg().ckpt_running.store(false, Ordering::Release);
        fs.bg().waits.wake_ckpt();
    }
    drop(weak);
    // SAFETY: this thread holds no lock and owns nothing further; the weak
    // reference it was given has been dropped above.
    unsafe { sched::live::kthread_exit(0) }
}

/// Park until somebody enrols a checkpoint, with no deadline of its own.
///
/// No interval, unlike the other two: a checkpoint is never written because
/// time has passed — the periodic one is the cleaner's balance path asking for
/// it — so this thread has nothing to do until a caller asks.
/// # C: O(1) plus the sleep
fn park_ckpt(fs: &Arc<F2fs>) {
    let bg = fs.bg();
    let cond = || bg.stopping() || bg.cprc.lock().wake;
    // SAFETY: running kernel thread in process context holding no volume or
    // background lock; the condition takes only the short request lock, which
    // no waker holds across its wake.
    let _ = unsafe { sched::live::wait_event_uninterruptible(&bg.waits.ckpt, cond) };
}

extern "C" fn discard_thread(arg: usize) -> ! {
    // SAFETY: `arg` is the `Weak<F2fs>` this thread was spawned with, leaked
    // by `spawn` and owned by this thread alone until it is dropped below.
    let weak = unsafe { Weak::from_raw(arg as *const F2fs) };
    let mut wait_ms = crate::bg::discard::DEF_MIN_DISCARD_ISSUE_TIME;
    while !winding_up(&weak) {
        let Some(fs) = weak.upgrade() else { break };
        park(&fs, false, wait_ms);
        if fs.bg().stopping() { break; }
        wait_ms = round::discard_pass(&fs).wait_ms;
    }
    if let Some(fs) = weak.upgrade() {
        fs.bg().discard_running.store(false, Ordering::Release);
    }
    drop(weak);
    // SAFETY: this thread holds no lock and owns nothing further; the weak
    // reference it was given has been dropped above.
    unsafe { sched::live::kthread_exit(0) }
}
