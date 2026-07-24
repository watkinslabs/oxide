//! Generic timer-wheel driver kthread (`ktimers`). Fires due software
//! timers (`crates/kernel/timer`) in process context — so callbacks may
//! take runqueue/subsystem locks. Subsystems self-register their own work
//! (docs/56); this driver names none. Lives in sched because it needs the
//! kthread spawn + park + monotonic clock the scheduler owns.
//!
//! ktimers is the sole caller of `timer::run_due` (which fires the periodic
//! `tick_wake_expired` deadline walker + reaper). It parks 100 ms between runs
//! and MUST be woken independently: the walker it runs is the only thing that
//! wakes deadline-parked tasks, so if ktimers relied on that walker to wake
//! ITSELF the system would be circular and wedge once incidental early wakers
//! stop (the B1344 regression — moving the walker off the hard tick into
//! ktimers removed ktimers's independent waker). `tick_poll_ktimers`, called
//! from the hard timer tick, is that independent waker — the Linux
//! `raise_softirq(TIMER_SOFTIRQ)` equivalent — using only a lock-free deadline
//! atomic + the IRQ-safe deferred wake list, never the registry/rq locks B1344
//! correctly exiled from IRQ context.
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};
use alloc::sync::Arc;
use crate::Task;
use super::WaitList;

static WAIT: WaitList = WaitList::new();
const TICK_NS: u64 = 100_000_000;

/// ktimers' Task, published once at spawn (a permanent kthread; one ref is
/// leaked so this pointer is valid for the machine's life). Read lock-free by
/// the timer tick to enqueue a wake.
static KTIMERS: AtomicPtr<Task> = AtomicPtr::new(core::ptr::null_mut());
/// ktimers' current park deadline (ns). Non-zero ⇒ armed: the tick wakes
/// ktimers once `now >= deadline`, then disarms (re-armed by the driver on its
/// next park). Zero ⇒ not parked / already woken.
static DEADLINE: AtomicU64 = AtomicU64::new(0);

#[cfg(target_arch = "x86_64")]
fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(target_arch = "aarch64")]
fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn this_cpu() -> u32 { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn this_cpu() -> u32 { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() }
#[cfg(not(target_os = "oxide-kernel"))]
fn this_cpu() -> u32 { 0 }

/// # C: O(due timers) per 100 ms wake
extern "C" fn driver(_arg: usize) -> ! {
    loop {
        let now = now_ns();
        timer::run_due(now);
        // Arm the tick-waker BEFORE parking so a tick between this store and the
        // park still observes the (future) deadline; a spurious early wake is
        // harmless (run_due is idempotent and re-arms).
        DEADLINE.store(now + TICK_NS, Ordering::Release);
        // SAFETY: running kthread on this CPU; preempt-off; no lock held across the park; schedule() yields immediately after per the WaitList contract.
        unsafe { WAIT.park_with_deadline(now + TICK_NS); super::schedule(); }
    }
}

/// Independent waker for ktimers, called from the HARD timer tick (BSP). When
/// ktimers' 100 ms park deadline passes, enqueue a wake on the local CPU's
/// deferred wake list (IRQ-safe, unlike the registry/rq locks) and disarm so
/// exactly one wake fires per park. The tick already set `need_resched`, so the
/// IRQ-return `schedule()` drains the wake list and runs ktimers. Without this,
/// ktimers is woken only by the walker it runs → circular wedge.
/// # C: O(1)
pub fn tick_poll_ktimers(now_ns: u64) {
    let dl = DEADLINE.load(Ordering::Acquire);
    if dl == 0 || now_ns < dl { return; }
    // Claim the arm exactly once; a racing tick that loses the CAS does nothing.
    if DEADLINE.compare_exchange(dl, 0, Ordering::AcqRel, Ordering::Acquire).is_err() { return; }
    let p = KTIMERS.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: `p` came from `Arc::as_ptr` of the spawned ktimers Task with one
    // ref permanently leaked (kthread never exits), so it stays live; bump the
    // strong count to materialise an owned Arc the wake list can hold.
    unsafe { Arc::increment_strong_count(p as *const Task); }
    // SAFETY: matches the increment above; hands the fresh Arc to the wake list.
    let arc = unsafe { Arc::from_raw(p as *const Task) };
    super::ttwu::wake_list_push(this_cpu(), arc);
}

/// Spawn the timer-driver kthread. Boot, once, after the runqueue installs.
/// # C: O(1)
pub fn spawn_timer_driver() -> Result<(), super::SpawnError> {
    let tid = super::next_tid();
    // SAFETY: boot path after install_default_runqueue; entry is a 'static extern "C" fn ptr; arg unused.
    let task = unsafe { super::spawn_kernel_thread(tid, "ktimers", driver, 0) }?;
    // Publish ktimers for the tick-waker and leak one ref so the pointer stays
    // valid for the machine's life (a permanent kthread that never exits).
    KTIMERS.store(Arc::as_ptr(&task) as *mut Task, Ordering::Release);
    core::mem::forget(task);
    Ok(())
}
