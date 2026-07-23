use core::ptr::null_mut;
use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use super::types::*;

pub type NowHook = fn() -> u64;

#[no_mangle]
pub static jiffies: AtomicU64 = AtomicU64::new(0);
#[no_mangle]
pub static jiffies_64: AtomicU64 = AtomicU64::new(0);

static NOW_HOOK: AtomicPtr<()> = AtomicPtr::new(null_mut());
pub(super) static FALLBACK_NS: AtomicU64 = AtomicU64::new(0);

pub(super) fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("msecs_to_jiffies", msecs_to_jiffies as *const () as usize),
        ("__msecs_to_jiffies", msecs_to_jiffies as *const () as usize),
        ("usecs_to_jiffies", usecs_to_jiffies as *const () as usize),
        ("__usecs_to_jiffies", usecs_to_jiffies as *const () as usize),
        ("nsecs_to_jiffies", nsecs_to_jiffies as *const () as usize),
        ("jiffies_to_msecs", jiffies_to_msecs as *const () as usize),
        ("jiffies_to_usecs", jiffies_to_usecs as *const () as usize),
        ("round_jiffies", round_jiffies as *const () as usize),
        ("ktime_get", ktime_get as *const () as usize),
        ("ktime_get_ns", ktime_get_ns as *const () as usize),
        ("ktime_get_with_offset", ktime_get_with_offset as *const () as usize),
        ("ktime_get_ts64", ktime_get_ts64 as *const () as usize),
        ("ktime_get_raw_ts64", ktime_get_raw_ts64 as *const () as usize),
        ("ktime_get_real_ts64", ktime_get_real_ts64 as *const () as usize),
        ("ktime_set", ktime_set as *const () as usize),
        ("ns_to_ktime", ns_to_ktime as *const () as usize),
        ("ktime_to_ns", ktime_to_ns as *const () as usize),
        ("ktime_add_ns", ktime_add_ns as *const () as usize),
        ("ktime_sub_ns", ktime_sub_ns as *const () as usize),
        ("msleep", msleep as *const () as usize),
        ("msleep_interruptible", msleep_interruptible as *const () as usize),
        ("usleep_range", usleep_range as *const () as usize),
        ("usleep_range_state", usleep_range_state as *const () as usize),
        ("udelay", udelay as *const () as usize),
        ("__udelay", udelay as *const () as usize),
        ("__const_udelay", __const_udelay as *const () as usize),
        ("mdelay", mdelay as *const () as usize),
        ("schedule", schedule as *const () as usize),
        ("schedule_timeout", schedule_timeout as *const () as usize),
        ("__SCT__preempt_schedule_notrace", preempt_schedule_notrace as *const () as usize),
    ] { export(name, addr, false); }
}

pub(super) fn set_now_hook(f: NowHook) {
    NOW_HOOK.store(f as *mut (), Ordering::Release);
}

pub(super) extern "C" fn msecs_to_jiffies(ms: u32) -> u64 { div_ceil(ms as u64 * KPI_HZ, MSEC_PER_SEC) }
pub(super) extern "C" fn usecs_to_jiffies(us: u32) -> u64 { div_ceil(us as u64 * KPI_HZ, USEC_PER_SEC) }
pub(super) extern "C" fn nsecs_to_jiffies(ns: u64) -> u64 { div_ceil(ns.saturating_mul(KPI_HZ), NSEC_PER_SEC) }
pub(super) extern "C" fn jiffies_to_msecs(j: u64) -> u32 { ((j.saturating_mul(MSEC_PER_SEC)) / KPI_HZ) as u32 }
pub(super) extern "C" fn jiffies_to_usecs(j: u64) -> u32 { ((j.saturating_mul(USEC_PER_SEC)) / KPI_HZ) as u32 }
pub(super) extern "C" fn round_jiffies(j: u64) -> u64 { j }
pub(super) extern "C" fn ktime_get() -> i64 { ktime_get_ns() }
pub(super) extern "C" fn ktime_get_ns() -> i64 { now_ns() as i64 }
pub(super) extern "C" fn ktime_get_with_offset(_offs: i32) -> i64 { ktime_get_ns() }
pub(super) extern "C" fn ktime_set(secs: i64, nsecs: u64) -> i64 { secs.saturating_mul(NSEC_PER_SEC as i64).saturating_add(nsecs as i64) }
pub(super) extern "C" fn ns_to_ktime(ns: i64) -> i64 { ns }
pub(super) extern "C" fn ktime_to_ns(kt: i64) -> i64 { kt }
pub(super) extern "C" fn ktime_add_ns(kt: i64, ns: u64) -> i64 { kt.saturating_add(ns as i64) }
pub(super) extern "C" fn ktime_sub_ns(kt: i64, ns: u64) -> i64 { kt.saturating_sub(ns as i64) }

pub(super) extern "C" fn ktime_get_ts64(ts: *mut LinuxTimespec64) { write_ts64(ts, now_ns()); }
pub(super) extern "C" fn ktime_get_raw_ts64(ts: *mut LinuxTimespec64) { write_ts64(ts, now_ns()); }
pub(super) extern "C" fn ktime_get_real_ts64(ts: *mut LinuxTimespec64) { write_ts64(ts, now_ns()); }

pub(super) extern "C" fn msleep(ms: u32) { sleep_ns(ms as u64 * NSEC_PER_MSEC); }
pub(super) extern "C" fn msleep_interruptible(ms: u32) -> u64 { msleep(ms); 0 }
pub(super) extern "C" fn usleep_range(min: u32, max: u32) { let _ = max; sleep_ns(min as u64 * NSEC_PER_USEC); }
pub(super) extern "C" fn usleep_range_state(min: u64, max: u64, state: u32) {
    let _ = (max, state);
    sleep_ns(min.saturating_mul(NSEC_PER_USEC));
}
pub(super) extern "C" fn udelay(us: u32) { busy_delay_ns(us as u64 * NSEC_PER_USEC); }
pub(super) extern "C" fn __const_udelay(xloops: u64) { busy_delay_ns(xloops / 4); }
pub(super) extern "C" fn mdelay(ms: u32) { busy_delay_ns(ms as u64 * NSEC_PER_MSEC); }
pub(super) extern "C" fn schedule_timeout(timeout: i64) -> i64 {
    if timeout > 0 { sleep_ns(jiffies_to_ns(timeout as u64)); }
    0
}
pub(super) extern "C" fn preempt_schedule_notrace() { schedule(); }

pub(super) extern "C" fn schedule() {
    #[cfg(target_os = "oxide-kernel")]
    unsafe {
        // SAFETY: caller requested a Linux schedule point in process/kthread context.
        sched::live::schedule();
    }
}

pub(super) fn sleep_ns(ns: u64) {
    if ns == 0 { return; }
    #[cfg(target_os = "oxide-kernel")]
    {
        let wait = sched::live::WaitList::new();
        let deadline = now_ns().saturating_add(ns);
        let id = timer::register_oneshot(deadline, &wait as *const _ as usize, wake_sleep);
        // SAFETY: stack wait list remains alive until this task is woken and schedule returns.
        unsafe { wait.park(); sched::live::schedule(); }
        // `wait` is a STACK-LOCAL on this task's kernel-stack Box (kalloc STATIC_HEAP),
        // and the park above is SIGNAL-INTERRUPTIBLE (`wake_if_sleeping` rouses any
        // Sleeping task) — so schedule() can return BEFORE `deadline`. Without this
        // cancel, the one-shot stays queued in `timer::ONESHOTS` pointing at `&wait`;
        // once this fn returns `wait` dies and, if the task then exits, its kernel
        // stack Box is freed back to STATIC_HEAP — where `wake_sleep`'s later
        // `(*wait).wake_all()` (a `Spinlock` CAS at offset 0 of the freed block) would
        // scribble the free-list header of whatever now occupies that slot: the exact
        // CPU stale-kernel-pointer static-heap UAF (`size=0` etc.). Cancel it now so it
        // can never fire after `wait` is gone. (Idempotent no-op if it already fired
        // at the deadline, which happens only while `wait` was still parked + alive.)
        timer::unregister_oneshot(id);
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    {
        FALLBACK_NS.fetch_add(ns, Ordering::AcqRel);
        publish_jiffies();
    }
}

#[cfg(target_os = "oxide-kernel")]
fn wake_sleep(arg: usize) {
    let wait = arg as *const sched::live::WaitList;
    if wait.is_null() { return; }
    // SAFETY: sleep_ns keeps the stack wait list alive until this callback wakes it.
    unsafe { (*wait).wake_all(); }
}

pub(super) fn busy_delay_ns(ns: u64) {
    let end = now_ns().saturating_add(ns);
    while now_ns() < end { core::hint::spin_loop(); }
}

pub(super) fn now_ns() -> u64 {
    let p = NOW_HOOK.load(Ordering::Acquire);
    let ns = if p.is_null() {
        FALLBACK_NS.load(Ordering::Acquire)
    } else {
        // SAFETY: hook installed by set_now_hook with matching fn() -> u64 ABI.
        let f: NowHook = unsafe { core::mem::transmute(p) };
        f()
    };
    publish_jiffies_from(ns);
    ns
}

#[cfg(not(target_os = "oxide-kernel"))]
fn publish_jiffies() { publish_jiffies_from(FALLBACK_NS.load(Ordering::Acquire)); }

fn publish_jiffies_from(ns: u64) {
    let j = nsecs_to_jiffies(ns);
    jiffies.store(j, Ordering::Release);
    jiffies_64.store(j, Ordering::Release);
}

pub(super) fn jiffies_to_ns(j: u64) -> u64 { j.saturating_mul(NSEC_PER_SEC / KPI_HZ) }
fn div_ceil(n: u64, d: u64) -> u64 { if n == 0 { 0 } else { ((n - 1) / d) + 1 } }

fn write_ts64(ts: *mut LinuxTimespec64, ns: u64) {
    if ts.is_null() { return; }
    // SAFETY: non-null pointer names caller-owned timespec64 storage.
    unsafe {
        (*ts).tv_sec = (ns / NSEC_PER_SEC) as i64;
        (*ts).tv_nsec = (ns % NSEC_PER_SEC) as i64;
    }
}
