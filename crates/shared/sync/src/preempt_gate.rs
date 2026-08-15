// The preemption gate every spinning lock in this crate takes, and the reason
// it exists.
//
// A spinning lock is only correct while its owner keeps running. The reference
// makes that structural rather than hopeful: `spin_lock` is
// `preempt_disable()` + the acquire, and `spin_unlock` is the release +
// `preempt_enable()`, so an owner CANNOT be descheduled inside its critical
// section. On a uniprocessor build the acquire itself compiles away entirely
// and the preempt-disable IS the lock.
//
// Without it, an owner that reaches ANY voluntary reschedule point inside the
// section — a `local_bh_enable` at the end of a nested bottom-half section, a
// `preempt_enable` returning to zero with a pending request — gives up the CPU
// still holding the lock. Every later acquirer then spins for a lock whose
// owner is not running. With a second CPU a peer picks the owner up and the
// window closes in microseconds, which is why the shape survives an SMP boot;
// with one CPU nothing can run the owner, and if any spinner in the resulting
// chain masks interrupts the machine stops taking ticks altogether.
//
// The count itself belongs to the scheduler, which sits ABOVE this crate in
// the dependency order, so the gate is installed as a pair of function
// pointers — the same shape `spin_relax`, the RCU CPU hooks and the lockdep
// context hook already use. Uninstalled (hosted tests, early boot before the
// scheduler exists) it is inert, and preemption cannot happen there anyway.
//
// PAIRING: `acquire` returns the release half it just used, and every guard
// carries that value to its `Drop`. A lock taken before the ops are installed
// therefore releases with the same (absent) ops it acquired with, so an
// installation that lands mid-critical-section can never produce an unmatched
// decrement.

use core::sync::atomic::{AtomicPtr, Ordering};
#[cfg(feature = "debug-preempt")]
use core::sync::atomic::{AtomicU16, AtomicU8};
#[cfg(feature = "debug-preempt")]
use core::panic::Location;

/// The scheduler's preempt-count pair, as this crate's locks use it.
/// `disable` must raise the count by exactly one and `enable` must lower it by
/// exactly one WITHOUT taking a reschedule — a spin lock release is not a
/// schedule point in this kernel, and the pending request is taken at the next
/// natural one (return-to-user, `local_bh_enable`, `preempt_enable`).
#[derive(Clone, Copy)]
pub struct PreemptOps {
    /// Linux `preempt_disable`.
    pub disable: fn(),
    /// Linux `preempt_enable_no_resched`.
    pub enable: fn(),
}

static OPS: AtomicPtr<PreemptOps> = AtomicPtr::new(core::ptr::null_mut());

/// Debug-only current-CPU hook. Kept separate from `PreemptOps` so ordinary
/// clients retain the stable two-function preemption gate contract.
#[cfg(feature = "debug-preempt")]
static CPU_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Held-lock trace per CPU. The trace uses a fixed acquisition stack; overflow
/// stays explicit rather than silently turning a diagnostic into a wrong rank.
#[cfg(feature = "debug-preempt")]
const HELD_LOCK_DEPTH: usize = 48;

#[cfg(feature = "debug-preempt")]
static HELD_RANKS: [[AtomicU16; HELD_LOCK_DEPTH]; crate::MAX_CPUS] =
    [const { [const { AtomicU16::new(0) }; HELD_LOCK_DEPTH] }; crate::MAX_CPUS];
#[cfg(feature = "debug-preempt")]
static HELD_DEPTH: [AtomicU8; crate::MAX_CPUS] = [const { AtomicU8::new(0) }; crate::MAX_CPUS];
#[cfg(feature = "debug-preempt")]
static HELD_OVERFLOW: [AtomicU8; crate::MAX_CPUS] = [const { AtomicU8::new(0) }; crate::MAX_CPUS];

/// Where each held frame was acquired, as a `&'static Location` the compiler
/// supplies through `#[track_caller]`. A rank names a lock CLASS, and a class
/// has many call sites — the site is what turns "something at rank 100" into
/// the line to read. Captured with no stack walking: a frame-pointer walk from
/// inside the allocator faulted the guest twice before this shape replaced it.
#[cfg(feature = "debug-preempt")]
static HELD_SITES: [[AtomicPtr<Location<'static>>; HELD_LOCK_DEPTH]; crate::MAX_CPUS] =
    [const { [const { AtomicPtr::new(core::ptr::null_mut()) }; HELD_LOCK_DEPTH] }; crate::MAX_CPUS];

#[cfg(feature = "debug-preempt")]
fn cpu_slot(cpu: usize) -> usize { cpu.min(crate::MAX_CPUS - 1) }

#[cfg(feature = "debug-preempt")]
#[inline(never)]
fn trace_push(cpu: usize, rank: u16, site: &'static Location<'static>) {
    let cpu = cpu_slot(cpu);
    let depth = HELD_DEPTH[cpu].load(Ordering::Relaxed) as usize;
    if depth < HELD_LOCK_DEPTH {
        HELD_RANKS[cpu][depth].store(rank, Ordering::Relaxed);
        HELD_SITES[cpu][depth].store(site as *const _ as *mut _, Ordering::Relaxed);
        HELD_DEPTH[cpu].store((depth + 1) as u8, Ordering::Relaxed);
    } else {
        HELD_OVERFLOW[cpu].fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(feature = "debug-preempt")]
#[inline(never)]
fn trace_pop(cpu: usize) {
    let cpu = cpu_slot(cpu);
    let overflow = HELD_OVERFLOW[cpu].load(Ordering::Relaxed);
    if overflow != 0 {
        HELD_OVERFLOW[cpu].store(overflow - 1, Ordering::Relaxed);
        return;
    }
    let depth = HELD_DEPTH[cpu].load(Ordering::Relaxed);
    if depth == 0 { return; }
    HELD_DEPTH[cpu].store(depth - 1, Ordering::Relaxed);
}

#[cfg(feature = "debug-preempt")]
fn installed_cpu() -> usize {
    let p = CPU_HOOK.load(Ordering::Acquire);
    if p.is_null() { return 0; }
    // SAFETY: the hook is installed once from a static fn and never freed.
    let f: fn() -> usize = unsafe { core::mem::transmute(p) };
    f()
}

/// The innermost held lock class rank on this CPU, 0 when none. # C: O(1)
#[cfg(feature = "debug-preempt")]
pub fn held_rank() -> u16 {
    let cpu = cpu_slot(installed_cpu());
    let depth = HELD_DEPTH[cpu].load(Ordering::Relaxed);
    if depth == 0 { return 0; }
    HELD_RANKS[cpu][(depth - 1) as usize].load(Ordering::Relaxed)
}

/// Print every held frame on this CPU as `rank@file:line`, outermost first.
///
/// The innermost rank alone cannot answer "which two locks is this path
/// holding" — that is the question every sleep-while-atomic report raises, and
/// the one that cost a whole session of guessing. # C: O(depth)
#[cfg(feature = "debug-preempt")]
pub fn write_held_stack() {
    let cpu = cpu_slot(installed_cpu());
    let depth = HELD_DEPTH[cpu].load(Ordering::Relaxed) as usize;
    klog::write_raw(b" held=[");
    for i in 0..depth.min(HELD_LOCK_DEPTH) {
        if i != 0 { klog::write_raw(b" "); }
        klog::write_dec_u64(HELD_RANKS[cpu][i].load(Ordering::Relaxed) as u64);
        let site = HELD_SITES[cpu][i].load(Ordering::Relaxed);
        if site.is_null() { continue; }
        // SAFETY: the slot only ever holds a `&'static Location` the compiler
        // materialised for a `#[track_caller]` call site, which lives for the
        // program's lifetime; it is never freed and never rewritten to a
        // non-Location value.
        let site = unsafe { &*site };
        klog::write_raw(b"@");
        klog::write_raw(site.file().as_bytes());
        klog::write_raw(b":");
        klog::write_dec_u64(site.line() as u64);
    }
    klog::write_raw(b"]");
}

/// Snapshot the current CPU's diagnostic lock trace: innermost rank, tracked
/// depth, and overflowed frames. # C: O(1)
#[cfg(feature = "debug-preempt")]
pub fn held_trace() -> (u16, u8, u8) {
    let cpu = cpu_slot(installed_cpu());
    (held_rank(), HELD_DEPTH[cpu].load(Ordering::Relaxed),
     HELD_OVERFLOW[cpu].load(Ordering::Relaxed))
}

/// Diagnostic gate state paired with one spinning-lock acquisition.
#[cfg(feature = "debug-preempt")]
#[derive(Clone, Copy)]
pub(crate) struct PreemptToken {
    enable: Option<fn()>,
}

/// The normal guard remains the original callback shape.  Lock tracing is a
/// debug-only addition and must not enlarge normal startup call chains.
#[cfg(not(feature = "debug-preempt"))]
pub(crate) type PreemptToken = Option<fn()>;

/// Install the preempt gate. Boot path, once, as soon as the preempt count is
/// usable and before the first reschedule can be taken.
/// # C: O(1)
pub fn set_preempt_ops(ops: &'static PreemptOps) {
    OPS.store(ops as *const PreemptOps as *mut PreemptOps, Ordering::Release);
}

/// Install the debug current-CPU hook before the first lock diagnostic.
/// # C: O(1)
#[cfg(feature = "debug-preempt")]
pub fn set_debug_cpu_hook(f: fn() -> usize) {
    CPU_HOOK.store(f as *mut (), Ordering::Release);
}

/// Enter a normal spinning-lock critical section and return its release half.
/// # C: O(1)
#[cfg(not(feature = "debug-preempt"))]
#[inline]
pub(crate) fn acquire(_rank: u16) -> PreemptToken {
    let p = OPS.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: OPS is only ever written by set_preempt_ops from a &'static
    // PreemptOps, so a non-null value is a live 'static pointer to a Copy
    // struct of fn pointers.
    let ops = unsafe { *p };
    (ops.disable)();
    Some(ops.enable)
}

/// Enter a diagnostic spinning-lock critical section. A regular spin guard
/// cannot migrate while its preemption level is raised, so release reads the
/// same current-CPU slot without enlarging every guard. # C: O(1)
#[cfg(feature = "debug-preempt")]
#[inline]
#[track_caller]
pub(crate) fn acquire(rank: u16) -> PreemptToken {
    let site = Location::caller();
    let p = OPS.load(Ordering::Acquire);
    if p.is_null() {
        trace_push(0, rank, site);
        return PreemptToken { enable: None };
    }
    // SAFETY: OPS is only ever written by set_preempt_ops from a &'static
    // PreemptOps, so a non-null value is a live 'static pointer to a Copy
    // struct of fn pointers.
    let ops = unsafe { *p };
    (ops.disable)();
    let cpu = cpu_slot(installed_cpu());
    trace_push(cpu, rank, site);
    PreemptToken { enable: Some(ops.enable) }
}

/// Join the held-lock trace WITHOUT touching the count.
///
/// A `lock_bh` acquisition raises only the softirq field — the reference's
/// `spin_lock_bh` does the same, and adding a preempt level here would make
/// this kernel's count disagree with it. But a diagnostic that cannot see the
/// section is worse than useless: a sleep taken inside one reported `held=[]`
/// and named no lock at all, which is the report the boot wedge produces.
/// The returned token carries no enable half, so its release pops the trace
/// and nothing else.
/// # C: O(1)
#[cfg(feature = "debug-preempt")]
#[inline]
#[track_caller]
pub(crate) fn acquire_trace_only(rank: u16) -> PreemptToken {
    trace_push(cpu_slot(installed_cpu()), rank, Location::caller());
    PreemptToken { enable: None }
}

/// Without the diagnostic there is no trace to join. # C: O(1)
#[cfg(not(feature = "debug-preempt"))]
#[inline]
pub(crate) fn acquire_trace_only(_rank: u16) -> PreemptToken { None }

/// Leave a spinning-lock critical section with the release half `acquire`
/// returned. Called after the lock word is released, so a reschedule taken at
/// the next natural point never finds this lock held.
/// # C: O(1)
#[cfg(not(feature = "debug-preempt"))]
#[inline]
pub(crate) fn release(token: PreemptToken) {
    if let Some(f) = token { f(); }
}

/// Leave a diagnostic spinning-lock critical section. # C: O(1)
#[cfg(feature = "debug-preempt")]
#[inline]
pub(crate) fn release(token: PreemptToken) {
    trace_pop(installed_cpu());
    if let Some(f) = token.enable { f(); }
}

/// The installed normal release half for a forgotten runqueue guard.
/// # C: O(1)
#[cfg(not(feature = "debug-preempt"))]
#[inline]
pub(crate) fn installed_release() -> PreemptToken {
    let p = OPS.load(Ordering::Acquire);
    if p.is_null() { return None; }
    // SAFETY: the installed ops are static and live for the kernel lifetime.
    Some((unsafe { *p }).enable)
}

/// The installed release half, for the ONE release that cannot carry its own:
/// `Spinlock::raw_unlock`, where the acquiring task forgot its guard and a
/// different task performs the release (the runqueue lock across a context
/// switch). Sound because the ops are installed once, during boot, long before
/// the first switch.
/// # C: O(1)
#[cfg(feature = "debug-preempt")]
#[inline]
pub(crate) fn release_forgotten() {
    trace_pop(installed_cpu());
    let p = OPS.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: same contract as `acquire` — non-null implies a live 'static
    // PreemptOps written by set_preempt_ops.
    (unsafe { *p }.enable)();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Buddy, Spinlock};
    #[cfg(feature = "debug-preempt")]
    use crate::LockClass;

    // Per-THREAD depth: `OPS` is global, so while these ops are installed every
    // sibling test's lock traffic runs them too. A process-wide counter reads
    // their acquisitions as this test's.
    std::thread_local! {
        static DEPTH: core::cell::Cell<i64> = const { core::cell::Cell::new(0) };
        static MIN_DEPTH: core::cell::Cell<i64> = const { core::cell::Cell::new(0) };
    }
    fn up() { DEPTH.with(|d| d.set(d.get() + 1)); }
    fn down() {
        DEPTH.with(|d| {
            let next = d.get() - 1;
            d.set(next);
            MIN_DEPTH.with(|m| if next < m.get() { m.set(next) });
        });
    }
    fn depth() -> i64 { DEPTH.with(core::cell::Cell::get) }
    #[cfg(feature = "debug-preempt")]
    std::thread_local! {
        static CPU: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
    }
    #[cfg(feature = "debug-preempt")]
    fn current_cpu() -> usize { CPU.with(core::cell::Cell::get) }
    #[cfg(feature = "debug-preempt")]
    fn set_cpu(cpu: usize) { CPU.with(|c| c.set(cpu)); }

    static COUNTING: PreemptOps = PreemptOps {
        disable: up,
        enable: down,
    };

    fn with_ops<R>(f: impl FnOnce() -> R) -> R {
        DEPTH.with(|d| d.set(0));
        MIN_DEPTH.with(|m| m.set(0));
        #[cfg(feature = "debug-preempt")]
        set_debug_cpu_hook(current_cpu);
        set_preempt_ops(&COUNTING);
        let r = f();
        OPS.store(core::ptr::null_mut(), Ordering::Release);
        #[cfg(feature = "debug-preempt")]
        CPU_HOOK.store(core::ptr::null_mut(), Ordering::Release);
        r
    }

    #[test]
    fn a_held_spinlock_keeps_preemption_disabled_for_the_whole_section() {
        with_ops(|| {
            let lk: Spinlock<u32, Buddy> = Spinlock::new(0);
            assert_eq!(depth(), 0);
            {
                let mut g = lk.lock();
                assert_eq!(depth(), 1, "spin_lock must disable preemption");
                *g = 5;
                assert_eq!(depth(), 1);
            }
            assert_eq!(depth(), 0, "spin_unlock must re-enable preemption");
            assert_eq!(MIN_DEPTH.with(core::cell::Cell::get), 0,
                "the release ran before its matching disable");
        });
    }

    #[test]
    fn try_lock_gates_preemption_only_when_it_succeeds() {
        with_ops(|| {
            let lk: Spinlock<u32, Buddy> = Spinlock::new(0);
            let held = lk.lock();
            assert_eq!(depth(), 1);
            assert!(lk.try_lock().is_none());
            assert_eq!(depth(), 1, "a failed try_lock must not leave preemption off");
            drop(held);
            let got = lk.try_lock().expect("free lock");
            assert_eq!(depth(), 1);
            drop(got);
            assert_eq!(depth(), 0);
        });
    }

    #[test]
    fn a_forgotten_guard_released_by_raw_unlock_still_balances() {
        // The runqueue lock's cross-task handoff: acquire, forget the guard,
        // and release from `raw_unlock`. The count must come back to zero, or
        // every context switch leaks one preempt level and the CPU stops
        // rescheduling for good.
        with_ops(|| {
            let lk: Spinlock<u32, crate::TaskList> = Spinlock::new(0);
            core::mem::forget(lk.lock());
            assert_eq!(depth(), 1);
            #[cfg(feature = "debug-preempt")]
            assert_eq!(held_rank(), crate::TaskList::rank());
            // SAFETY: exactly one forgotten guard holds this lock.
            unsafe { lk.raw_unlock(); }
            assert_eq!(depth(), 0);
            #[cfg(feature = "debug-preempt")]
            assert_eq!(held_rank(), 0);
            assert!(lk.try_lock().is_some());
        });
    }

    #[test]
    fn an_uninstalled_gate_is_inert() {
        OPS.store(core::ptr::null_mut(), Ordering::Release);
        DEPTH.with(|d| d.set(0));
        let lk: Spinlock<u32, Buddy> = Spinlock::new(0);
        drop(lk.lock());
        assert_eq!(depth(), 0);
    }

    #[cfg(feature = "debug-preempt")]
    #[test]
    fn held_rank_is_per_cpu_and_restores_the_outer_lock() {
        with_ops(|| {
            set_cpu(0);
            let outer: Spinlock<u32, crate::TaskList> = Spinlock::new(0);
            let inner: Spinlock<u32, crate::TaskWake> = Spinlock::new(0);
            let _outer = outer.lock();
            assert_eq!(held_rank(), crate::TaskList::rank());
            {
                let _inner = inner.lock();
                assert_eq!(held_rank(), crate::TaskWake::rank());
            }
            assert_eq!(held_rank(), crate::TaskList::rank());

            let peer = std::thread::spawn(|| {
                set_cpu(1);
                let other: Spinlock<u32, crate::Tty> = Spinlock::new(0);
                let _other = other.lock();
                assert_eq!(held_rank(), crate::Tty::rank());
            });
            peer.join().unwrap();
            assert_eq!(held_rank(), crate::TaskList::rank(),
                "a peer CPU must not overwrite this CPU's diagnostic stack");
        });
    }
}
