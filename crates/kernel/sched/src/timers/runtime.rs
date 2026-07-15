use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use crate::timer_model::{next_programmed_interrupt, project_deadline, ClockSpec, Expiration,
    Notify, PosixTimer};
use crate::{SigInfo, Task};

use super::{backend, clock};

const SI_TIMER: i32 = -2;
pub const ACCOUNTING_TICK_NS: u64 = 10_000_000;

type ProgramDeadline = fn(u64);

static EARLIEST_WALL_NS: AtomicU64 = AtomicU64::new(u64::MAX);
static PROGRAM_DEADLINE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

fn pending(current: &Task, notify: Notify) -> bool {
    let Notify::Signal { signo, target_tid, .. } = notify else { return false };
    if !(1..=64).contains(&signo) { return false; }
    if target_tid == 0 {
        return current.sigpending.load(Ordering::Acquire) & (1u64 << (signo - 1)) != 0;
    }
    crate::registry::lookup(target_tid).map(|task|
        task.sigpending.load(Ordering::Acquire) & (1u64 << (signo - 1)) != 0).unwrap_or(false)
}

fn post_to(target: &Task, event: Expiration, wake: bool) {
    if event.signo >= 33 {
        let _ = target.rt_push(SigInfo {
            signo: event.signo, code: SI_TIMER, pid: 0, uid: 0, value: event.value,
        });
    }
    target.sigpending.fetch_or(1u64 << (event.signo - 1), Ordering::Release);
    if wake {
        if let Some(target) = crate::registry::lookup(target.tid) {
            // SAFETY: timer tick is an IRQ wake site and the registry Arc pins target.
            unsafe { crate::live::ttwu::ttwu_deferred(target); }
        }
    }
}

fn post(current: &Task, event: Expiration, wake: bool) {
    if event.target_tid == 0 {
        post_to(current, event, wake);
    } else if let Some(target) = crate::registry::lookup(event.target_tid) {
        post_to(&target, event, wake);
    }
}

fn service_wake(timer: &mut PosixTimer, current: &Task, wake: bool) {
    let Some(now) = clock::now_ns(timer.domain) else { return };
    if let Some(event) = timer.expire(now, pending(current, timer.notify)) {
        post(current, event, wake);
    }
}

pub(super) fn service(timer: &mut PosixTimer, current: &Task) {
    service_wake(timer, current, false);
}

pub(super) fn setting(timer: &mut PosixTimer, current: &Task) -> crate::timer_model::TimerSetting {
    service(timer, current);
    let now = clock::now_ns(timer.domain).unwrap_or(0);
    timer.setting(now, pending(current, timer.notify))
}

pub(super) fn overrun(timer: &mut PosixTimer, current: &Task) -> i64 {
    service(timer, current);
    let now = clock::now_ns(timer.domain).unwrap_or(0);
    timer.overrun_last(now, pending(current, timer.notify))
}

/// Service every POSIX timer owned by the current thread group. # C: O(SLOTS)
pub fn fire_due_timers() {
    let Some(current) = crate::live::current() else { return };
    let owner = clock::timer_owner(current);
    let _guard = backend::lock();
    // SAFETY: STATE serializes all process-wide POSIX timer slot access.
    let slots = unsafe { &mut *owner.task().posix_timers.get() };
    for timer in slots.iter_mut().filter(|timer| timer.allocated) { service(timer, current); }
}

fn cpu_clock_runs_for(clock: ClockSpec, current: &Task) -> bool {
    let ClockSpec::Cpu(cpu) = clock else { return false };
    if cpu.per_thread { cpu.target == current.tid }
    else { cpu.target == current.tgid.load(Ordering::Acquire) }
}

/// Evaluate CPU timers immediately after scheduler tick accounting. # C: O(SLOTS)
/// # Ctx: timer IRQ
pub fn account_cpu_tick(current: &Task) {
    let owner = clock::timer_owner(current);
    let Some(_guard) = backend::try_lock() else { return };
    // SAFETY: STATE try-lock serializes process timer slots without blocking IRQ context.
    let slots = unsafe { &mut *owner.task().posix_timers.get() };
    for timer in slots.iter_mut().filter(|timer|
        timer.allocated && cpu_clock_runs_for(timer.domain, current))
    {
        service_wake(timer, current, true);
    }
}

fn program(deadline_ns: u64) {
    let raw = PROGRAM_DEADLINE.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: install_deadline_programmer stores only a ProgramDeadline function pointer.
    let f: ProgramDeadline = unsafe { core::mem::transmute(raw) };
    f(deadline_ns);
}

fn scan_wall_locked(fire: bool) -> u64 {
    let mono = clock::monotonic_now_ns();
    let mut earliest = u64::MAX;
    for tid in crate::registry::live_tids() {
        let Some(task) = crate::registry::lookup(tid) else { continue };
        if task.tgid.load(Ordering::Acquire) != task.tid { continue; }
        // SAFETY: caller holds backend STATE across every process timer slot access.
        let slots = unsafe { &mut *task.posix_timers.get() };
        for timer in slots.iter_mut().filter(|timer|
            timer.allocated && !matches!(timer.domain, ClockSpec::Cpu(_)))
        {
            if fire { service_wake(timer, &task, true); }
            let deadline = timer.armed_deadline();
            if deadline == 0 { continue; }
            let Some(now) = clock::now_ns(timer.domain) else { continue };
            earliest = earliest.min(project_deadline(deadline, now, mono));
        }
    }
    earliest
}

fn publish_earliest(deadline_ns: u64) {
    EARLIEST_WALL_NS.store(deadline_ns, Ordering::Release);
}

/// Install architecture-local one-shot programming. # C: O(1)
pub fn install_deadline_programmer(f: fn(u64)) {
    PROGRAM_DEADLINE.store(f as *const () as *mut (), Ordering::Release);
}

/// Recompute wall timers and program the earliest advancing POSIX clock. # C: O(N_tasks * SLOTS)
pub fn reprogram_posix_timers() {
    let _guard = backend::lock();
    let earliest = scan_wall_locked(false);
    publish_earliest(earliest);
    drop(_guard);
    program(next_interrupt_deadline());
}

fn current_cpu_deadline(mono_ns: u64) -> u64 {
    let Some(current) = crate::live::current() else { return u64::MAX };
    let owner = clock::timer_owner(current);
    let Some(_guard) = backend::try_lock() else { return u64::MAX };
    // SAFETY: STATE try-lock serializes process timer slots in IRQ and process contexts.
    let slots = unsafe { &mut *owner.task().posix_timers.get() };
    let mut earliest = u64::MAX;
    for timer in slots.iter_mut().filter(|timer|
        timer.allocated && cpu_clock_runs_for(timer.domain, current))
    {
        let deadline = timer.armed_deadline();
        if deadline == 0 { continue; }
        let Some(now) = clock::now_ns(timer.domain) else { continue };
        earliest = earliest.min(project_deadline(deadline, now, mono_ns));
    }
    earliest
}

/// Service due wall timers from the hardware timer IRQ. # C: O(1) or O(N_tasks * SLOTS)
/// # Ctx: timer IRQ
pub fn wall_timer_interrupt() {
    let now = clock::monotonic_now_ns();
    if EARLIEST_WALL_NS.load(Ordering::Acquire) > now { return; }
    let Some(_guard) = backend::try_lock() else { return };
    let earliest = scan_wall_locked(true);
    publish_earliest(earliest);
}

/// Next hardware interrupt, bounded by CPU accounting precision. # C: O(SLOTS * N_threads)
pub fn next_interrupt_deadline() -> u64 {
    let now = clock::monotonic_now_ns();
    let advancing = EARLIEST_WALL_NS.load(Ordering::Acquire)
        .min(current_cpu_deadline(now));
    next_programmed_interrupt(now, advancing, ACCOUNTING_TICK_NS)
}
