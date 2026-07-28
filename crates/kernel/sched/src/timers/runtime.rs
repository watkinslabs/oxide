use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use crate::timer_model::{advance_tick, next_programmed_interrupt, project_deadline, ClockSpec,
    Expiration, Notify, PosixTimer};
use crate::{SigInfo, Task};

use super::{backend, clock};

const SI_TIMER: i32 = -2;
/// One owner for the tick period: `clock_getres` reports it for the COARSE
/// clocks, so the two can never disagree.
pub const ACCOUNTING_TICK_NS: u64 = crate::posix_clock::TICK_NSEC;

type ProgramDeadline = fn(u64);

static EARLIEST_WALL_NS: AtomicU64 = AtomicU64::new(u64::MAX);
static PROGRAM_DEADLINE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Per-CPU absolute expiry of the accounting tick (Linux `ts->sched_timer`).
/// Owned by [`tick_deadline`], which only ever moves it FORWARD past a `now`
/// that has already reached it — the property that makes a reprogram from an
/// unrelated caller unable to postpone the tick (B1455).
static NEXT_TICK_NS: [AtomicU64; cpu::MAX_CPUS] =
    [const { AtomicU64::new(0) }; cpu::MAX_CPUS];

/// This CPU's accounting-tick expiry, advanced when `now` has reached it.
/// # C: O(1)
/// # Ctx: IRQ or process, local CPU
fn tick_deadline(now_ns: u64) -> u64 {
    let slot = &NEXT_TICK_NS[crate::cpustat::this_cpu()];
    let mut cur = slot.load(Ordering::Relaxed);
    loop {
        let next = advance_tick(cur, now_ns, ACCOUNTING_TICK_NS);
        if next == cur { return cur; }
        match slot.compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return next,
            // A concurrent tick on this CPU already advanced it; re-read rather
            // than clobber, so the deadline never moves backwards.
            Err(observed) => cur = observed,
        }
    }
}

fn pending(current: &Task, notify: Notify) -> bool {
    let Notify::Signal { signo, target_tid, .. } = notify else { return false };
    let Some(bit) = crate::bit_for(signo) else { return false; };
    if target_tid == 0 {
        return current.sigpending.load(Ordering::Acquire) & bit != 0;
    }
    crate::registry::lookup(target_tid).map(|task|
        task.sigpending.load(Ordering::Acquire) & bit != 0).unwrap_or(false)
}

fn post_to(target: &Task, event: Expiration, wake: bool) {
    if crate::signum::is_realtime(event.signo) {
        let _ = target.sigq_push(SigInfo {
            signo: event.signo, code: SI_TIMER, pid: 0, uid: 0, value: event.value, sys: None,
        });
    }
    if let Some(bit) = crate::bit_for(event.signo) {
        target.sigpending.fetch_or(bit, Ordering::Release);
    }
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
    // `now_ns_for`, not `now_ns`: this runs from `account_cpu_tick` in hard-IRQ
    // context, where `registry::lookup` is forbidden (`06§3.1`) and where a
    // failed lookup would silently skip the wake forever.
    let Some(now) = clock::now_ns_for(timer.domain, current) else { return };
    // Linux `cpu_timer_fire` (`posix-cpu-timers.c:682-688`): a `clock_nanosleep`
    // timer wakes its sleeper and disarms, rather than queueing a signal. This
    // runs from `account_cpu_tick` on the RUNNING task, which is the only thing
    // that can advance a CPU clock — a sleeping task accrues no CPU time, so a
    // sibling's tick is what releases it.
    if let Notify::Wake { tid } = timer.notify {
        if timer.deadline_ns != 0 && now >= timer.deadline_ns {
            timer.deadline_ns = 0;
            wake_sleeper(tid);
        }
        return;
    }
    if let Some(event) = timer.expire(now, pending(current, timer.notify)) {
        post(current, event, wake);
    }
}

/// `wake_up_process(timer->it_process)` — IRQ-safe, same deferred path the
/// signal post uses.
/// # C: O(1)
fn wake_sleeper(tid: u32) {
    if let Some(target) = crate::registry::lookup(tid) {
        // SAFETY: timer tick is an IRQ wake site and the registry Arc pins target.
        unsafe { crate::live::ttwu::ttwu_deferred(target); }
    }
}

fn wall_entry(owner_tid: u32, timer_id: usize, timer: &PosixTimer,
    owner: alloc::sync::Weak<Task>) -> Option<backend::WallEntry>
{
    if !timer.allocated || super::cpu_nanosleep::is_cpu_clock(timer.domain) { return None; }
    let deadline = timer.armed_deadline();
    if deadline == 0 { return None; }
    let now = clock::now_ns(timer.domain)?;
    Some(backend::WallEntry {
        deadline_ns: project_deadline(deadline, now, clock::monotonic_now_ns()),
        owner_tid,
        timer_id,
        owner,
    })
}

pub(super) fn sync_wall_locked(state: &mut backend::State, owner_tid: u32,
    timer_id: usize, timer: &PosixTimer, owner: alloc::sync::Weak<Task>)
{
    state.wall.upsert(wall_entry(owner_tid, timer_id, timer, owner), owner_tid, timer_id);
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
    let mut guard = backend::lock();
    // SAFETY: STATE serializes all process-wide POSIX timer slot access.
    let slots = unsafe { &mut *current.thread_group.posix_timers.get() };
    for (timer_id, timer) in slots.iter_mut().enumerate().filter(|(_, timer)| timer.allocated) {
        service(timer, owner.task());
        sync_wall_locked(&mut guard, owner.task().tid, timer_id, timer, owner.weak());
    }
    drop(guard);
    program(next_interrupt_deadline());
}

/// One owner with [`clock::now_ns_for`]'s registry-free branch: the filter
/// here is exactly the condition that makes sampling off `current` valid.
fn cpu_clock_runs_for(clock: ClockSpec, current: &Task) -> bool {
    clock::cpu_clock_names(clock, current)
}

/// Evaluate CPU timers immediately after scheduler tick accounting. # C: O(SLOTS)
/// # Ctx: timer IRQ
pub fn account_cpu_tick(current: &Task) {
    // No `timer_owner` here: this runs in hard-IRQ context on every tick, and
    // resolving the group leader went through `registry::lookup` -> `REG.lock()`
    // plus an O(N) scan. `REG` is a plain lock held by fork/exit/execve with
    // IRQs enabled, so the tick could preempt a holder and wedge the CPU
    // (`06§3.1`). The slots now live on the thread group every task already
    // holds an `Arc` to, and a group-directed timer signal may be delivered to
    // any thread of the group — Linux `group_send_sig_info` — so `current` is
    // the correct target as well as the lookup-free one.
    let Some(_guard) = backend::try_lock() else { return };
    // SAFETY: STATE try-lock serializes process timer slots without blocking IRQ context.
    let slots = unsafe { &mut *current.thread_group.posix_timers.get() };
    for timer in slots.iter_mut().filter(|timer|
        timer.allocated && cpu_clock_runs_for(timer.domain, current))
    {
        service_wake(timer, current, true);
    }
}

/// Last deadline handed to the hardware per CPU, so a reprogram that resolves
/// to the already-armed expiry skips the LVT + MSR writes. `fire_due_timers`
/// reprograms on every syscall return; without this the arm cost rode every
/// syscall. A cached deadline that `now` has passed is re-armed regardless —
/// the hardware disarms itself once it fires, so a stale cache must not be
/// mistaken for an armed timer.
static ARMED_NS: [AtomicU64; cpu::MAX_CPUS] = [const { AtomicU64::new(0) }; cpu::MAX_CPUS];

fn program(deadline_ns: u64) {
    let raw = PROGRAM_DEADLINE.load(Ordering::Acquire);
    if raw.is_null() { return; }
    let slot = &ARMED_NS[crate::cpustat::this_cpu()];
    if slot.load(Ordering::Relaxed) == deadline_ns
        && deadline_ns > clock::monotonic_now_ns() { return; }
    slot.store(deadline_ns, Ordering::Relaxed);
    // SAFETY: install_deadline_programmer stores only a ProgramDeadline function pointer.
    let f: ProgramDeadline = unsafe { core::mem::transmute(raw) };
    f(deadline_ns);
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
    let guard = backend::lock();
    publish_earliest(guard.wall.earliest_ns());
    drop(guard);
    program(next_interrupt_deadline());
}

/// Reproject absolute realtime/TAI timers after a wall-clock adjustment.
/// Runs in process context; the timer IRQ only consumes the ordered queue.
pub fn clock_was_set() {
    let mut guard = backend::lock();
    guard.wall.reproject(|entry| {
        let owner = crate::registry::lookup(entry.owner_tid)?;
        // SAFETY: backend STATE serializes every process timer slot access.
        let slots = unsafe { &mut *owner.thread_group.posix_timers.get() };
        wall_entry(entry.owner_tid, entry.timer_id, slots.get(entry.timer_id)?,
            entry.owner.clone())
            .map(|projected| projected.deadline_ns)
    });
    publish_earliest(guard.wall.earliest_ns());
    drop(guard);
    program(next_interrupt_deadline());
}

fn current_cpu_deadline(mono_ns: u64) -> u64 {
    let Some(current) = crate::live::current() else { return u64::MAX };
    // Reached from `deadline::rearm_local` in hard-IRQ context on every tick. It only
    // ever needed the slots, never the leader task, so the `timer_owner`
    // lookup here was pure `REG` contention on the hottest path in the kernel.
    let Some(_guard) = backend::try_lock() else { return u64::MAX };
    // SAFETY: STATE try-lock serializes process timer slots in IRQ and process contexts.
    let slots = unsafe { &mut *current.thread_group.posix_timers.get() };
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
    let Some(mut guard) = backend::try_lock() else { return };
    while let Some(entry) = guard.wall.pop_due(now) {
        // O(1) upgrade of the entry's own Weak. This was
        // `registry::lookup(entry.owner_tid)` — an O(N_tasks) scan of `REG`
        // taken in hard-IRQ context on every expiry (`skizm.md` Step 1b). A
        // failed upgrade means the owner exited, which is the same "skip it"
        // outcome the failed lookup produced.
        let Some(owner) = entry.owner.upgrade() else { continue };
        // SAFETY: backend STATE serializes every process timer slot access.
        let slots = unsafe { &mut *owner.thread_group.posix_timers.get() };
        let Some(timer) = slots.get_mut(entry.timer_id) else { continue };
        if !timer.allocated || super::cpu_nanosleep::is_cpu_clock(timer.domain) { continue; }
        service_wake(timer, &owner, true);
        if let Some(restart) =
            wall_entry(entry.owner_tid, entry.timer_id, timer, entry.owner.clone())
        {
            guard.wall.restart(restart);
        }
    }
    publish_earliest(guard.wall.earliest_ns());
}

/// Delete every process-owned POSIX timer at exec or final process exit.
pub fn clear_process_timers(current: &Task) {
    let owner = clock::timer_owner(current);
    let owner_tid = owner.task().tid;
    let mut guard = backend::lock();
    // SAFETY: backend STATE serializes every process timer slot access.
    let slots = unsafe { &mut *current.thread_group.posix_timers.get() };
    for (timer_id, timer) in slots.iter_mut().enumerate() {
        guard.wall.remove(owner_tid, timer_id);
        *timer = PosixTimer::default();
    }
    // Release anything the process grew beyond the base working set; the next
    // `timer_create` grows again from a clean table (Linux frees every
    // `k_itimer` back to its slab in `exit_itimers`).
    slots.truncate(PosixTimer::SLOTS);
    slots.shrink_to_fit();
    publish_earliest(guard.wall.earliest_ns());
    drop(guard);
    program(next_interrupt_deadline());
}

/// Next hardware interrupt, bounded by CPU accounting precision. # C: O(SLOTS * N_threads)
pub fn next_interrupt_deadline() -> u64 {
    let now = clock::monotonic_now_ns();
    let advancing = EARLIEST_WALL_NS.load(Ordering::Acquire)
        .min(current_cpu_deadline(now));
    let programmed = next_programmed_interrupt(now, advancing, tick_deadline(now));
    // B1460: armed WAIT expiries are part of the next event too — Linux
    // `__hrtimer_get_next_event` mins over every active base, and a blocking
    // wait's timeout is an hrtimer like any other. Folded here rather than into
    // `advancing` so a POSIX wall timer that is due-but-uncollectable (the
    // contested-lock case `next_programmed_interrupt` guards) cannot also
    // discard an unrelated sub-tick wait deadline.
    crate::hrtimeout::fold_wait_expiry(now, programmed, crate::hrtimeout::earliest_hard_ns())
}

/// Re-arm this CPU's one-shot after a wait expiry was armed or cancelled in
/// process context — Linux `hrtimer_reprogram`. `program`'s `ARMED_NS` cache
/// makes it a no-op when the resolved deadline is unchanged, which is the
/// common case for a park behind an already-earlier timer.
/// # C: O(SLOTS * N_threads)
/// # Ctx: process
pub fn reprogram_local() { program(next_interrupt_deadline()); }
