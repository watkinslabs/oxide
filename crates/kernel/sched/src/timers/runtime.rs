use core::sync::atomic::{AtomicPtr, AtomicU64, Ordering};

use crate::timer_model::{advance_tick, next_programmed_interrupt, project_deadline, ClockSpec,
    Expiration, Notify, PosixTimer};
use crate::{SigInfo, Task};

use super::{backend, clock};

/// One owner for the tick period: `clock_getres` reports it for the COARSE
/// clocks, so the two can never disagree.
pub const ACCOUNTING_TICK_NS: u64 = crate::posix_clock::TICK_NSEC;

type ProgramDeadline = fn(u64);
type ClockWasSetHook = fn(u64);

static EARLIEST_WALL_NS: AtomicU64 = AtomicU64::new(u64::MAX);
static PROGRAM_DEADLINE: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static CLOCK_WAS_SET_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

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
        return current.pending_signals() & bit != 0;
    }
    crate::registry::lookup(target_tid).map(|task|
        task.pending_signals() & bit != 0).unwrap_or(false)
}

/// Linux `posix_timer_queue_signal`'s send: the record the timer has owned
/// since `timer_create` goes onto the target set through the ONE enqueue.
///
/// `SIGEV_THREAD_ID` names a thread, which is Linux's `PIDTYPE_PID` — the
/// thread's private set. Every other notification is `PIDTYPE_TGID`, so the
/// record belongs on the PROCESS' shared set: a group-directed timer signal
/// may be taken by any thread, and posting it into whichever thread the tick
/// happened to interrupt hid it from every sibling.
/// # C: O(1)
/// # Ctx: IRQ
fn post(current: &Task, event: Expiration, timer_id: usize, wake: bool) {
    let info = super::signal::timer_record(event.signo, timer_id, event.value);
    let (target, tid) = if event.target_tid == 0 {
        (current, current.tid)
    } else {
        match crate::registry::lookup(event.target_tid) {
            Some(t) => {
                if crate::live::send::send_signal_irq(&t, info, crate::sigsend::SigTarget::Thread)
                    && wake
                {
                    // SAFETY: timer tick is an IRQ wake site and the registry Arc pins the target.
                    unsafe { crate::live::ttwu::ttwu_deferred(t); }
                }
                return;
            }
            None => return,
        }
    };
    if !crate::live::send::send_signal_irq(target, info, crate::sigsend::SigTarget::Process) { return; }
    if !wake { return; }
    if let Some(t) = crate::registry::lookup(tid) {
        // SAFETY: timer tick is an IRQ wake site and the registry Arc pins the target.
        unsafe { crate::live::ttwu::ttwu_deferred(t); }
    }
}

fn service_wake(timer: &mut PosixTimer, timer_id: usize, current: &Task, wake: bool) {
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
        post(current, event, timer_id, wake);
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

pub(super) fn service(timer: &mut PosixTimer, timer_id: usize, current: &Task) {
    service_wake(timer, timer_id, current, false);
}

pub(super) fn setting(timer: &mut PosixTimer, timer_id: usize, current: &Task)
    -> crate::timer_model::TimerSetting
{
    service(timer, timer_id, current);
    let now = clock::now_ns(timer.domain).unwrap_or(0);
    timer.setting(now, pending(current, timer.notify))
}

pub(super) fn overrun(timer: &mut PosixTimer, timer_id: usize, current: &Task) -> i64 {
    service(timer, timer_id, current);
    let now = clock::now_ns(timer.domain).unwrap_or(0);
    timer.overrun_last(now, pending(current, timer.notify))
}

/// Linux `posixtimer_rearm`: a `SI_TIMER` record being handed to a consumer
/// (`SA_SIGINFO` delivery, `rt_sigtimedwait`, a `signalfd` read) names its
/// timer in `si_tid`. Settle that timer's delivery — which is what computes
/// the overrun for THIS delivery and re-arms a periodic timer — and stamp the
/// count into `si_overrun`.
///
/// One accumulator, so `si_overrun` and `timer_getoverrun(2)` can never
/// disagree: both read `PosixTimer::overrun_last` after the same
/// `reconcile_delivery`. Called with NO signal-queue lock held (the record is
/// already popped), which is what keeps the timer lock out of the dequeue's
/// lock order.
/// # C: O(1)
/// # Ctx: process
pub fn posixtimer_rearm(owner: &Task, rec: &mut SigInfo) {
    if !super::signal::is_timer_record(rec) { return; }
    let id = super::signal::timer_id(rec);
    let timer_owner = clock::timer_owner(owner);
    let mut guard = backend::lock();
    // SAFETY: backend STATE serializes every process timer slot access.
    let slots = unsafe { &mut *owner.thread_group.posix_timers.get() };
    let Some(timer) = slots.get_mut(id) else { return };
    if !timer.allocated { return; }
    let now = clock::now_ns(timer.domain).unwrap_or(0);
    // `false`: the record is being TAKEN right now, so the delivery is no
    // longer pending no matter what the bitmap still says.
    let overrun = timer.overrun_last(now, false);
    super::signal::stamp_overrun(rec, overrun);
    // Linux rearms the hrtimer as part of `posixtimer_rearm`; do not leave a
    // forwarded periodic deadline for an unrelated syscall-return scan to
    // discover. Timer mutation owns queue synchronization and reprogramming.
    sync_wall_locked(&mut guard, timer_owner.task().tid, id, timer, timer_owner.weak());
    drop(guard);
    reprogram_posix_timers();
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
    for (timer_id, timer) in slots.iter_mut().enumerate().filter(|(_, timer)|
        timer.allocated && cpu_clock_runs_for(timer.domain, current))
    {
        service_wake(timer, timer_id, current, true);
    }
}

/// Last deadline handed to the hardware per CPU, so a reprogram that resolves
/// to the already-armed expiry skips the LVT + MSR writes. A cached deadline
/// that `now` has passed is re-armed regardless —
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

/// Install a filesystem wall-clock-step observer without introducing a
/// scheduler → filesystem dependency. Boot owns the one-time wiring.
/// # C: O(1)
pub fn install_clock_was_set_hook(f: fn(u64)) {
    CLOCK_WAS_SET_HOOK.store(f as *const () as *mut (), Ordering::Release);
}

fn notify_clock_was_set_hook(step_mono_ns: u64) {
    let raw = CLOCK_WAS_SET_HOOK.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: the slot is written only by install_clock_was_set_hook with this signature.
    let hook: ClockWasSetHook = unsafe { core::mem::transmute(raw) };
    hook(step_mono_ns);
}

/// Recompute wall timers and program the earliest advancing POSIX clock. # C: O(N_tasks * SLOTS)
pub fn reprogram_posix_timers() {
    let guard = backend::lock();
    publish_earliest(guard.wall.earliest_ns());
    drop(guard);
    program(next_interrupt_deadline());
}

/// Reproject absolute realtime/TAI timers after a wall-clock adjustment.
/// `step_mono_ns` is sampled immediately before the timekeeper mutation and
/// remains the old-domain expiration boundary while observers are processed.
/// # C: O(N_wall_timers)
pub fn clock_was_set(step_mono_ns: u64) {
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
    notify_clock_was_set_hook(step_mono_ns);
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
        service_wake(timer, entry.timer_id, &owner, true);
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
    let with_waits = crate::hrtimeout::fold_wait_expiry(now, programmed,
        crate::hrtimeout::earliest_hard_ns());
    // A throttled SCHED_DEADLINE entity's replenishment instant is an event
    // like any other: without it here the throttle would end at the next
    // accounting tick instead of at the start of the entity's next period,
    // which turns a sub-tick reservation into a tick-granularity one.
    let with_deadline = crate::hrtimeout::fold_wait_expiry(
        now, with_waits, crate::deadline::replenish::earliest_ns());
    // The rseq extension is a per-running-task hrtimer.  It participates in
    // the same one-shot decision rather than waiting for the accounting tick.
    #[cfg(target_os = "oxide-kernel")]
    { crate::hrtimeout::fold_wait_expiry(now, with_deadline, crate::rseq::slice_deadline()) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { with_deadline }
}

/// Re-arm this CPU's one-shot after a wait expiry was armed or cancelled in
/// process context — Linux `hrtimer_reprogram`. `program`'s `ARMED_NS` cache
/// makes it a no-op when the resolved deadline is unchanged, which is the
/// common case for a park behind an already-earlier timer.
/// # C: O(SLOTS * N_threads)
/// # Ctx: process
pub fn reprogram_local() { program(next_interrupt_deadline()); }
