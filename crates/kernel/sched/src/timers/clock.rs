use alloc::sync::{Arc, Weak};
use core::sync::atomic::Ordering;

use namespace_identity::{NamespaceKind, NamespaceRef};

use crate::timer_model::{ClockSpec, CpuClock, CpuMeasure};
use crate::Task;

pub(super) fn monotonic_now_ns() -> u64 { timekeeper::monotonic_ns() }

pub(super) struct TimerOwner<'a> { owner: Option<Arc<Task>>, fallback: &'a Task }

impl<'a> TimerOwner<'a> {
    pub(super) fn task(&self) -> &Task { self.owner.as_deref().unwrap_or(self.fallback) }

    /// A `Weak` to the owning task, for `WallEntry` to carry.
    ///
    /// This is the only registry lookup left on the wall-timer path, and it is
    /// deliberately HERE: arming runs in process context, where an O(N) scan is
    /// merely a cost. Resolving the owner at EXPIRY instead meant that scan ran
    /// in the hard-IRQ handler (`skizm.md` Step 1b). A decayed `Weak` — the
    /// no-Arc-obtainable case — is correct rather than lossy: an entry whose
    /// owner cannot be named is one whose expiry would have been skipped anyway.
    /// # C: O(N_tasks) once at arm time
    pub(super) fn weak(&self) -> Weak<Task> {
        if let Some(owner) = &self.owner { return Arc::downgrade(owner); }
        crate::registry::lookup(self.fallback.tid)
            .map(|arc| Arc::downgrade(&arc))
            .unwrap_or_default()
    }
}

pub(super) fn timer_owner(current: &Task) -> TimerOwner<'_> {
    let tgid = current.tgid.load(Ordering::Acquire);
    let owner = if tgid == current.tid { None } else { crate::registry::lookup(tgid) };
    TimerOwner { owner, fallback: current }
}

fn pid_namespace(current: &Task) -> NamespaceRef {
    current.namespace_owner(NamespaceKind::Pid)
        .unwrap_or_else(|| namespace_identity::initial(NamespaceKind::Pid))
}

/// `pid_for_clock()`. A per-thread clock may only name a thread of the
/// caller's own thread group; a process clock may name ANY thread-group
/// leader in the caller's PID namespace — that is how `clock_getcpuclockid(2)`
/// on another process feeds `clock_gettime`. `gettime` relaxes the leader
/// requirement for the caller's own tid the way Linux does, so a non-leader
/// thread can read its own process clock by tid.
/// # C: O(N_tasks)
pub(super) fn resolve_clock(current: &Task, clock: ClockSpec, gettime: bool)
    -> Option<ClockSpec>
{
    let ClockSpec::CpuEncoded { pid, per_thread, measure } = clock else { return Some(clock) };
    // CPUCLOCK_WHICH(clock) >= CPUCLOCK_MAX.
    if measure == CpuMeasure::Invalid { return None; }
    let target = if pid == 0 {
        if per_thread { current.tid } else { current.tgid.load(Ordering::Acquire) }
    } else {
        let task = crate::registry::lookup_in_namespace(&pid_namespace(current), pid)?;
        if per_thread {
            if task.tgid.load(Ordering::Acquire) != current.tgid.load(Ordering::Acquire) {
                return None;
            }
            task.tid
        } else if gettime && task.tid == current.tid {
            current.tgid.load(Ordering::Acquire)
        } else {
            // pid_has_task(pid, PIDTYPE_TGID)
            if task.tid != task.tgid.load(Ordering::Acquire) { return None; }
            task.tid
        }
    };
    Some(ClockSpec::Cpu(CpuClock { target, per_thread, measure }))
}

fn task_cpu_sample(task: &Task, measure: CpuMeasure) -> u64 {
    match measure {
        CpuMeasure::Prof => task.utime_ns.load(Ordering::Acquire)
            .saturating_add(task.stime_ns.load(Ordering::Acquire)),
        CpuMeasure::Virt => task.utime_ns.load(Ordering::Acquire),
        CpuMeasure::Sched => task.utime_ns.load(Ordering::Acquire)
            .saturating_add(task.stime_ns.load(Ordering::Acquire)),
        CpuMeasure::Invalid => 0,
    }
}

fn cpu_now_ns(clock: CpuClock) -> Option<u64> {
    if clock.per_thread {
        return crate::registry::lookup(clock.target).map(|task| task_cpu_sample(&task, clock.measure));
    }
    let leader = crate::registry::lookup(clock.target)?;
    let (user, system) = leader.thread_group.cpu_sample();
    Some(match clock.measure {
        CpuMeasure::Virt => user,
        CpuMeasure::Prof | CpuMeasure::Sched => user.saturating_add(system),
        CpuMeasure::Invalid => 0,
    })
}

pub(super) fn now_ns(clock: ClockSpec) -> Option<u64> {
    match crate::posix_clock::sample_domain(clock) {
        ClockSpec::Realtime => Some(timekeeper::realtime_ns()),
        ClockSpec::Monotonic => Some(monotonic_now_ns()),
        ClockSpec::Boottime => Some(timekeeper::boottime_ns()),
        ClockSpec::Tai => Some(timekeeper::tai_ns()),
        ClockSpec::Cpu(clock) => cpu_now_ns(clock),
        _ => None,
    }
}

/// Sample one CPU clock id for `clock_gettime`, `posix_cpu_clock_get`
/// semantics: resolve the encoded target against the caller's PID namespace
/// (EINVAL when it names no live task in the caller's thread group), then read
/// the requested measure. Process-wide samples come from the thread group's
/// cumulative accounting, so a thread exiting cannot make the process clock go
/// backwards (Linux `thread_group_cputime` includes reaped threads).
/// # C: O(N_tasks)
pub fn cpu_clock_sample_ns(current: &Task, clock: ClockSpec) -> Option<u64> {
    now_ns(resolve_clock(current, clock, true)?)
}

/// Validate a CPU clock target without sampling it —
/// `validate_clock_permissions()`, used by `clock_getres` and `clock_settime`.
/// # C: O(N_tasks)
pub fn cpu_clock_valid(current: &Task, clock: ClockSpec) -> bool {
    resolve_clock(current, clock, false).is_some()
}

pub(super) fn absolute_deadline(current: &Task, clock: ClockSpec, user_ns: u64) -> Option<u64> {
    let owner = current.namespace_owner(NamespaceKind::Time);
    let deadline = match crate::posix_clock::sample_domain(clock) {
        ClockSpec::Monotonic => time_namespace::absolute_to_host_or_initial(owner.as_ref(),
            time_namespace::TimeNsClock::Monotonic, user_ns).ok()?,
        ClockSpec::Boottime => time_namespace::absolute_to_host_or_initial(owner.as_ref(),
            time_namespace::TimeNsClock::Boottime, user_ns).ok()?,
        ClockSpec::Realtime | ClockSpec::Tai | ClockSpec::Cpu(_) => user_ns,
        _ => return None,
    };
    Some(deadline.max(1))
}
