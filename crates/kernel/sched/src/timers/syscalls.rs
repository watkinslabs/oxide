use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use syscall::SyscallArgs;

use crate::posix_clock;
use crate::timer_model::{arm_domain, ClockError, Notify, PosixTimer};
use crate::Task;

use super::{backend, clock, runtime, sigevent, slots, uapi};

fn err(errno: Errno) -> i64 { -(errno.as_i32() as i64) }

fn current() -> Result<&'static Task, i64> { crate::live::current().ok_or(err(Errno::Esrch)) }

fn clock_error(error: ClockError) -> i64 {
    match error {
        ClockError::Invalid => err(Errno::Einval),
        ClockError::Unsupported => err(Errno::Eopnotsupp),
    }
}

/// `lock_timer()` — an id naming no timer of this process is EINVAL.
fn slot_id(slots: &[PosixTimer], id: u64) -> Result<usize, i64> {
    slots::slot_index(slots, id as i64).ok_or(err(Errno::Einval))
}

fn thread_id_target(current: &Task, tid: i32) -> Option<u32> {
    if tid <= 0 { return None; }
    let ns = current.namespace_owner(namespace_identity::NamespaceKind::Pid)
        .unwrap_or_else(|| namespace_identity::initial(namespace_identity::NamespaceKind::Pid));
    let task = crate::registry::lookup_in_namespace(&ns, tid as u32)?;
    (task.tgid.load(Ordering::Acquire) == current.tgid.load(Ordering::Acquire)).then_some(task.tid)
}

fn notification(event: Option<sigevent::Sigevent>, current: &Task, id: usize)
    -> Result<Notify, i64>
{
    sigevent::notify_for(event, id, |tid| thread_id_target(current, tid)).map_err(err)
}

fn reserve_notification(notify: Notify, owner: &Task) {
    let Notify::Signal { signo, target_tid, .. } = notify else { return };
    let target = if target_tid == 0 { None } else { crate::registry::lookup(target_tid) };
    target.as_deref().unwrap_or(owner).rt_reserve(signo);
}

/// Linux timer_create work function. # C: O(SLOTS + N_tasks)
pub fn sys_timer_create(args: &SyscallArgs) -> i64 {
    // The sigevent copy happens in the syscall wrapper, BEFORE do_timer_create
    // classifies the clock: a bad sigevent pointer is EFAULT even for a
    // nonsense clock id.
    let event = if args.a1 == 0 { None } else {
        match uapi::read_sigevent(args.a1) { Ok(event) => Some(event), Err(error) => return error }
    };
    let clock = match posix_clock::classify_clock(args.a0 as i32) {
        Ok(clock) => clock,
        Err(error) => return clock_error(error),
    };
    // `!kc->timer_create` is EOPNOTSUPP, not EINVAL.
    if let Err(error) = posix_clock::timer_creatable(clock) { return clock_error(error); }
    let current = match current() { Ok(current) => current, Err(error) => return error };
    // `alarm_timer_create()` gates the RTC-wakeup clocks on CAP_WAKE_ALARM.
    if posix_clock::needs_wake_alarm(clock) && !current.has_cap(crate::cap::WAKE_ALARM) {
        return err(Errno::Eperm);
    }
    let owner = clock::timer_owner(current);
    let _guard = backend::lock();
    // SAFETY: STATE serializes all process-wide POSIX timer slot access.
    let slots = unsafe { &mut *current.thread_group.posix_timers.get() };
    let Some(id) = slots::allocate_id(slots) else { return err(Errno::Eagain) };
    let notify = match notification(event, current, id) {
        Ok(notify) => notify, Err(error) => return error,
    };
    // `posix_cpu_timer_create()` validates the encoded CPU target.
    let clock = match clock::resolve_clock(current, clock, false) {
        Some(clock) => clock,
        None => return err(Errno::Einval),
    };
    // The id copy-out precedes any state the timer owns, so an EFAULT here
    // cannot leak an rt-signal reservation on a timer that was never created.
    if let Err(error) = uapi::write_timer_id(args.a2, id as i32) { return error; }
    reserve_notification(notify, owner.task());
    slots[id] = PosixTimer::allocate(clock, notify);
    0
}

/// Linux timer_settime work function. # C: O(1)
pub fn sys_timer_settime(args: &SyscallArgs) -> i64 {
    if args.a2 == 0 { return err(Errno::Einval); }
    let new = match uapi::read_itimerspec(args.a2) { Ok(new) => new, Err(error) => return error };
    let current = match current() { Ok(current) => current, Err(error) => return error };
    let owner = clock::timer_owner(current);
    let mut guard = backend::lock();
    // SAFETY: STATE serializes all process-wide POSIX timer slot access.
    let slots = unsafe { &mut *current.thread_group.posix_timers.get() };
    let id = match slot_id(slots, args.a0) { Ok(id) => id, Err(error) => return error };
    let timer = &mut slots[id];
    let old = runtime::setting(timer, owner.task());
    let absolute = args.a1 & uapi::TIMER_ABSTIME != 0;
    let domain = arm_domain(timer.clock, absolute);
    let deadline = if new.value_ns == 0 {
        0
    } else if absolute {
        match clock::absolute_deadline(current, timer.clock, new.value_ns) {
            Some(deadline) => deadline, None => return err(Errno::Einval),
        }
    } else {
        match clock::now_ns(domain) {
            Some(now) => now.saturating_add(new.value_ns).max(1),
            None => return err(Errno::Einval),
        }
    };
    timer.set(domain, deadline, new.interval_ns);
    runtime::sync_wall_locked(&mut guard, owner.task().tid, id, timer, owner.weak());
    drop(guard);
    runtime::reprogram_posix_timers();
    if args.a3 != 0 {
        if let Err(error) = uapi::write_itimerspec(args.a3, old) { return error; }
    }
    0
}

/// Linux timer_gettime work function. # C: O(1)
pub fn sys_timer_gettime(args: &SyscallArgs) -> i64 {
    let current = match current() { Ok(current) => current, Err(error) => return error };
    let owner = clock::timer_owner(current);
    let mut guard = backend::lock();
    // SAFETY: STATE serializes all process-wide POSIX timer slot access.
    let slots = unsafe { &mut *current.thread_group.posix_timers.get() };
    let id = match slot_id(slots, args.a0) { Ok(id) => id, Err(error) => return error };
    let timer = &mut slots[id];
    let setting = runtime::setting(timer, owner.task());
    runtime::sync_wall_locked(&mut guard, owner.task().tid, id, timer, owner.weak());
    drop(guard);
    runtime::reprogram_posix_timers();
    match uapi::write_itimerspec(args.a1, setting) {
        Ok(()) => 0, Err(error) => error,
    }
}

/// Linux timer_getoverrun cached last-delivered read. # C: O(1)
pub fn sys_timer_getoverrun(args: &SyscallArgs) -> i64 {
    let current = match current() { Ok(current) => current, Err(error) => return error };
    let owner = clock::timer_owner(current);
    let mut guard = backend::lock();
    // SAFETY: STATE serializes all process-wide POSIX timer slot access.
    let slots = unsafe { &mut *current.thread_group.posix_timers.get() };
    let id = match slot_id(slots, args.a0) { Ok(id) => id, Err(error) => return error };
    let timer = &mut slots[id];
    let overrun = runtime::overrun(timer, owner.task());
    runtime::sync_wall_locked(&mut guard, owner.task().tid, id, timer, owner.weak());
    drop(guard);
    runtime::reprogram_posix_timers();
    overrun
}

/// Linux timer_delete work function. # C: O(1)
pub fn sys_timer_delete(args: &SyscallArgs) -> i64 {
    let current = match current() { Ok(current) => current, Err(error) => return error };
    let owner = clock::timer_owner(current);
    let mut guard = backend::lock();
    // SAFETY: STATE serializes all process-wide POSIX timer slot access.
    let slots = unsafe { &mut *current.thread_group.posix_timers.get() };
    let id = match slot_id(slots, args.a0) { Ok(id) => id, Err(error) => return error };
    let timer = &mut slots[id];
    *timer = PosixTimer::default();
    runtime::sync_wall_locked(&mut guard, owner.task().tid, id, timer, owner.weak());
    drop(guard);
    runtime::reprogram_posix_timers();
    0
}

/// Dispatch one POSIX timer syscall number. # C: O(SLOTS)
pub fn timer_dispatch(nr: u64, args: &SyscallArgs) -> Option<i64> {
    use syscall::nrs::*;
    Some(match nr {
        NR_TIMER_CREATE => sys_timer_create(args),
        NR_TIMER_SETTIME => sys_timer_settime(args),
        NR_TIMER_GETTIME => sys_timer_gettime(args),
        NR_TIMER_GETOVERRUN => sys_timer_getoverrun(args),
        NR_TIMER_DELETE => sys_timer_delete(args),
        _ => return None,
    })
}
