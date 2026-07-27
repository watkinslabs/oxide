use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use syscall::SyscallArgs;

use crate::timer_model::{arm_domain, classify_clock, ClockError, Notify, PosixTimer};
use crate::Task;

use super::{backend, clock, runtime, uapi};

fn err(errno: Errno) -> i64 { -(errno.as_i32() as i64) }

fn current() -> Result<&'static Task, i64> { crate::live::current().ok_or(err(Errno::Esrch)) }

fn clock_error(error: ClockError) -> i64 {
    match error { ClockError::Invalid => err(Errno::Einval), ClockError::Unsupported => err(Errno::Eopnotsupp) }
}

fn slot_mut<'a>(slots: &'a mut [PosixTimer; PosixTimer::SLOTS], id: i32)
    -> Result<&'a mut PosixTimer, i64>
{
    if !(0..PosixTimer::SLOTS as i32).contains(&id) { return Err(err(Errno::Einval)); }
    let timer = &mut slots[id as usize];
    if !timer.allocated { return Err(err(Errno::Einval)); }
    Ok(timer)
}

fn thread_id_target(current: &Task, tid: i32) -> Option<u32> {
    if tid <= 0 { return None; }
    let ns = current.namespace_owner(namespace_identity::NamespaceKind::Pid)
        .unwrap_or_else(|| namespace_identity::initial(namespace_identity::NamespaceKind::Pid));
    let task = crate::registry::lookup_in_namespace(&ns, tid as u32)?;
    (task.tgid.load(Ordering::Acquire) == current.tgid.load(Ordering::Acquire)).then_some(task.tid)
}

fn notification(event: Option<uapi::Sigevent>, current: &Task, id: i32) -> Result<Notify, i64> {
    let Some(event) = event else {
        return Ok(Notify::Signal { signo: uapi::SIGALRM, value: id as u64, target_tid: 0 });
    };
    match event.notify {
        uapi::SIGEV_NONE => Ok(Notify::None),
        uapi::SIGEV_SIGNAL => {
            if !(1..=uapi::SIGNAL_MAX).contains(&event.signo) { return Err(err(Errno::Einval)); }
            Ok(Notify::Signal { signo: event.signo as u32, value: event.value, target_tid: 0 })
        }
        uapi::SIGEV_THREAD_ID => {
            if !(1..=uapi::SIGNAL_MAX).contains(&event.signo) { return Err(err(Errno::Einval)); }
            let target_tid = thread_id_target(current, event.tid).ok_or(err(Errno::Einval))?;
            Ok(Notify::Signal { signo: event.signo as u32, value: event.value, target_tid })
        }
        _ => Err(err(Errno::Einval)),
    }
}

fn reserve_notification(notify: Notify, owner: &Task) {
    let Notify::Signal { signo, target_tid, .. } = notify else { return };
    let target = if target_tid == 0 { None } else { crate::registry::lookup(target_tid) };
    target.as_deref().unwrap_or(owner).sigq_reserve(signo);
}

/// Linux timer_create work function. # C: O(SLOTS + N_tasks)
pub fn sys_timer_create(args: &SyscallArgs) -> i64 {
    let event = if args.a1 == 0 { None } else {
        match uapi::read_sigevent(args.a1) { Ok(event) => Some(event), Err(error) => return error }
    };
    let clock = match classify_clock(args.a0 as i32) {
        Ok(clock) => clock,
        Err(error) => return clock_error(error),
    };
    let current = match current() { Ok(current) => current, Err(error) => return error };
    let owner = clock::timer_owner(current);
    let _guard = backend::lock();
    // SAFETY: STATE serializes all process-wide POSIX timer slot access.
    let slots = unsafe { &mut *current.thread_group.posix_timers.get() };
    let Some(id) = slots.iter().position(|timer| !timer.allocated).map(|id| id as i32) else {
        return err(Errno::Eagain);
    };
    let notify = match notification(event, current, id) { Ok(notify) => notify, Err(error) => return error };
    let clock = match clock::resolve_clock(current, clock) {
        Some(clock) => clock,
        None => return err(Errno::Einval),
    };
    reserve_notification(notify, owner.task());
    if let Err(error) = uapi::write_timer_id(args.a2, id) { return error; }
    slots[id as usize] = PosixTimer::allocate(clock, notify);
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
    let timer = match slot_mut(slots, args.a0 as i32) { Ok(timer) => timer, Err(error) => return error };
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
    runtime::sync_wall_locked(&mut guard, owner.task().tid, args.a0 as usize, timer, owner.weak());
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
    let timer = match slot_mut(slots, args.a0 as i32) { Ok(timer) => timer, Err(error) => return error };
    let setting = runtime::setting(timer, owner.task());
    runtime::sync_wall_locked(&mut guard, owner.task().tid, args.a0 as usize, timer, owner.weak());
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
    let timer = match slot_mut(slots, args.a0 as i32) { Ok(timer) => timer, Err(error) => return error };
    let overrun = runtime::overrun(timer, owner.task());
    runtime::sync_wall_locked(&mut guard, owner.task().tid, args.a0 as usize, timer, owner.weak());
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
    let timer = match slot_mut(slots, args.a0 as i32) { Ok(timer) => timer, Err(error) => return error };
    *timer = PosixTimer::default();
    runtime::sync_wall_locked(&mut guard, owner.task().tid, args.a0 as usize, timer, owner.weak());
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
