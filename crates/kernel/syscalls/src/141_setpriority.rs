// 141 setpriority — one syscall, one file (docs/53 §0).
//
// setpriority(which, who, prio): PRIO_PROCESS (0) / PRIO_PGRP (1) /
// PRIO_USER (2). Clamps nice to [-20,19] and rewrites the live CFS
// weight so the change shifts CPU shares. Shared target resolution
// lives in priority_common.

#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::SyscallArgs;
use super::priority_common::for_each_target;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(all(test, not(target_os = "oxide-kernel")))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_setpriority(which, who, prio)` — slot 141. Clamps nice to [-20,19],
/// then applies Linux `set_one_prio` per target: an owner mismatch is EPERM and
/// an unprivileged nice reduction beyond RLIMIT_NICE is EACCES.
/// # C: O(N_tasks)
pub fn sys_setpriority(args: &SyscallArgs) -> i64 {
    let (which, who, prio) = (args.a0, args.a1 as u32, args.a2 as i32);
    let cur = match current_task() {
        Some(c) => c,
        None => return crate::sched_policy::err(syscall::errno::Errno::Esrch),
    };
    let mut walk = match crate::sched_policy::SetpriorityWalk::new(which, &cur, prio) {
        Ok(walk) => walk,
        Err(rv) => return rv,
    };
    let nice = walk.nice();
    for_each_target(which, who, |t| {
        // Store the nice value AND rewrite the live CFS weight so the change
        // actually shifts CPU shares (`13§3`): nice<0 → heavier → more CPU.
        // Linux `set_user_nice`/`set_load_weight`: an RT/DEADLINE task records
        // the nice value but keeps its RT class, and a SCHED_IDLE task stays
        // pinned at WEIGHT_IDLEPRIO — nice never rewrites either one's weight.
        walk.visit(t, || sched::live::runqueue::set_nice(t, nice));
    });
    walk.result()
}

#[cfg(all(test, not(target_os = "oxide-kernel")))]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::ptr;
    use core::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::Mutex;

    static SERIAL: Mutex<()> = Mutex::new(());
    static CURRENT: AtomicPtr<sched::Task> = AtomicPtr::new(ptr::null_mut());

    fn current() -> Option<&'static sched::Task> {
        let task = CURRENT.load(Ordering::Acquire);
        if task.is_null() { None } else {
            // SAFETY: each test pins all task Arcs until the syscall returns.
            Some(unsafe { &*task })
        }
    }

    fn task(tid: u32, ruid: u32, euid: u32) -> Arc<sched::Task> {
        let task = Arc::new(sched::Task::new(tid, "setpriority-production",
            sched::SchedClass::Normal { weight: 1024 }));
        task.security.creds.ruid.store(ruid, Ordering::Release);
        task.security.creds.euid.store(euid, Ordering::Release);
        task.security.creds.cap_effective.store(0, Ordering::Release);
        task.security.creds.cap_permitted.store(0, Ordering::Release);
        task.security.vtid.store(tid, Ordering::Release);
        task.security.vtgid.store(tid, Ordering::Release);
        task.set_state(sched::TaskState::Sleeping);
        sched::live::registry::insert(&task);
        task
    }

    fn call(which: u64, who: u32, nice: i32) -> i64 {
        sys_setpriority(&SyscallArgs {
            a0: which, a1: who as u64, a2: nice as u32 as u64,
            a3: 0, a4: 0, a5: 0,
        })
    }

    fn begin(caller: &Arc<sched::Task>) {
        CURRENT.store(Arc::as_ptr(caller).cast_mut(), Ordering::Release);
        sched::set_current_hook(current);
    }

    fn end() {
        CURRENT.store(ptr::null_mut(), Ordering::Release);
        sched::registry::clear_for_tests();
    }

    #[test]
    fn process_and_same_task_use_the_production_resolver_and_runqueue_commit() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        sched::registry::clear_for_tests();
        let caller = task(0x7ffe_1001, 1000, 1000);
        let target = task(0x7ffe_1002, 1000, 1000);
        begin(&caller);
        assert_eq!(call(crate::priority_target::PRIO_PROCESS, target.tid, 6), 0);
        assert_eq!(target.nice_value(), 6);
        assert_eq!(call(crate::priority_target::PRIO_PROCESS, 0, 4), 0);
        assert_eq!(caller.nice_value(), 4, "who=0 resolves and mutates current");
        end();
    }

    #[test]
    fn pgrp_walk_accumulates_error_and_mutates_only_allowed_members() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        sched::registry::clear_for_tests();
        let caller = task(0x7ffe_1010, 1000, 1000);
        let first = task(0x7ffe_1011, 1000, 1000);
        let denied = task(0x7ffe_1012, 2000, 2000);
        let last = task(0x7ffe_1013, 1000, 1000);
        let pgrp = Arc::new(sched::pid::PidIdentity::new(0x7ffe_1100));
        for member in [&first, &denied, &last] { member.set_pgrp(Arc::clone(&pgrp)); }
        begin(&caller);
        assert_eq!(call(crate::priority_target::PRIO_PGRP, pgrp.tid, 8),
            -(syscall::errno::Errno::Eperm.as_i32() as i64));
        assert_eq!((first.nice_value(), denied.nice_value(), last.nice_value()), (8, 0, 8));
        end();
    }

    #[test]
    fn user_walk_uses_real_uid_set_and_suppresses_denied_mutation() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        sched::registry::clear_for_tests();
        let caller = task(0x7ffe_1020, 1000, 1000);
        let allowed = task(0x7ffe_1021, 3000, 1000);
        let denied = task(0x7ffe_1022, 3000, 2000);
        let also_allowed = task(0x7ffe_1023, 3000, 1000);
        begin(&caller);
        assert_eq!(call(crate::priority_target::PRIO_USER, 3000, 9),
            -(syscall::errno::Errno::Eperm.as_i32() as i64));
        assert_eq!((allowed.nice_value(), denied.nice_value(), also_allowed.nice_value()),
            (9, 0, 9));
        end();
    }
}
