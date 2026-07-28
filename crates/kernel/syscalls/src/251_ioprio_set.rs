// 251 ioprio_set — one syscall, one file (docs/53 §0).
// `ioprio_set(which, who, ioprio)`: Linux `block/ioprio.c:65`. Thin shim over
// `crate::ioprio` (Linux `ioprio_check_cap`) and `priority_common` for the
// which/who target set; the stored value is the raw `int`, as
// `io_context::ioprio` holds it.
#![cfg(target_os = "oxide-kernel")]

use core::sync::atomic::Ordering;
use syscall::errno::Errno;
use syscall::SyscallArgs;
use crate::ioprio::{self, CapNeed};

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_ioprio_set(which, who, ioprio)` — slot 251.
/// # C: O(N_tasks) for PGRP/USER
pub fn sys_ioprio_set(args: &SyscallArgs) -> i64 {
    let which  = args.a0 as i32;
    let who    = args.a1 as u32;
    let prio   = args.a2 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return err(Errno::Esrch) };
    // Linux runs ioprio_check_cap BEFORE the `which` switch, so an RT request
    // from an unprivileged caller is EPERM even when `which` is nonsense.
    match ioprio::check_cap(prio) {
        Err(rv) => return rv,
        Ok(CapNeed::SysAdminOrSysNice) => {
            // CAP_SYS_ADMIN is tested first so an LSM denial names the
            // capability Linux historically required.
            if !cur.has_cap(sched::cap::SYS_ADMIN) && !cur.has_cap(sched::cap::SYS_NICE) {
                return err(Errno::Eperm);
            }
        }
        Ok(CapNeed::None) => {}
    }
    let base = match ioprio::who_base(which) { Ok(b) => b, Err(rv) => return rv };

    let has_nice = cur.has_cap(sched::cap::SYS_NICE);
    let euid = cur.creds.euid.load(Ordering::Acquire);
    let ruid = cur.creds.ruid.load(Ordering::Acquire);
    // Linux `set_task_ioprio` owner check: the target's REAL uid must match the
    // caller's euid or ruid, or the caller holds CAP_SYS_NICE. The loop aborts
    // on the first failure and returns it, so a partially-applied PGRP/USER
    // request still reports EPERM.
    let mut ret: i64 = err(Errno::Esrch);
    crate::priority::priority_common::for_each_target(base, who, |t| {
        if ret != err(Errno::Esrch) && ret != 0 { return; }
        let target_ruid = t.creds.ruid.load(Ordering::Acquire);
        if !(has_nice || target_ruid == euid || target_ruid == ruid) {
            ret = err(Errno::Eperm);
            return;
        }
        t.ioprio.store(prio as u32, Ordering::Release);
        ret = 0;
    });
    ret
}
