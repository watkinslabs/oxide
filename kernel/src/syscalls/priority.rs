// sys_getpriority / sys_setpriority extracted from proc.rs to keep
// that file under the 1000-line cap (`08§7`). Honors PRIO_PROCESS (0),
// PRIO_PGRP (1), PRIO_USER (2).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getpriority(which, who)` — slot 140. PRIO_PROCESS/PGRP/USER.
/// Returns `20 - nice` of the lowest-nice matching task; -ESRCH if none.
/// # C: O(N_tasks)
pub fn sys_getpriority(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let (which, who) = (args.a0, args.a1 as u32);
    if which > 2 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let mut best: Option<i32> = None;
    for_each_target(which, who, |t| {
        let n = t.nice.load(Ordering::Acquire) as i32;
        best = Some(match best { Some(b) => b.min(n), None => n });
    });
    match best { Some(n) => 20 - n as i64, None => -(syscall::errno::Errno::Esrch.as_i32() as i64) }
}

/// `sys_setpriority(which, who, prio)` — slot 141. Clamps nice to [-20,19].
/// # C: O(N_tasks)
pub fn sys_setpriority(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    let (which, who, prio) = (args.a0, args.a1 as u32, args.a2 as i32);
    if which > 2 { return -(syscall::errno::Errno::Einval.as_i32() as i64); }
    let n = sched::rlimit::clamp_nice(prio);
    let mut touched = false;
    for_each_target(which, who, |t| { t.nice.store(n, Ordering::Release); touched = true; });
    if touched { 0 } else { -(syscall::errno::Errno::Esrch.as_i32() as i64) }
}

fn for_each_target(which: u64, who: u32, mut f: impl FnMut(&alloc::sync::Arc<sched::Task>)) {
    use core::sync::atomic::Ordering;
    match which {
        0 => {
            let t = if who == 0 {
                sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
            } else { sched::live::registry::lookup(who) };
            if let Some(t) = t { f(&t); }
        }
        1 => {
            let pgid = if who == 0 {
                sched::live::current().map(|c| c.pgid.load(Ordering::Acquire)).unwrap_or(0)
            } else { who };
            for t in sched::live::registry::tasks_in_pgrp(pgid) { f(&t); }
        }
        2 => {
            let uid = if who == 0 {
                sched::live::current().map(|c| c.creds.ruid.load(Ordering::Acquire)).unwrap_or(0)
            } else { who };
            for tid in sched::live::registry::live_tids() {
                if let Some(t) = sched::live::registry::lookup(tid) {
                    if t.creds.ruid.load(Ordering::Acquire) == uid { f(&t); }
                }
            }
        }
        _ => {}
    }
}
