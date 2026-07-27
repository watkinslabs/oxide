// Shared target-set resolution for getpriority/setpriority (140/141) and
// ioprio_set/get (251/252). `for_each_target` resolves a which/who pair
// to a set of tasks per the getpriority(2) base (0=PROCESS, 1=PGRP,
// 2=USER) and invokes the callback for each.

#![cfg(target_os = "oxide-kernel")]

/// Resolve a `which`/`who` target set (0=PROCESS, 1=PGRP, 2=USER — the
/// getpriority(2) base) and call `f` for each task. Shared with ioprio_set/get
/// (slots 251/252), which pass `which-1` to map IOPRIO_WHO_PROCESS=1/PGRP=2/
/// USER=3 onto the same resolution.
/// # C: O(N_tasks) for PGRP/USER; O(1) for PROCESS
pub(crate) fn for_each_target(which: u64, who: u32, mut f: impl FnMut(&alloc::sync::Arc<sched::Task>)) {
    use core::sync::atomic::Ordering;
    match which {
        0 => {
            let t = if who == 0 {
                sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
            } else { sched::live::registry::resolve_user_pid(who) };
            if let Some(t) = t { f(&t); }
        }
        1 => {
            let pgid = if who == 0 {
                sched::live::current().map(|c| c.pgid()).unwrap_or(0)
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
