// Shared target-set resolution for getpriority/setpriority (140/141) and
// ioprio_set/get (251/252). `for_each_target` resolves a which/who pair
// to a set of tasks per the getpriority(2) base (0=PROCESS, 1=PGRP,
// 2=USER) and invokes the callback for each.
//
// The RULES this walk applies (which/who decoding, the `who == 0` aliases,
// user-namespace id mapping, and the pid-namespace visibility test) live in
// `priority_target`, which carries no target gate so they are hosted-testable.

#![cfg(target_os = "oxide-kernel")]

use crate::priority_target::{user_target_matches, user_target_uid, which_from_prio_base, Which};

/// Resolve a `which`/`who` target set (0=PROCESS, 1=PGRP, 2=USER — the
/// getpriority(2) base) and call `f` for each task. Shared with ioprio_set/get
/// (slots 251/252), which pass `which-1` to map IOPRIO_WHO_PROCESS=1/PGRP=2/
/// USER=3 onto the same resolution.
///
/// The PGRP and USER walks cover every THREAD, not just group leaders — both
/// nice and ioprio are per-thread state and Linux iterates
/// `do_each_pid_thread`/`for_each_process_thread`.
/// # C: O(N_tasks) for PGRP/USER; O(1) for PROCESS
pub(crate) fn for_each_target(which: u64, who: u32, mut f: impl FnMut(&alloc::sync::Arc<sched::Task>)) {
    use core::sync::atomic::Ordering;
    let Some(which) = which_from_prio_base(which) else { return; };
    match which {
        Which::Process => {
            let t = if who == 0 {
                sched::live::current().and_then(|c| sched::live::registry::lookup(c.tid))
            } else { sched::live::registry::resolve_user_pid(who) };
            if let Some(t) = t { f(&t); }
        }
        Which::Pgrp => {
            let pgid = if who == 0 {
                sched::live::current().map(|c| c.pgid()).unwrap_or(0)
            } else { who };
            for t in sched::live::registry::tasks_in_pgrp(pgid) { f(&t); }
        }
        Which::User => {
            let Some(cur) = sched::live::current() else { return; };
            // `who` is a namespace-relative uid and is translated to the
            // internal id credentials actually store. An id the caller's user
            // namespace does not map names no task at all, so the target set
            // is empty and the caller reports its seed ESRCH.
            let mapped = sched::cred::make_kuid(who);
            let caller_ruid = cur.creds.ruid.load(Ordering::Acquire);
            let Some(uid) = user_target_uid(who, caller_ruid, mapped) else { return; };
            // The pid-namespace visibility guard, resolved once for the walk
            // instead of per task.
            let ns = sched::live::registry::caller_pid_ns();
            for tid in sched::live::registry::live_tids() {
                if let Some(t) = sched::live::registry::lookup(tid) {
                    let visible = match &ns {
                        Some(ns) => sched::live::registry::vnr_in(&t, ns).is_some(),
                        None => true,
                    };
                    let ruid = t.creds.ruid.load(Ordering::Acquire);
                    if user_target_matches(uid, ruid, visible) { f(&t); }
                }
            }
        }
    }
}
