// `kill_orphaned_pgrp` (Linux `kernel/exit.c`, POSIX 3.2.2.2): when this exit
// orphans a process group that still holds stopped jobs, the group gets SIGHUP
// then SIGCONT — otherwise those jobs stay frozen with nothing left able to
// resume them (a `^Z`ed job under a shell whose session leader dies).

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use crate::exit::orphan::{should_kill_orphaned_pgrp, PgrpMember};
use crate::signum::Signum;
use crate::{registry, Task, TaskState};

/// Snapshot the POSIX facts about every member of `pgid`. # C: O(N_tasks)
fn members(pgid: u32) -> Vec<PgrpMember> {
    registry::tasks_in_pgrp(pgid)
        .iter()
        .map(|p| {
            let parent = p.parent();
            let parent_is_init = parent.as_ref().is_some_and(|q| {
                q.vtgid.load(Ordering::Acquire) == super::pidns::INIT_VPID
                    && super::pidns::in_initial_pid_namespace(q)
            });
            PgrpMember {
                tid: p.tid,
                sid: p.sid(),
                exiting: matches!(p.state(), TaskState::Zombie),
                thread_group_empty: p.thread_group.is_single_member(),
                stopped: matches!(p.state(), TaskState::Stopped),
                parent_is_init,
                parent_pgid: parent.as_ref().map(|q| q.pgid()).unwrap_or(0),
                parent_sid: parent.as_ref().map(|q| q.sid()).unwrap_or(0),
            }
        })
        .collect()
}

/// Post `sig` to every member of `pgid` and wake it. # C: O(N_tasks)
fn kill_pgrp(pgid: u32, sig: Signum) {
    for t in registry::tasks_in_pgrp(pgid) {
        t.sigpending.fetch_or(sig.bit(), Ordering::Release);
        crate::live::signal_wake_up(&t);
    }
}

/// Linux `kill_orphaned_pgrp(tsk, parent)`.
///
/// `reparenting` selects which of Linux's two call sites this is:
///   * `false` — `exit_notify`'s `kill_orphaned_pgrp(tsk->group_leader, NULL)`:
///     the reference parent is `tsk`'s own real parent and `tsk` is excluded
///     from the orphan scan, because it is the connection that is going away;
///   * `true` — `reparent_leader`'s `kill_orphaned_pgrp(p, father)`: the
///     reference parent is the reparenting father and nothing is excluded.
/// # C: O(N_tasks)
pub fn kill_orphaned_pgrp(task: &Task, reparenting_father: Option<&Task>) {
    let pgrp = task.pgid();
    let session = task.sid();
    let (parent_pgid, parent_sid, ignored) = match reparenting_father {
        Some(f) => (f.pgid(), f.sid(), None),
        None => {
            let Some(p) = task.parent() else { return };
            (p.pgid(), p.sid(), Some(task.tid))
        }
    };
    let members = members(pgrp);
    if !should_kill_orphaned_pgrp(pgrp, session, parent_pgid, parent_sid, &members, ignored) {
        return;
    }
    kill_pgrp(pgrp, Signum::Sighup);
    kill_pgrp(pgrp, Signum::Sigcont);
}
