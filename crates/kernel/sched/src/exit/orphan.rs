// `will_become_orphaned_pgrp` / `has_stopped_jobs` / `kill_orphaned_pgrp`
// (Linux `kernel/exit.c`, POSIX 2.2.2.52 + 3.2.2.2).
//
// A process group is orphaned when no member has a parent that is in a
// DIFFERENT process group of the SAME session — i.e. nothing outside the group
// can still drive its job control. If this exit orphans such a group and any
// member is stopped, the group is sent SIGHUP then SIGCONT, so stopped jobs
// are not left frozen with no shell able to resume them.

/// One member of the process group under test, plus the facts about its real
/// parent the POSIX rule needs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PgrpMember {
    pub tid: u32,
    pub sid: u32,
    /// `p->exit_state` is set (zombie/dead).
    pub exiting: bool,
    /// `thread_group_empty(p)`.
    pub thread_group_empty: bool,
    /// `p->signal->flags & SIGNAL_STOP_STOPPED`.
    pub stopped: bool,
    /// `is_global_init(p->real_parent)`.
    pub parent_is_init: bool,
    pub parent_pgid: u32,
    pub parent_sid: u32,
}

/// Linux `will_become_orphaned_pgrp`. `ignored_tid` is the task whose exit is
/// being evaluated (`None` on the reparent path, where the child is kept in
/// the scan).
/// # C: O(N_members)
pub fn will_become_orphaned_pgrp(members: &[PgrpMember], pgrp: u32, ignored_tid: Option<u32>) -> bool {
    for p in members {
        if Some(p.tid) == ignored_tid { continue; }
        if p.exiting && p.thread_group_empty { continue; }
        if p.parent_is_init { continue; }
        if p.parent_pgid != pgrp && p.parent_sid == p.sid { return false; }
    }
    true
}

/// Linux `has_stopped_jobs`. # C: O(N_members)
pub fn has_stopped_jobs(members: &[PgrpMember]) -> bool {
    members.iter().any(|p| p.stopped)
}

/// Linux `kill_orphaned_pgrp`: whether SIGHUP+SIGCONT must go to `pgrp`.
///
/// `parent_pgid`/`parent_sid` describe the reference parent — the exiting
/// task's own real parent on the exit path (`parent == NULL`, `ignored_tid =
/// Some(tsk)`), or the reparenting father on the reparent path
/// (`ignored_tid = None`).
/// # C: O(N_members)
pub fn should_kill_orphaned_pgrp(
    pgrp: u32,
    session: u32,
    parent_pgid: u32,
    parent_sid: u32,
    members: &[PgrpMember],
    ignored_tid: Option<u32>,
) -> bool {
    parent_pgid != pgrp
        && parent_sid == session
        && will_become_orphaned_pgrp(members, pgrp, ignored_tid)
        && has_stopped_jobs(members)
}
