// `find_child_reaper` / `find_new_reaper` (Linux `kernel/exit.c`): who adopts
// the children of an exiting task.
//
//   1. another live thread of our own thread group, if one exists
//      (`find_alive_thread`) — a thread that exits must NOT hand its children
//      to init while its process is still running;
//   2. the nearest ancestor inside our pid namespace that set
//      `PR_SET_CHILD_SUBREAPER` (a service manager), skipping ancestors with
//      no live thread and stopping at the init task;
//   3. the `child_reaper` of our OWN pid namespace — NOT always global PID 1.

/// One candidate on the walk from `father->real_parent` upward.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Ancestor {
    pub tid: u32,
    /// `task_pid(reaper)->level`; the walk stops when it leaves the level of
    /// the exiting task, so a `setns()`-injected parent cannot pull children
    /// into another namespace.
    pub ns_level: u32,
    pub is_child_subreaper: bool,
    /// `find_alive_thread(reaper)` — a member not already `PF_EXITING`.
    pub alive_thread: Option<u32>,
    /// The chain terminates at `&init_task`.
    pub is_init_task: bool,
}

/// Adoption target.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NewReaper {
    /// A still-live thread of the exiting task's own group.
    AliveSibling(u32),
    /// A `PR_SET_CHILD_SUBREAPER` ancestor's live thread.
    Subreaper(u32),
    /// The `child_reaper` of the exiting task's pid namespace.
    NsInit,
}

/// Linux `find_new_reaper`. `has_child_subreaper` is the exiting task's
/// `signal->has_child_subreaper` (set when any ancestor asked to be one);
/// `ns_level` is the exiting task's pid level.
/// # C: O(N_ancestors)
pub fn find_new_reaper(
    alive_sibling: Option<u32>,
    has_child_subreaper: bool,
    ns_level: u32,
    ancestors: &[Ancestor],
) -> NewReaper {
    if let Some(tid) = alive_sibling { return NewReaper::AliveSibling(tid); }
    if !has_child_subreaper { return NewReaper::NsInit; }
    for a in ancestors {
        if a.ns_level != ns_level { break; }
        if a.is_init_task { break; }
        if !a.is_child_subreaper { continue; }
        if let Some(tid) = a.alive_thread { return NewReaper::Subreaper(tid); }
    }
    NewReaper::NsInit
}

/// Linux `find_child_reaper`: when the pid namespace's own `child_reaper` is
/// the task that is exiting, leadership passes to one of its live threads;
/// if none remain the namespace itself is torn down
/// (`zap_pid_ns_processes`).
/// # C: O(1)
pub const fn child_reaper_succession(
    reaper_is_father: bool,
    alive_sibling: Option<u32>,
) -> ChildReaperSuccession {
    if !reaper_is_father { return ChildReaperSuccession::Unchanged; }
    match alive_sibling {
        Some(tid) => ChildReaperSuccession::Promote(tid),
        None      => ChildReaperSuccession::ZapNamespace,
    }
}

/// Result of [`child_reaper_succession`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ChildReaperSuccession {
    /// The namespace's reaper is somebody else; nothing to do.
    Unchanged,
    /// Another thread of the dying reaper takes the role.
    Promote(u32),
    /// The namespace lost its init: every member dies.
    ZapNamespace,
}
