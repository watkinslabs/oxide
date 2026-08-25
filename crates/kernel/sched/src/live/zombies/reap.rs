use core::sync::atomic::Ordering;

use crate::Task;
use crate::registry::{self, wait_candidate_matches, WaitChildSnapshot};
use crate::wait_select::{Candidate, Waiter};
use super::{notify_real_parent_of_zombie, ZOMBIES};
use super::notify::accrue_child_rusage;

/// Reap one Zombie child matching the `wait4` filter
/// (`wait_pid_matches`). Returns `Some((tid, exit_code))` and drops
/// the strong-ref so the Task is freed. `None` if no matching Zombie
/// is queued.
/// # C: O(N_zombies)
/// True iff any queued zombie has `parent_tid == parent`. Used
/// by `sys_wait4` to decide whether to clear the SIGCHLD pending
/// bit after a reap (F237 — keeps a signal_dispatch SIGCHLD
/// from firing after wait4 already drained the zombies, which
/// would make the shell's handler re-wait → ECHILD → $?=255).
/// # C: O(N_zombies)
pub fn has_zombies(parent: u32) -> bool {
    use core::sync::atomic::Ordering;
    ZOMBIES.lock().iter().any(|t| t.parent_tid.load(Ordering::Acquire) == parent)
}

/// # C: O(N_tasks)
fn zombie_candidate(t: &Task) -> Candidate {
    let parent_tid = t.parent_tid.load(Ordering::Acquire);
    let tracer_tid = t.traced_by.load(Ordering::Acquire);
    let tgid_of = |tid: u32| registry::lookup(tid)
        .map(|p| p.tgid.load(Ordering::Acquire))
        .unwrap_or(0);
    Candidate {
        parent_tid,
        parent_tgid: tgid_of(parent_tid),
        tracer_tid,
        tracer_tgid: tgid_of(tracer_tid),
        vpid: crate::registry::leader_tgid_nr_in(t, &crate::registry::reader_pid_ns())
            .unwrap_or(0),
        pgid:        t.pgrp().tid,
        exit_signal: t.exit_signal.load(Ordering::Acquire),
    }
}

/// Peek one Zombie child matching the `wait4` filter WITHOUT removing
/// it — the `waitid(2)` `WNOWAIT` contract (leave the child in a
/// waitable state). Same filter as `reap_one`. systemd's SIGCHLD
/// handler peeks with `WEXITED|WNOHANG|WNOWAIT` to learn which unit a
/// pid belongs to, then reaps separately; if the peek reaped, that
/// second wait would get ECHILD and systemd mis-supervises the service.
/// # C: O(N_zombies)
pub fn peek_one(parent: u32, parent_tgid: u32, pid: i32, parent_pgid: u32, options: u64) -> Option<(WaitChildSnapshot, i32)> {
    let q = ZOMBIES.lock();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    let t = q.iter().find(|t| wait_candidate_matches(zombie_candidate(t), waiter, pid, options))?;
    Some((WaitChildSnapshot::from_task(t), crate::exit::wait_status(t)))
}

/// # C: O(N_zombies)
pub fn reap_one(parent: u32, parent_tgid: u32, pid: i32, parent_pgid: u32, options: u64) -> Option<(WaitChildSnapshot, i32)> {
    // Seam: before the list lock, so a schedule can place a reaper anywhere in
    // an exiting task's publication sequence.
    #[cfg(test)] crate::tests::interleave::point("reap:entry");
    let mut q = ZOMBIES.lock();
    #[cfg(feature = "debug-ssh")]
    {
        let total = q.len();
        let mine = q.iter().filter(|t| t.parent_tid.load(Ordering::Acquire) == parent).count();
        klog::write_raw(b"[INFO]  ssh-trace: reap_one parent=");
        klog::write_dec_u64(parent as u64);
        klog::write_raw(b" pid=");
        klog::write_dec_u64(pid as i64 as u64);
        klog::write_raw(b" zombies_total=");
        klog::write_dec_u64(total as u64);
        klog::write_raw(b" zombies_for_parent=");
        klog::write_dec_u64(mine as u64);
        klog::write_raw(b"\n");
        // Show each zombie's (tid, parent_tid) so a parent/pid mismatch is visible.
        for t in q.iter() {
            klog::write_raw(b"[INFO]  ssh-trace:   zombie tid=");
            klog::write_dec_u64(t.tid as u64);
            klog::write_raw(b" parent_tid=");
            klog::write_dec_u64(t.parent_tid.load(Ordering::Acquire) as u64);
            klog::write_raw(b"\n");
        }
    }
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    let pos = q.iter().position(|t| wait_candidate_matches(zombie_candidate(t), waiter, pid, options))?;
    // Linux `wait_task_zombie`'s EXIT_TRACE arm. A tracer reaping a tracee it
    // did NOT fork must not consume the zombie: the real parent is still owed
    // its `wait4`. Linux reports the status to the tracer, then `ptrace_unlink`s
    // and re-runs `do_notify_parent(p, p->exit_signal)`, leaving the zombie for
    // the real parent. Removing it here instead would give the shell that
    // spawned the process an ECHILD the moment anything straced it.
    let reparented_tracee = {
        let c = zombie_candidate(&q[pos]);
        crate::wait_select::ptrace_scope_matches(c, waiter, options)
            && c.parent_tgid != c.tracer_tgid
    };
    if reparented_tracee {
        let t = alloc::sync::Arc::clone(&q[pos]);
        let child = WaitChildSnapshot::from_task(&t);
        let code = crate::exit::wait_status(&t);
        drop(q);
        // `ptrace_unlink(p)` — the tracer is done with it.
        t.traced_by.store(0, Ordering::Release);
        t.ptrace_options.store(0, Ordering::Release);
        t.security.ptrace_seized.store(false, Ordering::Release);
        // `do_notify_parent(p, p->exit_signal)` again, now that `parent` has
        // reverted to `real_parent`.
        notify_real_parent_of_zombie(&t);
        return Some((child, code));
    }
    let t = q.remove(pos);
    // Return the child's vpid (vtgid) — the PID userspace waited on — NOT the
    // opaque internal tid. Single pid identity (Linux): waitpid returns the
    // same value fork() returned.
    let child = WaitChildSnapshot::from_task(&t);
    let code = crate::exit::wait_status(&t);
    let is_leader = t.pid.is_group_leader();
    drop(q);
    // Linux `wait_task_zombie`, `state == EXIT_DEAD && thread_group_leader(p)`:
    // this is the ONLY arm that consumes the zombie, so it is the only one that
    // accumulates. The `WNOWAIT` peek and the `EXIT_TRACE` hand-back above both
    // leave the child waitable and must not account it — the real parent's
    // later reap will. The credit goes to the REAPER's process (`current->
    // signal`), which is `parent` here by construction, so a child reparented
    // to the subreaper is accounted to whoever actually waited for it.
    if is_leader {
        if let Some(reaper) = registry::lookup(parent) {
            accrue_child_rusage(&reaper, child.rusage);
        }
    }
    // Linux release_task: a reaped process leaves /proc immediately, even if a
    // pidfd still pins the task_struct. Mark it so procfs enumeration drops it —
    // otherwise a pidfd-pinned reaped child lingers as a visible zombie in
    // ps/htop (the strong Arc keeps the registry Weak alive).
    registry::mark_reaped(&t);
    drop(t);  // strong-ref released; Task freed if no other holders
    Some((child, code))
}

/// # C: O(N_zombies × N_tasks)
pub fn has_wait_zombies(parent: u32, parent_tgid: u32, pid: i32, parent_pgid: u32, options: u64) -> bool {
    let q = ZOMBIES.lock();
    let waiter = Waiter { tid: parent, tgid: parent_tgid, pgid: parent_pgid };
    q.iter().any(|t| wait_candidate_matches(zombie_candidate(t), waiter, pid, options))
}
