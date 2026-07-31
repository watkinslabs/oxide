// 062 kill — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use syscall::errno::Errno;
use syscall::SyscallArgs;
use sched::sigsend::{SigSource, SigTarget};

use crate::kill_policy::{classify, signal_valid, BroadcastFold, PgrpFold, PidClass};
use crate::signal_common::*;

/// `sys_kill(pid, sig)` — slot 62. Linux `kill_something_info`.
///
///   `pid > 0`  — that process (PIDTYPE_TGID: the group's shared pending set,
///                never one thread's private one).
///   `pid == 0` — every process in the caller's process group.
///   `pid == -1`— every process the caller may signal except init and its own
///                thread group, with EPERM swallowed (see `BroadcastFold`).
///   `pid < -1` — every process in group `-pid`.
///
/// `sig == 0` is the permission probe: every check runs, nothing is sent.
///
/// Error ORDER is Linux's, and it is not the obvious one: the target is
/// resolved FIRST, so a `kill(2)` naming a nonexistent pid answers ESRCH even
/// when the signal number is also invalid. EINVAL and EPERM both come out of
/// `check_kill_permission`, which only runs once a target exists.
/// # C: O(N_tasks) on a group fan; O(log N) for a single pid
pub fn sys_kill(args: &SyscallArgs) -> i64 {
    let pid = args.a0 as i32;
    let sig = args.a1 as i32;
    let Some(cur) = sched::live::current() else {
        return -(Errno::Esrch.as_i32() as i64);
    };
    // Linux `prepare_kill_siginfo`: `kill(2)` sends SEND_SIG_NOINFO, which
    // `__send_signal_locked` expands into si_code = SI_USER plus the SENDER's
    // pid and uid. Posting `None` (the prior behaviour) left an SA_SIGINFO
    // handler and every `signalfd`/`rt_sigtimedwait` consumer reading
    // si_pid == 0, si_uid == 0 — systemd's `sd_event` signal handlers key on
    // si_pid to tell a child's death from an operator's `systemctl kill`.
    let src = SigSource::User {
        pid: cur.vtgid.load(Ordering::Acquire),
        uid: cur.creds.ruid.load(Ordering::Acquire),
    };
    match classify(pid) {
        PidClass::NoSuchGroup => -(Errno::Esrch.as_i32() as i64),
        PidClass::Process(vpid) => {
            let namespace = match cur.namespace_owner(namespace_identity::NamespaceKind::Pid) {
                Some(namespace) => namespace,
                None => return -(Errno::Esrch.as_i32() as i64),
            };
            match sched::registry::lookup_in_namespace(&namespace, vpid) {
                Some(t) => post_one(cur, &t, sig, src),
                None => -(Errno::Esrch.as_i32() as i64),
            }
        }
        PidClass::CallerPgrp => post_pgrp(cur, cur.pgid(), sig, src),
        PidClass::Pgrp(pgid) => post_pgrp(cur, pgid, sig, src),
        PidClass::Broadcast  => post_broadcast(cur, sig, src),
    }
}

/// Linux `group_send_sig_info`: `check_kill_permission` (EINVAL then EPERM),
/// then `do_send_sig_info(..., PIDTYPE_TGID)` — but only when `sig != 0`.
/// # C: O(N_threads)
fn post_one(cur: &sched::Task, t: &Arc<sched::Task>, sig: i32, src: SigSource) -> i64 {
    if !signal_valid(sig) { return -(Errno::Einval.as_i32() as i64); }
    if !sig_perm_check(cur, t, sig) { return -(Errno::Eperm.as_i32() as i64); }
    if sig == 0 { return 0; }
    match sched::live::send_signal(t, sig as u32, src, SigTarget::Process) {
        Ok(()) => 0,
        // `kill(2)` is documented never to fail with EAGAIN, and the enqueue
        // agrees: a standard signal overrides the pending ceiling and an RT
        // signal from `kill(2)` loses its record rather than failing. This arm
        // therefore cannot be reached from here — it exists so a future caller
        // that DOES pass a queued record gets the right errno rather than 0.
        Err(sched::live::SendErr::Again) => -(Errno::Eagain.as_i32() as i64),
    }
}

/// `kill(-1)` fan-out. Linux visits every process with `task_pid_vnr(p) > 1`
/// that is not in the caller's thread group — note it does NOT skip a
/// permission-denied target, it counts it and swallows the EPERM.
/// # C: O(N_tasks)
fn post_broadcast(cur: &sched::Task, sig: i32, src: SigSource) -> i64 {
    let Some(tasks) = sched::registry::try_snapshot() else {
        return -(Errno::Esrch.as_i32() as i64);
    };
    let cur_tgid = cur.tgid.load(Ordering::Acquire);
    let mut fold = BroadcastFold::new();
    for t in &tasks {
        if t.reaped.load(Ordering::Acquire) { continue; }
        let vtgid = t.vtgid.load(Ordering::Acquire);
        // vpid 0 is a kernel thread (no user pid at all); vpid 1 is init, which
        // Linux excludes from the broadcast by the `> 1` test.
        if vtgid <= 1 { continue; }
        // `__kill_pgrp_info`-style one-visit-per-PROCESS: the pid hash holds
        // only group leaders, so a per-thread walk would run the send N times.
        if !is_group_leader(t) { continue; }
        // Linux `!same_thread_group(p, current)` — the whole calling process is
        // excluded, not merely the calling thread.
        if t.tgid.load(Ordering::Acquire) == cur_tgid { continue; }
        fold.visit(post_one(cur, t, sig, src));
    }
    fold.finish()
}

/// Linux hashes only group leaders into `PIDTYPE_PGID`, so `__kill_pgrp_info`
/// visits each PROCESS once.
/// # C: O(1)
fn is_group_leader(t: &sched::Task) -> bool {
    t.tid == t.tgid.load(Ordering::Acquire)
}

/// Linux `__kill_pgrp_info`. # C: O(N_tasks)
fn post_pgrp(cur: &sched::Task, pgid: u32, sig: i32, src: SigSource) -> i64 {
    let mut fold = PgrpFold::new();
    for t in &sched::live::registry::tasks_in_pgrp(pgid) {
        if !is_group_leader(t) { continue; }
        fold.visit(post_one(cur, t, sig, src));
    }
    fold.finish()
}
