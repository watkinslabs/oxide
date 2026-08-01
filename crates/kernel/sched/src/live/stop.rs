// SIGSTOP / SIGCONT scheduler glue per `28§4` / signal(7).
//
// Self-stop: dispatch tail calls `stop_until_cont` after observing
// a SIGSTOP / default-disposition SIGTSTP / SIGTTIN / SIGTTOU. We
// flip current.state = Stopped + voluntary schedule(); the picker
// won't re-enqueue Stopped tasks. SIGCONT delivery (kill path)
// flips the target back to Runnable + re-enqueues, so the next
// schedule() round picks it up and we resume.

// Arch-neutral now: only uses sched + state primitives that exist on
// both arches. Pre-F16 was gated x86-only by oversight, blocking the
// SIGSTOP / SIGTSTP / SIGTTIN / SIGTTOU default-stop disposition on
// aarch64.

use core::sync::atomic::Ordering;

use crate::exit::notify::{cldstop_notify, Cldstop, ParentSigchld};
use crate::jobctl::{self, NotifyTarget, StopKind, WakeKind};
use crate::TaskState;

/// Flip current to Stopped + schedule away. Loops until SIGCONT
/// (or any signal flipping state back to Runnable) wakes us.
/// # SAFETY: dispatch tail context — process / kthread, preempt-off,
/// running task is the live one on this CPU.
/// # C: O(N_schedule) until cont
pub fn stop_until_cont() {
    stop_until_cont_sig(crate::Signum::Sigstop as u8)
}

/// Variant of `stop_until_cont` recording the originating stop signal
/// (SIGSTOP=19/SIGTSTP=20/SIGTTIN=21/SIGTTOU=22) as the stop code
/// `wait4(WUNTRACED)` reports. A job-control stop's code IS its signal; the
/// wider ptrace event codes come from `syscall::ptrace`.
/// # C: O(N_schedule) until cont
pub fn stop_until_cont_sig(sig: u8) { stop_until_cont_code(sig as u32, StopKind::JobControl) }

/// The full-width form. A ptrace event stop's code is `SIGTRAP | (event <<
/// 8)`, which does not fit the byte a job-control stop uses — passing it
/// through `stop_until_cont_sig` truncated the event byte away and every
/// event stop reported as a bare SIGTRAP.
///
/// `kind` separates Linux's two distinct stops. A job-control stop is reported
/// to the REAL parent as `CLD_STOPPED` and its SIGCONT resume as
/// `CLD_CONTINUED`; a ptrace stop is reported to the TRACER as `CLD_TRAPPED`
/// and its resume is not an event at all. Reporting both as
/// `CLD_STOPPED`/`CLD_CONTINUED` to the real parent meant every single
/// `PTRACE_SYSCALL` step of a traced process fired a spurious `SIGCHLD` pair at
/// the shell that started it, and a `wait4(WCONTINUED)` event that never
/// happened.
/// # C: O(N_schedule) until cont
pub fn stop_until_cont_code(code: u32, kind: StopKind) {
    let cur = match crate::live::current() { Some(c) => c, None => return };
    let sig = (code & 0xff) as u8;
    cur.stop_code.store(code, Ordering::Release);
    cur.stop_pending.store(true, Ordering::Release);
    cur.jobctl.fetch_or(match kind {
        StopKind::Ptrace     => jobctl::TRACED,
        StopKind::JobControl => jobctl::STOPPED,
    }, Ordering::AcqRel);
    cur.set_state(TaskState::Stopped);
    if group_stop_notifies(cur, kind) {
        notify_parent_cldstop(cur, jobctl::stop_si_code(kind), sig as u32,
                              jobctl::notify_target(kind));
    }
    loop {
        // SAFETY: process context, preempt-off, single-CPU; same as voluntary `schedule()` per `13§8`.
        unsafe { crate::live::schedule(); }
        if cur.state() == TaskState::Runnable {
            let wake = WakeKind::from_u8(cur.stop_wake.load(Ordering::Acquire));
            // `PTRACE_LISTEN`'s contract: the tracee stays stopped, and an
            // asynchronous event re-traps it so the tracer is told, instead of
            // silently resuming it into userspace with the event unreported.
            if jobctl::wake_retraps(cur.jobctl.load(Ordering::Acquire), wake) {
                cur.jobctl.fetch_and(!jobctl::TRAP_NOTIFY, Ordering::AcqRel);
                cur.stop_code.store(code, Ordering::Release);
                cur.stop_pending.store(true, Ordering::Release);
                cur.set_state(TaskState::Stopped);
                notify_parent_cldstop(cur, jobctl::stop_si_code(kind), sig as u32,
                                      jobctl::notify_target(kind));
                continue;
            }
            cur.jobctl.fetch_and(!(jobctl::TRACED | jobctl::STOPPED), Ordering::AcqRel);
            if let Some(why) = jobctl::resume_notify(kind, wake) {
                notify_parent_cldstop(cur, why, crate::Signum::Sigcont as u32,
                                      NotifyTarget::RealParent);
            }
            return;
        }
        // The pick may return us only if no other Runnable task
        // exists (Stopped tasks aren't re-enqueued by schedule).
        // Re-spin: wake_if_stopped on SIGCONT will flip state +
        // re-enqueue; only when that happens do we exit the loop.
        // Defensive: clear any pending SIGSTOP so we don't loop on
        // it forever (Linux wouldn't redeliver SIGSTOP to a Stopped
        // task either).
        cur.sigpending.fetch_and(!(1u64 << 18), Ordering::Release);
    }
}

/// Linux `task_participate_group_stop` folded together with `do_signal_stop`'s
/// `notify` decision: whether THIS park is the one that owes a report.
///
/// A ptrace stop always reports — it is per-tracee, and its audience is the
/// tracer. A job-control stop is per-PROCESS: the group stop is complete only
/// once every thread has parked, and exactly ONE `CLD_STOPPED` is owed for it.
/// Reporting per-thread made a `^Z` on a threaded process fire one `SIGCHLD`
/// per thread at the shell.
/// # C: O(1)
fn group_stop_notifies(cur: &crate::Task, kind: StopKind) -> bool {
    if kind == StopKind::Ptrace { return true; }
    // Take on the counter debt unless this thread already carries one, so a
    // thread re-parking inside one group stop cannot pay for it twice.
    let jc = cur.jobctl.fetch_or(jobctl::STOP_PENDING | jobctl::STOP_CONSUME, Ordering::AcqRel)
        | jobctl::STOP_PENDING | jobctl::STOP_CONSUME;
    let step = cur.thread_group.join_group_stop(jc);
    cur.jobctl.store(step.jobctl, Ordering::Release);
    step.completed
}

/// Linux `do_notify_parent_cldstop` wiring for a self-stop / resume. Posts
/// SIGCHLD when the parent's disposition allows it and ALWAYS wakes a
/// `wait4`-blocked parent — a stop that notified nobody left
/// `waitpid(WUNTRACED)` asleep through the stop it was waiting for, which is
/// what made a backgrounded tty read look like a hang rather than a stop.
///
/// `to` is `do_notify_parent_cldstop`'s `for_ptracer` argument: a ptrace stop
/// is announced to the tracer (`tsk->parent`), a job-control stop to the real
/// parent (`tsk->real_parent`). A tracee whose tracer has since detached falls
/// back to the real parent rather than notifying nobody.
/// # Ctx: dispatch tail, process context, preempt-off.
/// # C: O(N_waiters)
fn notify_parent_cldstop(cur: &crate::Task, why: Cldstop, status_sig: u32, to: NotifyTarget) {
    let tracer = match to {
        NotifyTarget::Tracer => {
            let tid = cur.traced_by.load(Ordering::Acquire);
            if tid == 0 { None } else { crate::registry::lookup(tid) }
        }
        NotifyTarget::RealParent => None,
    };
    let parent = match tracer { Some(t) => t, None => match cur.parent() {
        Some(p) => p, None => return,
    } };
    let act = parent.sigactions_ref().get(crate::Signum::Sigchld as u32);
    let n = cldstop_notify(why, ParentSigchld { handler: act.handler, flags: act.flags });
    let info = crate::task::SigInfo {
        signo: crate::Signum::Sigchld as u32,
        code:  n.si_code,
        // Read by the parent, so numbered in the PARENT's pid namespace.
        pid:   crate::registry::tgid_nr_seen_by(cur, &parent),
        uid:   cur.creds.ruid.load(Ordering::Acquire),
        value: status_sig as u64,
        sys:   None, fault: None, poll: None
    };
    // `do_notify_parent_cldstop` is `__group_send_sig_info(SIGCHLD, &info,
    // parent)` — PROCESS-directed, so any thread of a threaded supervisor can
    // collect the stop event even when its leader blocks SIGCHLD.
    //
    // The send comes BEFORE the `wait4` wake, the same order `zombies` uses: a
    // waiter must never be roused ahead of the event it will inspect. The cost
    // is a `WAITERS` entry that stays parked because `wake_wait4_parent` only
    // claims a waiter it still observes as `Sleeping`, which the dedup guard in
    // `park_for_wait4` already handles.
    if n.signal {
        let _ = crate::live::send::send_signal(&parent, crate::Signum::Sigchld as u32,
            crate::sigsend::SigSource::Info(info), crate::sigsend::SigTarget::Process);
    }
    if n.wake_parent { crate::live::zombies::wake_wait4_parent(parent.tid); }
}
