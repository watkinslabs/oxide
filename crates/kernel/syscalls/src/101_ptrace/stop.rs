// `ptrace_notify` / `ptrace_event` / `ptrace_event_pid` — the live glue that
// puts a tracee into a `PTRACE_EVENT_*` stop. The policy (which event, whether
// it is enabled, what the child inherits) is the ungated sibling
// `101_ptrace/event.rs`; this file only reads task state, records the event
// message and parks.
//
// Every producer in the tree routes through `event` / `notify` here, so the
// stop code a tracer's `wait` sees and the `si_code` its `PTRACE_GETSIGINFO`
// reads are composed in exactly one place.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use core::sync::atomic::Ordering;

use sched::{Signum, Task};

use crate::s101_ptrace_event as event;
use crate::s101_ptrace_sigstop as sigstop;
use crate::s101_ptrace_uapi as uapi;

/// Linux `ptrace_notify(exit_code, message)`: record the message
/// `PTRACE_GETEVENTMSG` reports, publish the `last_siginfo` a
/// `PTRACE_GETSIGINFO` reads, and stop until the tracer resumes us.
///
/// No signal is queued. Linux's `ptrace_notify` sets `last_siginfo` and calls
/// `ptrace_stop` directly — a real `SIGTRAP` posted here would still be
/// pending after the tracer's `PTRACE_CONT`, and would then kill the tracee
/// with its default action on the way back to user mode.
/// Returns the signal the tracer named on resume (Linux `ptrace_stop` returns
/// `current->exit_code`, which `ptrace_resume` overwrote with its `data`).
/// `stop_code` doubles as that cell exactly as Linux's `exit_code` does: it is
/// seeded with the reported code before parking, so a tracee woken by anything
/// OTHER than its tracer — a fatal signal, the tracer dying — reads back what
/// it reported instead of losing it.
/// # Ctx: the tracee itself, process context.
/// # Sleeps: yes — parks until the tracer resumes it.
/// # C: O(N_schedule) until the tracer resumes
pub fn notify(stop_code: i32, message: u64) -> u32 {
    notify_with(stop_code, message, sched::SigInfo {
        signo: Signum::Sigtrap as u32, code: stop_code,
        pid: 0, uid: 0, value: 0, sys: None, fault: None, poll: None,
    }).0
}

/// `ptrace_notify` with a caller-supplied `last_siginfo`. A signal-delivery
/// stop reports the SIGNAL's record, not a synthesised SIGTRAP, so a tracer's
/// `PTRACE_GETSIGINFO` sees what actually arrived — and its `PTRACE_SETSIGINFO`
/// rewrites the very record the tracee then delivers (Linux keeps a POINTER to
/// the pending `kernel_siginfo_t` in `last_siginfo`, so the rewrite is in
/// place). The caller reads the record back out after this returns.
/// # Ctx: the tracee itself, process context.
/// # Sleeps: yes — parks until the tracer resumes it.
/// # C: O(N_schedule) until the tracer resumes
pub fn notify_with(stop_code: i32, message: u64, mut info: sched::SigInfo)
    -> (u32, Option<sched::SigInfo>)
{
    let Some(cur) = sched::live::current() else { return (0, None) };
    cur.ptrace_eventmsg.store(message, Ordering::Release);
    // The record is read by the TRACEE (and by the tracer through
    // PTRACE_GETSIGINFO), so the tracer is named by the number the tracee's pid
    // namespace gives it — never the opaque internal tid.
    if info.pid == 0 {
        let tracer = cur.traced_by.load(Ordering::Acquire);
        info.pid = sched::live::registry::lookup(tracer)
            .map(|t| sched::registry::tgid_nr_seen_by(&t, &cur))
            .unwrap_or(0);
    }
    *cur.ptrace_siginfo.lock() = Some(info);
    crate::ptrace_fpu::snapshot_current();
    sched::live::stop::stop_until_cont_code(stop_code as u32, sched::jobctl::StopKind::Ptrace);
    crate::ptrace_fpu::restore_if_dirty();
    // Linux `ptrace_stop`'s tail: `exit_code = current->exit_code;
    // current->last_siginfo = NULL; current->ptrace_message = 0;
    // current->exit_code = 0;`. The record is read back BEFORE it is dropped
    // because `PTRACE_SETSIGINFO` may have rewritten it while we slept, and
    // that rewrite is what the tracee must deliver. Clearing it on the TRACER
    // side (in `ptrace_resume`) would race the tracee's read and throw the
    // rewrite away — Linux clears it here, on the tracee, for that reason.
    let edited = cur.ptrace_siginfo.lock().take();
    let resume_sig = cur.stop_code.swap(0, Ordering::AcqRel);
    cur.ptrace_eventmsg.store(0, Ordering::Release);
    (resume_sig, edited)
}

/// Linux `ptrace_event(event, message)`. Reports `event` when the tracer
/// enabled it; the `PTRACE_EVENT_EXEC` arm additionally falls back to the
/// legacy bare `SIGTRAP` for a classically-attached tracee whose tracer never
/// set `PTRACE_O_TRACEEXEC`.
/// # Ctx: the tracee itself, process context.
/// # Sleeps: yes when the event is reported.
/// # C: O(N_schedule) when the event is reported, O(1) otherwise
pub fn ptrace_event(ev: u32, message: u64) {
    let Some(cur) = sched::live::current() else { return };
    let traced = cur.traced_by.load(Ordering::Acquire) != 0;
    let opts = cur.ptrace_options.load(Ordering::Acquire);
    if traced && event::event_enabled(opts, ev) {
        notify(uapi::event_stop_code(ev), message);
        return;
    }
    if ev == uapi::EVENT_EXEC {
        let seized = cur.ptrace_seized.load(Ordering::Acquire);
        if event::legacy_exec_sigtrap(traced, seized, opts) {
            sched::live::send_signal_self(Signum::Sigtrap);
        }
    }
}

/// Linux `ptrace_signal(signr, info, type)` — the signal-delivery-stop.
///
/// The signal has ALREADY been dequeued when this runs, so a tracer that
/// cancels it drops it for good and one that substitutes replaces it. The stop
/// reports the bare signal number as its stop code (`CLD_TRAPPED`, wait status
/// `WSTOPSIG() == signr`), which is how `strace` names the signal it caught.
///
/// Returns the decision plus the record to deliver with: the tracer's
/// `PTRACE_SETSIGINFO` edit when it made one, a fresh `SI_USER` record
/// attributed to the tracer when it substituted a different signal, and the
/// original otherwise.
/// # Ctx: the tracee itself, on its return-to-user path.
/// # Sleeps: yes — parks until the tracer resumes it.
/// # C: O(N_schedule) until the tracer resumes
pub fn signal_stop(sig: u32, info: Option<sched::SigInfo>)
    -> (sigstop::Outcome, Option<sched::SigInfo>)
{
    let Some(cur) = sched::live::current() else {
        return (sigstop::Outcome::Deliver { sig, substituted: false }, info);
    };
    let reported = info.unwrap_or(sched::SigInfo {
        signo: sig, code: 0, pid: 0, uid: 0, value: 0, sys: None, fault: None, poll: None,
    });
    let (resume_sig, edited) = notify_with(sig as i32, 0, reported);
    let blocked = cur.sigmask.load(Ordering::Acquire);
    let fatal = cur.sigpending.load(Ordering::Acquire) & Signum::Sigkill.bit() != 0;
    let outcome = sigstop::after_stop(sig, resume_sig, blocked, fatal);
    let delivered = match outcome {
        // `if (signr != info->si_signo) { clear_siginfo(info); ... }` — a
        // substituted signal cannot keep a record describing a different one.
        // The rebuilt record is `SI_USER` from the TRACER, which is what a
        // handler's `si_pid`/`si_uid` must name.
        sigstop::Outcome::Deliver { sig: new, substituted: true } => {
            let tracer = cur.traced_by.load(Ordering::Acquire);
            let uid = sched::live::registry::lookup(tracer)
                .map(|t| t.creds.ruid.load(Ordering::Acquire)).unwrap_or(0);
            let vpid = sched::live::registry::lookup(tracer)
                .map(|t| t.vtgid.load(Ordering::Acquire)).unwrap_or(0);
            Some(sched::SigInfo {
                signo: new, code: sigstop::SI_USER, pid: vpid, uid,
                value: 0, sys: None, fault: None, poll: None,
            })
        }
        _ => edited,
    };
    (outcome, delivered)
}

/// Whether `ev` would stop the running task, without stopping it. Callers that
/// must publish state before parking (the clone path, which reports only after
/// the child is schedulable) use this to skip the work when nothing is
/// listening.
/// # C: O(1)
pub fn event_armed(ev: u32) -> bool {
    let Some(cur) = sched::live::current() else { return false };
    cur.traced_by.load(Ordering::Acquire) != 0
        && event::event_enabled(cur.ptrace_options.load(Ordering::Acquire), ev)
}

/// Linux `ptrace_init_task`: a child created by a reported fork/vfork/clone is
/// auto-attached to the SAME tracer with the SAME options, and comes to rest
/// immediately — a SEIZED child in a `PTRACE_EVENT_STOP`, a classically
/// attached one on a pending `SIGSTOP`.
///
/// Runs on the PARENT before the child is published, so the child cannot run
/// past its own stop point before the link exists.
/// # C: O(1)
pub fn init_task(parent: &Task, child: &Arc<Task>, reported_event: Option<u32>) {
    let tracer = parent.traced_by.load(Ordering::Acquire);
    let opts = parent.ptrace_options.load(Ordering::Acquire);
    let seized = parent.ptrace_seized.load(Ordering::Acquire);
    let Some(inherited) = event::inherited_trace(reported_event, tracer, opts, seized) else {
        return;
    };
    child.traced_by.store(inherited.tracer, Ordering::Release);
    child.ptrace_options.store(inherited.opts, Ordering::Release);
    child.ptrace_seized.store(inherited.seized, Ordering::Release);
    let code = inherited.child_stop_code();
    child.stop_code.store(code as u32, Ordering::Release);
    *child.ptrace_siginfo.lock() = Some(sched::SigInfo {
        signo: Signum::Sigtrap as u32, code,
        pid: inherited.tracer, uid: 0, value: 0, sys: None, fault: None, poll: None,
    });
    // A SEIZED child is trapped by `JOBCTL_TRAP_STOP`, which has no signal
    // behind it; a classic attach adds SIGSTOP to the child's pending set and
    // the child stops at its first signal-delivery point.
    if !inherited.seized {
        child.sigpending.fetch_or(Signum::Sigstop.bit(), Ordering::Release);
    } else {
        child.stop_pending.store(true, Ordering::Release);
    }
}

/// Linux `exit_ptrace`: every tracee of a dying tracer is detached, and one
/// whose link carries `PTRACE_O_EXITKILL` is killed first. Without this a
/// tracer's death leaves its tracees permanently attached to a tid that no
/// longer exists — every later `ptrace_check_attach` then answers ESRCH and
/// the tracee can never be resumed.
/// # C: O(N_tasks)
pub fn exit_ptrace(tracer_tid: u32) {
    for t in sched::registry::tasks_traced_by(tracer_tid) {
        if event::exitkill(t.ptrace_options.load(Ordering::Acquire)) {
            sched::live::send_sig_priv_group(&t, Signum::Sigkill as u32);
        }
        t.traced_by.store(0, Ordering::Release);
        t.ptrace_options.store(0, Ordering::Release);
        t.ptrace_seized.store(false, Ordering::Release);
        t.ptrace_syscall_armed.store(false, Ordering::Release);
        t.singlestep.store(0, Ordering::Release);
        *t.ptrace_siginfo.lock() = None;
        // A tracee that ALREADY died was notified to its tracer, not to its
        // real parent (Linux notifies `tsk->parent`). With the tracer gone the
        // link reverts to the real parent, which must now be told — otherwise a
        // shell blocked in `wait` for a process that gdb attached to and then
        // crashed on never wakes. Linux reaches the same place through
        // `exit_ptrace` -> `__ptrace_detach` -> `release_task`/`do_notify_parent`.
        if t.state() == sched::TaskState::Zombie {
            sched::live::zombies::notify_real_parent_of_zombie(&t);
        }
        // A tracee parked in a ptrace stop has no tracer left to resume it.
        t.jobctl.store(sched::jobctl::resume_clears(t.jobctl.load(Ordering::Acquire)),
                       Ordering::Release);
        sched::live::registry::wake_if_stopped(&t, sched::jobctl::WakeKind::PtraceResume);
    }
}
