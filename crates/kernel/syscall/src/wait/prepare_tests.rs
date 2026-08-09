// Verified `kernel_wait4` / `kernel_waitid_prepare` contract. The errno ORDER
// is the thing these pin: every case below fixes which of two simultaneously
// rejectable arguments wins, so a reordering of the prologue goes red instead
// of shipping.

use super::*;
use crate::wait::{WEXITED, WCONTINUED, WNOHANG, WNOWAIT, WSTOPPED, WUNTRACED, __WALL, __WCLONE};

const P_ALL_: u64   = crate::wait::P_ALL;
const P_PID_: u64   = crate::wait::P_PID;
const P_PGID_: u64  = crate::wait::P_PGID;
const P_PIDFD_: u64 = crate::wait::P_PIDFD;

#[test]
fn wait4_rejects_the_option_bits_before_it_rejects_the_pid() {
    // Both arguments are rejectable; the option check runs first, so this is
    // EINVAL and not ESRCH. A prologue that tested the pid first would still
    // "reject the call" — with the wrong errno, invisibly.
    assert_eq!(wait4_prepare(i32::MIN, WEXITED), Err(Errno::Einval));
    // With legal options, INT_MIN is ESRCH — `-INT_MIN` cannot be built, so
    // the pgrp form does not exist for it.
    assert_eq!(wait4_prepare(i32::MIN, 0), Err(Errno::Esrch));
    // INT_MIN+1 is an ordinary pgrp request, not an error.
    assert!(wait4_prepare(i32::MIN + 1, 0).is_ok());
}

#[test]
fn wait4_always_consumes_and_always_reports_exits() {
    let p = wait4_prepare(-1, 0).expect("plain wait4 is legal");
    assert_eq!(p.pid, -1);
    assert!(p.consume, "wait4 has no WNOWAIT bit");
    assert!(p.events.exited, "wait4 implies WEXITED");
    assert!(!p.events.stopped);
    assert!(!p.events.continued);

    let p = wait4_prepare(0, WUNTRACED | WCONTINUED).expect("legal");
    assert!(p.events.exited && p.events.stopped && p.events.continued);
}

#[test]
fn wait4_options_reach_the_plan_truncated_to_an_int() {
    // glibc passes __WCLONE as a negative int; the register is sign-extended.
    let p = wait4_prepare(-1, 0xffff_ffff_8000_0000).expect("__WCLONE is legal");
    assert_eq!(p.options, __WCLONE, "the high half is not part of the value");
}

#[test]
fn waitid_rejects_options_before_the_idtype_switch() {
    // P_PID with id 0 is EINVAL on its own, and so is an empty class set. The
    // option check wins, which is what fixes the errno a caller sees when it
    // gets both wrong.
    assert_eq!(waitid_prepare(P_PID_, 0, 0), Err(Errno::Einval));
    assert_eq!(waitid_prepare(0xdead, 0, 0), Err(Errno::Einval));
    // An unknown idtype with a legal option set still reaches the switch.
    assert_eq!(waitid_prepare(4, 1, WEXITED), Err(Errno::Einval));
    assert_eq!(waitid_prepare(u64::MAX, 1, WEXITED), Err(Errno::Einval));
}

#[test]
fn waitid_requires_at_least_one_event_class() {
    assert_eq!(waitid_prepare(P_ALL_, 0, 0), Err(Errno::Einval));
    assert_eq!(waitid_prepare(P_ALL_, 0, WNOHANG), Err(Errno::Einval));
    assert_eq!(waitid_prepare(P_ALL_, 0, WNOWAIT | __WALL), Err(Errno::Einval));
    assert!(waitid_prepare(P_ALL_, 0, WSTOPPED).is_ok());
}

#[test]
fn waitid_idtype_maps_onto_the_wait4_pid_forms() {
    let ready = |r: Result<WaitidPrepare, Errno>| match r {
        Ok(WaitidPrepare::Ready(p)) => p,
        _ => unreachable!("idtype resolves to a wait4 pid form without an fd lookup"),
    };
    // P_ALL ignores its id entirely and means "any child".
    assert_eq!(ready(waitid_prepare(P_ALL_, 12345, WEXITED)).pid, -1);
    // P_PID demands a strictly positive pid.
    assert_eq!(ready(waitid_prepare(P_PID_, 42, WEXITED)).pid, 42);
    assert_eq!(waitid_prepare(P_PID_, 0, WEXITED), Err(Errno::Einval));
    assert_eq!(waitid_prepare(P_PID_, -1, WEXITED), Err(Errno::Einval));
    // P_PGID becomes wait4's negative form; id 0 means the caller's own pgrp,
    // which is wait4's pid == 0 — NOT "any child".
    assert_eq!(ready(waitid_prepare(P_PGID_, 42, WEXITED)).pid, -42);
    assert_eq!(ready(waitid_prepare(P_PGID_, 0, WEXITED)).pid, 0);
    assert_eq!(waitid_prepare(P_PGID_, -1, WEXITED), Err(Errno::Einval));
    // P_PIDFD defers to the fd-table lookup rather than resolving here.
    assert_eq!(waitid_prepare(P_PIDFD_, 7, WEXITED),
               Ok(WaitidPrepare::Pidfd { fd: 7, options: WEXITED }));
    assert_eq!(waitid_prepare(P_PIDFD_, -1, WEXITED), Err(Errno::Einval));
}

#[test]
fn waitid_gates_each_class_and_honours_wnowait() {
    let p = waitid_plan(-1, WSTOPPED);
    assert!(!p.events.exited, "WSTOPPED alone must not reap a zombie");
    assert!(p.events.stopped);
    assert!(p.consume);

    let p = waitid_plan(-1, WEXITED | WNOWAIT);
    assert!(p.events.exited);
    assert!(!p.consume, "WNOWAIT leaves the event waitable");
}

#[test]
fn a_pidfd_that_cannot_be_waited_on_reports_the_right_errno() {
    assert_eq!(pidfd_bind(WEXITED, PidfdTarget::BadFd), Err(Errno::Ebadf));
    // A released process and a non-leader thread are both "no eligible child",
    // not a bad descriptor: the fd itself was fine.
    assert_eq!(pidfd_bind(WEXITED, PidfdTarget::Released), Err(Errno::Echild));
    assert_eq!(pidfd_bind(WEXITED, PidfdTarget::NonLeader), Err(Errno::Echild));
}

#[test]
fn a_nonblocking_pidfd_forces_wnohang_only_when_the_caller_did_not_ask() {
    let leader = |nonblock| PidfdTarget::Leader { vpid: 99, nonblock };

    let (p, forced) = pidfd_bind(WEXITED, leader(true)).expect("live leader");
    assert_eq!(p.pid, 99);
    assert!(forced);
    assert_ne!(p.options & WNOHANG, 0, "O_NONBLOCK adds WNOHANG to the plan");

    // Already WNOHANG: nothing was forced, so the tail must not rewrite 0 into
    // EAGAIN for a caller that explicitly asked for the nonblocking form.
    let (p, forced) = pidfd_bind(WEXITED | WNOHANG, leader(true)).expect("live leader");
    assert!(!forced);
    assert_ne!(p.options & WNOHANG, 0);

    let (p, forced) = pidfd_bind(WEXITED, leader(false)).expect("live leader");
    assert!(!forced);
    assert_eq!(p.options & WNOHANG, 0);
}

#[test]
fn waitid_returns_zero_for_a_report_and_eagain_only_for_a_forced_nonblock() {
    // A reported event returns 0, never the pid: the siginfo is the result.
    assert_eq!(waitid_result(4321, false), 0);
    assert_eq!(waitid_result(4321, true), 0, "a report outranks the forced flag");
    // Nothing ready: plain WNOHANG says 0, a forced one says EAGAIN.
    assert_eq!(waitid_result(0, false), 0);
    assert_eq!(waitid_result(0, true), -(Errno::Eagain.as_i32() as i64));
    // An error passes through unchanged either way.
    let echild = -(Errno::Echild.as_i32() as i64);
    assert_eq!(waitid_result(echild, false), echild);
    assert_eq!(waitid_result(echild, true), echild);
}
