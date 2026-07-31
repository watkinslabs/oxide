// The submission ladder: what a caller observes for each refusal and each wait
// mode, and who owns the request afterwards.

use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

use alloc::boxed::Box;

use crate::backend::{self, HelperRun};
use crate::exec::{call_usermodehelper, call_usermodehelper_exec, call_usermodehelper_setup};
use crate::gate;
use crate::info::SubprocessInfo;
use crate::uapi::{UMH_NO_WAIT, UMH_WAIT_EXEC, UMH_WAIT_PROC};

use super::serialize;

/// Times the backend was entered.
static CALLS: AtomicU32 = AtomicU32::new(0);
/// Times a `cleanup` callback ran.
static CLEANUPS: AtomicU32 = AtomicU32::new(0);
/// What the recording backend reports back as `retval`.
static BACKEND_RETVAL: AtomicI32 = AtomicI32::new(0);
/// Non-zero = the backend detaches instead of returning the request.
static BACKEND_DETACH: AtomicU32 = AtomicU32::new(0);
/// Wait mode the backend saw.
static SEEN_WAIT: AtomicI32 = AtomicI32::new(-1);

fn recording_backend(mut info: Box<SubprocessInfo>) -> HelperRun {
    CALLS.fetch_add(1, Ordering::AcqRel);
    SEEN_WAIT.store(info.wait, Ordering::Release);
    if BACKEND_DETACH.load(Ordering::Acquire) != 0 {
        // A detaching backend owns the request, cleanup included.
        info.free();
        return HelperRun::Detached;
    }
    info.retval = BACKEND_RETVAL.load(Ordering::Acquire);
    HelperRun::Done(info)
}

fn count_cleanup(_info: &mut SubprocessInfo) { CLEANUPS.fetch_add(1, Ordering::AcqRel); }

/// Arm a gate-open, backend-installed world with fresh counters.
fn arm(retval: i32, detach: bool) {
    gate::reset_for_test();
    gate::usermodehelper_enable();
    backend::install(recording_backend);
    CALLS.store(0, Ordering::Release);
    CLEANUPS.store(0, Ordering::Release);
    BACKEND_RETVAL.store(retval, Ordering::Release);
    BACKEND_DETACH.store(u32::from(detach), Ordering::Release);
    SEEN_WAIT.store(-1, Ordering::Release);
}

const EINVAL: i32 = -22;
const EBUSY: i32 = -16;
const ENOENT: i32 = -2;
const EACCES: i32 = -13;

#[test]
fn null_program_is_einval_and_never_reaches_the_backend() {
    let _g = serialize();
    arm(0, false);
    let info = SubprocessInfo::new(None, &[], &[], None, Some(count_cleanup), 0);
    assert_eq!(call_usermodehelper_exec(info, UMH_WAIT_EXEC), EINVAL);
    assert_eq!(CALLS.load(Ordering::Acquire), 0);
    // The request is released on the rejection path too, so a caller that
    // attached owned context does not leak it.
    assert_eq!(CLEANUPS.load(Ordering::Acquire), 1);
}

#[test]
fn a_closed_gate_refuses_with_ebusy() {
    let _g = serialize();
    arm(0, false);
    gate::set_disable_depth(crate::uapi::UmhDisableDepth::Disabled);
    assert_eq!(call_usermodehelper(b"/sbin/request-key", &[], &[], UMH_WAIT_PROC), EBUSY);
    assert_eq!(CALLS.load(Ordering::Acquire), 0);
    // Refusal must not leave the in-flight count raised, or the next suspend
    // would wait five seconds for a helper that never existed.
    assert_eq!(gate::running_helpers(), 0);
}

#[test]
fn the_boot_gate_starts_closed() {
    let _g = serialize();
    gate::reset_for_test();
    backend::install(recording_backend);
    CALLS.store(0, Ordering::Release);
    assert!(gate::usermodehelper_disabled());
    assert_eq!(call_usermodehelper(b"/sbin/request-key", &[], &[], UMH_WAIT_EXEC), EBUSY);
    assert_eq!(CALLS.load(Ordering::Acquire), 0);
}

#[test]
fn the_empty_program_succeeds_as_a_no_op() {
    let _g = serialize();
    arm(0, false);
    let info = call_usermodehelper_setup(b"", &[], &[], None, Some(count_cleanup), 0);
    assert_eq!(call_usermodehelper_exec(info, UMH_WAIT_PROC), 0);
    assert_eq!(CALLS.load(Ordering::Acquire), 0);
    assert_eq!(CLEANUPS.load(Ordering::Acquire), 1);
}

#[test]
fn no_backend_refuses_rather_than_reporting_success() {
    let _g = serialize();
    arm(0, false);
    backend::clear_for_test();
    assert_eq!(call_usermodehelper(b"/sbin/request-key", &[], &[], UMH_WAIT_EXEC), EBUSY);
    backend::install(recording_backend);
}

#[test]
fn wait_exec_reports_the_exec_errno_for_a_missing_helper() {
    let _g = serialize();
    // The overwhelmingly common case: no helper binary is installed.
    arm(ENOENT, false);
    assert_eq!(call_usermodehelper(b"/sbin/request-key", &[], &[], UMH_WAIT_EXEC), ENOENT);
    assert_eq!(SEEN_WAIT.load(Ordering::Acquire), UMH_WAIT_EXEC);
}

#[test]
fn wait_exec_reports_a_permission_denial_unaltered() {
    let _g = serialize();
    arm(EACCES, false);
    assert_eq!(call_usermodehelper(b"/usr/lib/systemd/systemd-coredump", &[], &[], UMH_WAIT_EXEC),
               EACCES);
}

#[test]
fn wait_proc_reports_a_wait_status_not_an_errno() {
    let _g = serialize();
    // Exit code 1 encodes as 0x100 in a wait status; it is a POSITIVE number
    // and must not be mistaken for an errno by the caller or by us.
    arm(0x100, false);
    let rc = call_usermodehelper(b"/sbin/request-key", &[], &[], UMH_WAIT_PROC);
    assert_eq!(rc, 0x100);
    assert!(rc >= 0);
    assert_eq!(SEEN_WAIT.load(Ordering::Acquire), UMH_WAIT_PROC);
}

#[test]
fn wait_proc_reports_a_signal_death_status() {
    let _g = serialize();
    // Killed by SIGSEGV with a core: low byte 11 | 0x80.
    arm(0x8b, false);
    assert_eq!(call_usermodehelper(b"/sbin/request-key", &[], &[], UMH_WAIT_PROC), 0x8b);
}

#[test]
fn wait_proc_reports_a_negative_errno_when_no_process_could_be_made() {
    let _g = serialize();
    arm(-12, false); // ENOMEM
    assert_eq!(call_usermodehelper(b"/sbin/request-key", &[], &[], UMH_WAIT_PROC), -12);
}

#[test]
fn no_wait_returns_zero_and_hands_the_request_to_the_backend() {
    let _g = serialize();
    arm(0, true);
    let info = call_usermodehelper_setup(b"/sbin/hotplug", &[], &[], None, Some(count_cleanup), 0);
    assert_eq!(call_usermodehelper_exec(info, UMH_NO_WAIT), 0);
    assert_eq!(CALLS.load(Ordering::Acquire), 1);
    // Exactly one cleanup, run by the owner — never twice.
    assert_eq!(CLEANUPS.load(Ordering::Acquire), 1);
    assert_eq!(gate::running_helpers(), 0);
}

#[test]
fn a_waiting_mode_may_not_be_detached_behind_the_callers_back() {
    let _g = serialize();
    arm(0, true);
    // A backend that drops a request the caller is waiting on has produced no
    // result at all; reporting 0 there would be a fabricated success.
    assert_eq!(call_usermodehelper(b"/sbin/request-key", &[], &[], UMH_WAIT_PROC), EINVAL);
}

#[test]
fn the_in_flight_count_returns_to_zero_after_every_mode() {
    let _g = serialize();
    for (retval, wait) in [(0, UMH_WAIT_EXEC), (0x100, UMH_WAIT_PROC), (ENOENT, UMH_WAIT_EXEC)] {
        arm(retval, false);
        let _ = call_usermodehelper(b"/sbin/request-key", &[], &[], wait);
        assert_eq!(gate::running_helpers(), 0);
    }
}

#[test]
fn cleanup_runs_once_per_waiting_submission() {
    let _g = serialize();
    arm(0, false);
    for _ in 0..3 {
        let info = call_usermodehelper_setup(b"/sbin/request-key", &[], &[], None,
                                             Some(count_cleanup), 0);
        let _ = call_usermodehelper_exec(info, UMH_WAIT_PROC);
    }
    assert_eq!(CLEANUPS.load(Ordering::Acquire), 3);
}
