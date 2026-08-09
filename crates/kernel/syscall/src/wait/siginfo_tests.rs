// Verified `waitid` siginfo copy-out: which fields are set, at which offsets,
// and what `si_status` carries for each `si_code`. `si_status` is the RAW
// value — the exit code, the signal, the stop code, `SIGCONT` — never the
// wait-encoded status, and confusing the two is invisible until a program
// reads `si_status` and gets `code << 8`.

use super::*;
use crate::wait::{CLD_CONTINUED, CLD_DUMPED, CLD_EXITED, CLD_KILLED, CLD_STOPPED, CLD_TRAPPED,
                  SIGCONT};

const SIGCHLD: i32 = 17;
const PID: i32 = 4321;
const UID: u32 = 1000;

fn encode(kind: WaitEventKind, wstat: i32) -> [u8; SIGINFO_BYTES] {
    siginfo_bytes(SIGCHLD, Some(WaitReport { kind, wstat, pid: PID, uid: UID }))
}

fn code_status(kind: WaitEventKind, wstat: i32) -> (i32, i32) {
    let b = encode(kind, wstat);
    (siginfo_field(&b, SIGINFO_OFF_CODE), siginfo_field(&b, SIGINFO_OFF_STATUS))
}

#[test]
fn a_report_sets_signo_errno_pid_and_uid_at_the_abi_offsets() {
    let b = encode(WaitEventKind::Exited, 7 << 8);
    assert_eq!(siginfo_field(&b, SIGINFO_OFF_SIGNO), SIGCHLD);
    assert_eq!(siginfo_field(&b, SIGINFO_OFF_ERRNO), 0);
    assert_eq!(siginfo_field(&b, SIGINFO_OFF_PID), PID);
    assert_eq!(siginfo_field(&b, SIGINFO_OFF_UID) as u32, UID);
    // Every byte outside the six written fields stays zero — no stale user
    // data survives under the union tail.
    let written = [SIGINFO_OFF_SIGNO, SIGINFO_OFF_ERRNO, SIGINFO_OFF_CODE,
                   SIGINFO_OFF_PID, SIGINFO_OFF_UID, SIGINFO_OFF_STATUS];
    for i in 0..SIGINFO_BYTES {
        if written.iter().any(|&o| i >= o && i < o + 4) { continue; }
        assert_eq!(b[i], 0, "byte {i} outside a written field must be zero");
    }
    // Bytes 12..16 are the union padding between si_errno and si_pid.
    assert_eq!(&b[12..16], &[0, 0, 0, 0]);
}

#[test]
fn no_event_leaves_the_whole_siginfo_zero_including_si_signo() {
    // A WNOHANG miss and an error both copy out a zeroed structure; the zero
    // si_signo is how userspace distinguishes that from a real report.
    let b = siginfo_bytes(SIGCHLD, None);
    assert_eq!(b, [0u8; SIGINFO_BYTES]);
    assert_eq!(siginfo_field(&b, SIGINFO_OFF_SIGNO), 0);
}

#[test]
fn a_normal_exit_reports_cld_exited_with_the_raw_exit_code() {
    assert_eq!(code_status(WaitEventKind::Exited, 0), (CLD_EXITED, 0));
    assert_eq!(code_status(WaitEventKind::Exited, 7 << 8), (CLD_EXITED, 7));
    // The exit code is a byte: 0xff is the largest, and nothing above it
    // bleeds in from the wait-status high half.
    assert_eq!(code_status(WaitEventKind::Exited, 0xff << 8), (CLD_EXITED, 0xff));
}

#[test]
fn a_signal_death_reports_the_signal_and_distinguishes_a_core_dump() {
    // SIGSEGV, no core.
    assert_eq!(code_status(WaitEventKind::Exited, 11), (CLD_KILLED, 11));
    // SIGSEGV with the 0x80 core-dump flag set. Masking the flag off here is
    // the bug that made WCOREDUMP always false.
    assert_eq!(code_status(WaitEventKind::Exited, 11 | 0x80), (CLD_DUMPED, 11));
    assert_eq!(code_status(WaitEventKind::Exited, 6 | 0x80), (CLD_DUMPED, 6));
}

#[test]
fn a_stop_reports_the_stop_code_and_a_trap_reports_the_same_code_under_cld_trapped() {
    // The wait status is (code << 8) | 0x7f; si_status is the code back out.
    let stop = (19 << 8) | 0x7f;
    assert_eq!(code_status(WaitEventKind::Stopped, stop), (CLD_STOPPED, 19));
    // A ptrace event stop carries SIGTRAP | (event << 8) — 16 bits, so the
    // event number must survive the round trip.
    let event = 5 | (4 << 8);
    let trap = (event << 8) | 0x7f;
    assert_eq!(code_status(WaitEventKind::Trapped, trap), (CLD_TRAPPED, event));
}

#[test]
fn a_continue_reports_sigcont_not_the_wait_status() {
    assert_eq!(code_status(WaitEventKind::Continued, 0xffff), (CLD_CONTINUED, SIGCONT));
}
