// Wait-status encoding. Two representations exist and must never be confused:
//
//   INTERNAL (`Task::exit_status`) — bit 8 (`WSTATUS_SIGNALED`) marks
//     killed-by-signal; low 7 bits are the signo, bit 7 (`WSTATUS_CORE`) the
//     core-dump flag. A normal exit stores the raw 8-bit exit code with bit 8
//     clear. `crate::signum::killed_status` is the signal-death producer.
//
//   LINUX WSTATUS — what `wait4(2)` writes to userspace and the `W*` macros in
//     `<bits/waitstatus.h>` decode: `(code & 0xff) << 8` for a normal exit,
//     `signo | 0x80?` for a signal death, `(sig << 8) | 0x7f` for a job-control
//     stop, `0xffff` for continued.
//
// `wait_status` is the ONE conversion. Every wait-family syscall goes through
// it — `061_wait4` and `247_waitid` previously open-coded
// `if code & 0x100 != 0 { code & 0x7f } else { (code & 0xff) << 8 }`, which
// masked the core-dump bit off (`0x7f`, not `0xff`) and so made `WCOREDUMP`
// always false for a SIGSEGV/SIGABRT death (Linux `kernel/exit.c`
// `wait_task_zombie`: `wo->wo_stat = status` verbatim, core bit included).

use crate::signum::{WSTATUS_CORE, WSTATUS_SIGNALED};

/// Low 7 bits of a Linux wstatus: the terminating signal.
pub const WSTATUS_SIG_MASK: i32 = 0x7f;
/// Low byte of a Linux wstatus: signal + core-dump flag.
pub const WSTATUS_LOW_MASK: i32 = 0xff;
/// Bit count the exit code is shifted by in a Linux wstatus.
pub const WSTATUS_EXIT_SHIFT: u32 = 8;
/// `(sig << 8) | WSTATUS_STOPPED` is `wait4`'s WIFSTOPPED encoding.
pub const WSTATUS_STOPPED: i32 = 0x7f;
/// `wait4`'s WIFCONTINUED encoding (Linux `__W_CONTINUED`).
pub const WSTATUS_CONTINUED: i32 = 0xffff;

/// `SYSCALL_DEFINE1(exit, int, error_code)` truncation. Linux keeps only the
/// low byte (`(error_code & 0xff) << 8`), so `exit(0x180)` reports 0x80, not
/// 0x180. Storing the raw argument instead let bit 8 of a user-supplied code
/// alias `WSTATUS_SIGNALED` and be reaped as a signal death.
/// # C: O(1)
pub const fn from_exit_code(code: u64) -> i32 { (code & 0xff) as i32 }

/// True when this internal status records a signal death. # C: O(1)
pub const fn is_signaled(internal: i32) -> bool { internal & WSTATUS_SIGNALED != 0 }

/// Terminating signal of a signal death (0 for a normal exit). # C: O(1)
pub const fn term_sig(internal: i32) -> i32 {
    if is_signaled(internal) { internal & WSTATUS_SIG_MASK } else { 0 }
}

/// `WCOREDUMP`: the dying signal wrote a core. # C: O(1)
pub const fn core_dumped(internal: i32) -> bool {
    is_signaled(internal) && internal & WSTATUS_CORE != 0
}

/// Exit code of a normal exit (0 for a signal death). # C: O(1)
pub const fn exit_code(internal: i32) -> i32 {
    if is_signaled(internal) { 0 } else { internal & WSTATUS_LOW_MASK }
}

/// INTERNAL → Linux wstatus (`wait_task_zombie`'s `wo->wo_stat`). # C: O(1)
pub const fn wait_status(internal: i32) -> i32 {
    if is_signaled(internal) { internal & WSTATUS_LOW_MASK }
    else { (internal & WSTATUS_LOW_MASK) << WSTATUS_EXIT_SHIFT }
}

/// `wait_task_stopped`: `wo->wo_stat = (exit_code << 8) | 0x7f`. # C: O(1)
pub const fn stopped_status(sig: i32) -> i32 {
    (sig << WSTATUS_EXIT_SHIFT) | WSTATUS_STOPPED
}

/// `wait_task_continued`: `wo->wo_stat = 0xffff`. # C: O(1)
pub const fn continued_status() -> i32 { WSTATUS_CONTINUED }
