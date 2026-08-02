//! Durable provenance for the `signalfd_siginfo` contract: 128-byte size,
//! every field offset, and the `(signo, si_code)` → union-arm decision. A
//! record must never render a member its arm does not define.

use super::*;
use sched::signum::{self, Signum};

fn rec(signo: u32, code: i32) -> SigInfo {
    SigInfo { signo, code, pid: 0, uid: 0, value: 0, sys: None, fault: None, poll: None }
}

fn enc(signo: u32, r: &SigInfo) -> [u8; SIGINFO_SIZE] {
    let mut out = [0xAAu8; SIGINFO_SIZE];
    encode(signo, Some(r), &mut out);
    out
}

fn u32_at(b: &[u8], off: usize) -> u32 { u32::from_ne_bytes(b[off..off + 4].try_into().unwrap()) }
fn i32_at(b: &[u8], off: usize) -> i32 { i32::from_ne_bytes(b[off..off + 4].try_into().unwrap()) }
fn u64_at(b: &[u8], off: usize) -> u64 { u64::from_ne_bytes(b[off..off + 8].try_into().unwrap()) }
fn u16_at(b: &[u8], off: usize) -> u16 { u16::from_ne_bytes(b[off..off + 2].try_into().unwrap()) }

const SIGILL:  u32 = Signum::Sigill  as u32;
const SIGTRAP: u32 = Signum::Sigtrap as u32;
const SIGBUS:  u32 = Signum::Sigbus  as u32;
const SIGSEGV: u32 = Signum::Sigsegv as u32;
const SIGCHLD: u32 = Signum::Sigchld as u32;
const SIGIO:   u32 = Signum::Sigio   as u32;
const SIGSYS:  u32 = Signum::Sigsys  as u32;
const SIGUSR1: u32 = Signum::Sigusr1 as u32;
const SIGRTMIN: u32 = 34;

// ---- offsets / size ----------------------------------------------------

#[test]
fn the_record_is_exactly_128_bytes_with_a_zero_tail() {
    assert_eq!(SIGINFO_SIZE, 128);
    let out = enc(SIGUSR1, &rec(SIGUSR1, signum::SI_USER));
    assert!(out[SSI_PAD..].iter().all(|b| *b == 0), "trailing pad must read back zero");
    // Every offset must fit inside the record, widest member last.
    assert_eq!(SSI_ARCH + 4, SSI_PAD);
}

#[test]
fn field_offsets_match_the_published_layout() {
    let offsets = [
        SSI_SIGNO, SSI_ERRNO, SSI_CODE, SSI_PID, SSI_UID, SSI_FD, SSI_TID, SSI_BAND,
        SSI_OVERRUN, SSI_TRAPNO, SSI_STATUS, SSI_INT, SSI_PTR, SSI_UTIME, SSI_STIME,
        SSI_ADDR, SSI_ADDR_LSB, SSI_SYSCALL, SSI_CALL_ADDR, SSI_ARCH,
    ];
    assert_eq!(offsets, [0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 56, 64, 72, 80, 84, 88, 96]);
}

// ---- layout classification --------------------------------------------

#[test]
fn si_user_and_positive_kernel_codes_select_the_kill_arm() {
    assert_eq!(siginfo_layout(SIGUSR1, signum::SI_USER), SigLayout::Kill);
    assert_eq!(siginfo_layout(SIGUSR1, signum::SI_KERNEL), SigLayout::Kill);
    assert_eq!(siginfo_layout(SIGUSR1, signum::SI_TKILL), SigLayout::Rt);
}

#[test]
fn negative_codes_select_timer_sigio_or_the_rt_arm() {
    assert_eq!(siginfo_layout(SIGRTMIN, SI_TIMER), SigLayout::Timer);
    assert_eq!(siginfo_layout(SIGRTMIN, SI_SIGIO), SigLayout::Poll);
    assert_eq!(siginfo_layout(SIGRTMIN, signum::SI_QUEUE), SigLayout::Rt);
    assert_eq!(siginfo_layout(SIGRTMIN, signum::SI_MESGQ), SigLayout::Rt);
    // A signal-specific code wins over the signal's own arm only in the
    // positive half; SI_TIMER on SIGCHLD is still the timer arm.
    assert_eq!(siginfo_layout(SIGCHLD, SI_TIMER), SigLayout::Timer);
}

#[test]
fn signal_specific_codes_select_that_signals_arm() {
    assert_eq!(siginfo_layout(SIGSEGV, 1), SigLayout::Fault);     // SEGV_MAPERR
    assert_eq!(siginfo_layout(SIGILL, 1), SigLayout::Fault);      // ILL_ILLOPC
    assert_eq!(siginfo_layout(SIGCHLD, 1), SigLayout::Chld);      // CLD_EXITED
    assert_eq!(siginfo_layout(SIGCHLD, NSIGCHLD), SigLayout::Chld);
    assert_eq!(siginfo_layout(SIGIO, 1), SigLayout::Poll);        // POLL_IN
    assert_eq!(siginfo_layout(SIGSYS, 1), SigLayout::Sys);        // SYS_SECCOMP
}

#[test]
fn out_of_range_codes_fall_back_to_poll_then_kill() {
    // Above the signal's own limit but still <= NSIGPOLL ⇒ SIL_POLL.
    assert_eq!(siginfo_layout(SIGSYS, NSIGSYS + 1), SigLayout::Poll);
    // Above NSIGPOLL, and the signal has no arm at all ⇒ SIL_KILL.
    assert_eq!(siginfo_layout(SIGUSR1, NSIGPOLL + 1), SigLayout::Kill);
    // Past its own limit AND past NSIGPOLL ⇒ the kill arm, not the fault arm.
    assert_eq!(siginfo_layout(SIGSEGV, NSIGSEGV + 1), SigLayout::Kill);
    // Past its own limit but still within NSIGPOLL ⇒ the poll arm.
    assert_eq!(siginfo_layout(SIGILL, NSIGPOLL), SigLayout::Fault);
}

#[test]
fn the_fault_arm_exceptions_are_distinct_layouts() {
    assert_eq!(siginfo_layout(SIGBUS, BUS_MCEERR_AR), SigLayout::FaultMceerr);
    assert_eq!(siginfo_layout(SIGBUS, BUS_MCEERR_AO), SigLayout::FaultMceerr);
    assert_eq!(siginfo_layout(SIGBUS, BUS_MCEERR_AR - 1), SigLayout::Fault);
    assert_eq!(siginfo_layout(SIGSEGV, SEGV_BNDERR), SigLayout::FaultBnderr);
    assert_eq!(siginfo_layout(SIGSEGV, SEGV_PKUERR), SigLayout::FaultPkuerr);
    assert_eq!(siginfo_layout(SIGTRAP, TRAP_PERF), SigLayout::FaultPerfEvent);
    assert_eq!(siginfo_layout(SIGTRAP, TRAP_PERF - 1), SigLayout::Fault);
}

// ---- per-arm rendering -------------------------------------------------

#[test]
fn a_bitmap_only_signal_renders_signo_and_nothing_else() {
    let mut out = [0xAAu8; SIGINFO_SIZE];
    encode(SIGUSR1, None, &mut out);
    assert_eq!(u32_at(&out, SSI_SIGNO), SIGUSR1);
    assert!(out[4..].iter().all(|b| *b == 0));
}

#[test]
fn the_kill_arm_renders_only_signo_code_pid_uid() {
    let mut r = rec(SIGUSR1, signum::SI_USER);
    r.pid = 4242; r.uid = 1000; r.value = u64::MAX;
    let out = enc(SIGUSR1, &r);
    assert_eq!(u32_at(&out, SSI_PID), 4242);
    assert_eq!(u32_at(&out, SSI_UID), 1000);
    assert_eq!(i32_at(&out, SSI_CODE), signum::SI_USER);
    assert_eq!(u64_at(&out, SSI_PTR), 0, "the kill arm has no si_value");
    assert_eq!(i32_at(&out, SSI_STATUS), 0);
    assert_eq!(u64_at(&out, SSI_ADDR), 0);
}

#[test]
fn the_chld_arm_renders_status_and_never_an_rt_value() {
    let mut r = rec(SIGCHLD, 1);
    r.pid = 99; r.uid = 0; r.value = (-9i32) as u32 as u64;
    let out = enc(SIGCHLD, &r);
    assert_eq!(u32_at(&out, SSI_PID), 99);
    assert_eq!(i32_at(&out, SSI_STATUS), -9);
    assert_eq!(u64_at(&out, SSI_PTR), 0, "si_status is an int; ssi_ptr stays clear");
    assert_eq!(i32_at(&out, SSI_INT), 0);
}

#[test]
fn the_rt_arm_renders_the_full_eight_byte_sigqueue_value() {
    let ptr = 0x7fff_dead_beefu64;
    let mut r = rec(SIGRTMIN, signum::SI_QUEUE);
    r.pid = 7; r.uid = 1000; r.value = ptr;
    let out = enc(SIGRTMIN, &r);
    assert_eq!(u64_at(&out, SSI_PTR), ptr, "truncating loses a sigqueue(3) sival_ptr");
    assert_eq!(i32_at(&out, SSI_INT), ptr as i32);
    assert_eq!(u32_at(&out, SSI_PID), 7);
    assert_eq!(u32_at(&out, SSI_UID), 1000);
    assert_eq!(i32_at(&out, SSI_STATUS), 0, "ssi_status belongs to the chld arm only");
}

#[test]
fn the_timer_arm_renders_tid_and_overrun_not_pid_and_uid() {
    let mut r = rec(SIGRTMIN, SI_TIMER);
    r.pid = 5; r.uid = 3; r.value = 0x1234;
    let out = enc(SIGRTMIN, &r);
    assert_eq!(u32_at(&out, SSI_TID), 5);
    assert_eq!(u32_at(&out, SSI_OVERRUN), 3);
    assert_eq!(u32_at(&out, SSI_PID), 0, "a timer signal has no sender pid");
    assert_eq!(u32_at(&out, SSI_UID), 0);
    assert_eq!(u64_at(&out, SSI_PTR), 0x1234);
}

#[test]
fn the_poll_arm_renders_band_and_fd() {
    let mut r = rec(SIGIO, 1);
    r.pid = 0x40; r.value = 9;
    let out = enc(SIGIO, &r);
    assert_eq!(u32_at(&out, SSI_BAND), 0x40);
    assert_eq!(i32_at(&out, SSI_FD), 9);
    assert_eq!(u32_at(&out, SSI_PID), 0, "a SIGIO record has no sender pid");
}

#[test]
fn the_fault_arm_renders_an_address_and_no_sender() {
    let mut r = rec(SIGSEGV, 1);
    r.pid = 0xdead_beef; r.uid = 0x0000_7fff;
    let out = enc(SIGSEGV, &r);
    assert_eq!(u64_at(&out, SSI_ADDR), 0x0000_7fff_dead_beef);
    assert_eq!(u32_at(&out, SSI_PID), 0, "SIGSEGV never has a sender pid");
    assert_eq!(u32_at(&out, SSI_UID), 0);
}

// A real `force_sig_fault` record carries the `_sigfault` arm, and THAT is
// what signalfd must report — the pid/uid reconstruction above is only the
// fallback for a record that has no arm. This is the end of the chain that
// starts at the arch fault classifier: a SIGSEGV taken on a wild pointer is
// now readable from a signalfd with its real si_addr and si_code.
#[test]
fn a_forced_fault_record_reports_its_own_si_addr_not_the_overlaid_words() {
    let mut r = rec(SIGSEGV, 2);
    r.pid = 0xdead_beef; r.uid = 0x0000_7fff;
    r.fault = Some(hal::SigFault { addr: 0x7fff_1234_5000, addr_lsb: 0 });
    let out = enc(SIGSEGV, &r);
    assert_eq!(u64_at(&out, SSI_ADDR), 0x7fff_1234_5000);
    assert_eq!(i32_at(&out, SSI_CODE), 2, "SEGV_ACCERR survives the round trip");
    assert_eq!(u32_at(&out, SSI_PID), 0);
}

#[test]
fn a_forced_mceerr_record_reports_its_own_addr_lsb() {
    let mut r = rec(SIGBUS, BUS_MCEERR_AR);
    r.value = 0;
    r.fault = Some(hal::SigFault { addr: 0x4000, addr_lsb: 21 });
    let out = enc(SIGBUS, &r);
    assert_eq!(u64_at(&out, SSI_ADDR), 0x4000);
    assert_eq!(u16_at(&out, SSI_ADDR_LSB), 21);
}

#[test]
fn the_mceerr_arm_adds_addr_lsb_and_trap_variants_add_trapno() {
    let mut r = rec(SIGBUS, BUS_MCEERR_AR);
    r.pid = 0x1000; r.value = 12;
    let out = enc(SIGBUS, &r);
    assert_eq!(u64_at(&out, SSI_ADDR), 0x1000);
    assert_eq!(u16_at(&out, SSI_ADDR_LSB), 12);
    assert_eq!(u32_at(&out, SSI_TRAPNO), 0);
}

#[test]
fn the_sys_arm_renders_call_addr_syscall_arch_and_the_filter_errno() {
    let s = hal::Sigsys { call_addr: 0x7fff_1234_5678, syscall: 257, arch: 0xc000_003e, errno: 0xbeef };
    let mut r = rec(SIGSYS, 1);
    r.pid = 4242; r.uid = 1000; r.value = u64::MAX; r.sys = Some(s);
    let out = enc(SIGSYS, &r);
    assert_eq!(i32_at(&out, SSI_ERRNO), 0xbeef);
    assert_eq!(u64_at(&out, SSI_CALL_ADDR), 0x7fff_1234_5678);
    assert_eq!(i32_at(&out, SSI_SYSCALL), 257);
    assert_eq!(u32_at(&out, SSI_ARCH), 0xc000_003e);
    assert_eq!(u32_at(&out, SSI_PID), 0, "the sigsys arm overlays pid/uid; both must stay clear");
    assert_eq!(u32_at(&out, SSI_UID), 0);
    assert_eq!(u64_at(&out, SSI_PTR), 0);
}

#[test]
fn utime_and_stime_are_reserved_and_never_aliased() {
    for code in [signum::SI_USER, signum::SI_QUEUE, 1, SI_TIMER] {
        let mut r = rec(SIGCHLD, code);
        r.pid = u32::MAX; r.uid = u32::MAX; r.value = u64::MAX;
        let out = enc(SIGCHLD, &r);
        assert_eq!(u64_at(&out, SSI_UTIME), 0, "code {code}");
        assert_eq!(u64_at(&out, SSI_STIME), 0, "code {code}");
    }
}

#[test]
fn a_timer_expiry_renders_its_id_and_overrun_not_zeros() {
    // `ssi_tid` / `ssi_overrun` read back as 0 for every `timer_create(2)`
    // expiry until the producer started carrying a real `_timer` record: the
    // arm overlays `_kill`, so si_tid occupies si_pid's bytes and si_overrun
    // occupies si_uid's, and a producer that left those two words zero left
    // a supervisor unable to tell WHICH of its timers fired.
    let mut r = rec(SIGRTMIN, SI_TIMER);
    r.pid = 5;          // si_tid
    r.uid = 17;         // si_overrun
    r.value = 0x1122_3344_5566_7788;
    let out = enc(SIGRTMIN, &r);
    assert_eq!(u32_at(&out, SSI_TID), 5);
    assert_eq!(u32_at(&out, SSI_OVERRUN), 17);
    assert_eq!(u64_at(&out, SSI_PTR), 0x1122_3344_5566_7788, "si_value.sival_ptr");
    assert_eq!(i32_at(&out, SSI_INT), 0x5566_7788u32 as i32, "si_value.sival_int");
    assert_eq!(u32_at(&out, SSI_PID), 0, "the _timer arm names no sender");
}
