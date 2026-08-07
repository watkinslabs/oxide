// Durable provenance for the `siginfo_t` union arms: which `(si_signo,
// si_code)` pair selects which `_sifields` member, what each arm writes, and
// what a flat record decodes back to. Split from `siginfo.rs` per `08§7`.

use super::*;

#[test]
fn write_siginfo_fills_si_signo_even_without_a_payload() {
    let mut info = [0u8; 128];
    write_siginfo(&mut info, 11, None);
    assert_eq!(i32::from_ne_bytes(info[0..4].try_into().unwrap()), 11);
    assert!(info[4..].iter().all(|b| *b == 0), "no payload ⇒ nothing else is set");
}

#[test]
fn write_siginfo_sigchld_arm_writes_a_four_byte_si_status() {
    let mut info = [0u8; 128];
    let p = SigPayload { code: 1, pid: 42, uid: 7, status: -9, value: u64::MAX, chld_arm: true,
                         sigsys: None, fault: None, poll: None };
    write_siginfo(&mut info, 17, Some(p));
    assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), 1);
    assert_eq!(i32::from_ne_bytes(info[16..20].try_into().unwrap()), 42);
    assert_eq!(u32::from_ne_bytes(info[20..24].try_into().unwrap()), 7);
    assert_eq!(i32::from_ne_bytes(info[24..28].try_into().unwrap()), -9);
    assert!(info[28..32].iter().all(|b| *b == 0), "si_status is an int; bytes 28..32 stay clear");
}

#[test]
fn write_siginfo_rt_arm_writes_a_full_eight_byte_si_value() {
    let mut info = [0u8; 128];
    let ptr = 0x7fff_dead_beefu64;
    let p = SigPayload { code: -1, pid: 42, uid: 7, status: 0, value: ptr, chld_arm: false,
                         sigsys: None, fault: None, poll: None };
    write_siginfo(&mut info, 34, Some(p));
    assert_eq!(u64::from_ne_bytes(info[24..32].try_into().unwrap()), ptr,
               "truncating si_value to 4 bytes loses a sigqueue(3) sival_ptr");
}

// `force_sig_seccomp` fills si_errno / si_call_addr / si_syscall /
// si_arch. All four read back as 0 without the `_sigsys` arm, so a SIGSYS
// handler could not tell which syscall the filter rejected.
#[test]
fn write_siginfo_sigsys_arm_writes_call_addr_syscall_arch_and_errno() {
    let mut info = [0u8; 128];
    let s = Sigsys { call_addr: 0x7fff_1234_5678, syscall: 257, arch: 0xc000_003e, errno: 0xbeef };
    let p = SigPayload { code: 1, pid: 42, uid: 7, status: -9, value: u64::MAX, chld_arm: true,
                         sigsys: Some(s), fault: None, poll: None };
    write_siginfo(&mut info, 31, Some(p));
    assert_eq!(i32::from_ne_bytes(info[0..4].try_into().unwrap()), 31);
    assert_eq!(i32::from_ne_bytes(info[4..8].try_into().unwrap()), 0xbeef);
    assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), 1, "si_code = SYS_SECCOMP");
    assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), 0x7fff_1234_5678);
    assert_eq!(i32::from_ne_bytes(info[24..28].try_into().unwrap()), 257);
    assert_eq!(u32::from_ne_bytes(info[28..32].try_into().unwrap()), 0xc000_003e);
}

// A synchronous fault signal's whole point is si_addr; without the
// `_sigfault` arm a SIGSEGV handler reads si_addr == 0 and cannot tell
// which address faulted.
#[test]
fn write_siginfo_sigfault_arm_writes_si_addr_and_si_addr_lsb() {
    let mut info = [0u8; 128];
    let f = SigFault { addr: 0x7fff_dead_b000, addr_lsb: 12, pkey: 0 };
    let p = SigPayload { code: code::SEGV_MAPERR, pid: 0, uid: 0, status: 0, value: 0,
                         chld_arm: false, sigsys: None, fault: Some(f), poll: None };
    write_siginfo(&mut info, 11, Some(p));
    assert_eq!(i32::from_ne_bytes(info[0..4].try_into().unwrap()), 11);
    assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), code::SEGV_MAPERR);
    assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), 0x7fff_dead_b000);
    assert_eq!(i16::from_ne_bytes(info[24..26].try_into().unwrap()), 12);
}

// `_sigfault` overlaps `_kill`/`_rt` at byte 16, so si_pid/si_uid/si_value
// must not be written over si_addr.
#[test]
fn the_sigfault_arm_excludes_the_pid_uid_and_value_fields() {
    let mut info = [0u8; 128];
    let f = SigFault { addr: u64::MAX, addr_lsb: 0, pkey: 0 };
    let p = SigPayload { code: code::SEGV_ACCERR, pid: 0x4242, uid: 0x77, status: -9,
                         value: u64::MAX, chld_arm: false, sigsys: None, fault: Some(f), poll: None };
    write_siginfo(&mut info, 11, Some(p));
    assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), u64::MAX);
    assert!(info[26..].iter().all(|b| *b == 0), "nothing past si_addr_lsb is written");
}

// `F_SETSIG`'s whole point is telling the handler WHICH fd fired. si_band is
// a `long` covering both `_kill` words, so si_pid/si_uid must not be written
// over it and si_fd must land in the `si_value` slot.
#[test]
fn write_siginfo_sigpoll_arm_writes_si_band_and_si_fd() {
    let mut info = [0u8; 128];
    let q = SigPoll { band: 0x41, fd: 7 };
    let p = SigPayload { code: 1, pid: 0x4242, uid: 0x77, status: -9, value: u64::MAX,
                         chld_arm: false, sigsys: None, fault: None, poll: Some(q) };
    write_siginfo(&mut info, 29, Some(p));
    assert_eq!(i32::from_ne_bytes(info[0..4].try_into().unwrap()), 29);
    assert_eq!(i32::from_ne_bytes(info[8..12].try_into().unwrap()), 1, "si_code = POLL_IN");
    assert_eq!(i64::from_ne_bytes(info[16..24].try_into().unwrap()), 0x41,
               "si_band is a long; si_pid/si_uid must not be written over it");
    assert_eq!(i32::from_ne_bytes(info[24..28].try_into().unwrap()), 7, "si_fd");
    assert!(info[28..].iter().all(|b| *b == 0), "nothing past si_fd is written");
}

// The `_sigsys` arm OVERLAPS `_kill`/`_sigchld`: si_pid and si_call_addr
// share offset 16. Writing both would corrupt si_call_addr's low half.
#[test]
fn the_sigsys_arm_excludes_the_pid_uid_and_status_fields() {
    let mut info = [0u8; 128];
    let s = Sigsys { call_addr: u64::MAX, syscall: 0, arch: 0, errno: 0 };
    let p = SigPayload { code: 1, pid: 0x4242, uid: 0x77, status: -9, value: 0, chld_arm: false,
                         sigsys: Some(s), fault: None, poll: None };
    write_siginfo(&mut info, 31, Some(p));
    assert_eq!(u64::from_ne_bytes(info[16..24].try_into().unwrap()), u64::MAX,
               "si_pid/si_uid must not be written over si_call_addr");
}

// ---- (si_signo, si_code) -> union arm ----------------------------------
//
// The mapping a debugger depends on: `si_code` is what says whether bytes
// 16..24 are `si_addr` or a sender's pid. Verified against the published
// `siginfo_layout` contract, encoded here so it stays re-checkable.

use signo::*;
use source::*;
use limit::*;

/// SIGUSR1 — no signal-specific codes at all.
const SIGUSR1: u32 = 10;
/// The lowest real-time signal.
const SIGRTMIN: u32 = 34;

#[test]
fn a_source_code_outside_the_signal_specific_window_ignores_the_signal() {
    // `SI_USER < code < SI_KERNEL` is the whole window. Outside it the arm
    // comes from the SOURCE, even for a signal that has its own codes.
    assert_eq!(layout(SIGSEGV, SI_USER), Layout::Kill);
    assert_eq!(layout(SIGSEGV, SI_KERNEL), Layout::Kill);
    assert_eq!(layout(SIGSEGV, -6), Layout::Rt, "SI_TKILL is a queued RT record");
    assert_eq!(layout(SIGRTMIN, SI_TIMER), Layout::Timer);
    assert_eq!(layout(SIGRTMIN, SI_SIGIO), Layout::Poll);
    assert_eq!(layout(SIGRTMIN, -1), Layout::Rt, "SI_QUEUE");
}

#[test]
fn every_fault_signals_own_codes_select_the_sigfault_arm() {
    for (sig, bound) in [(SIGILL, NSIGILL), (SIGFPE, NSIGFPE), (SIGSEGV, NSIGSEGV),
                         (SIGBUS, NSIGBUS), (SIGTRAP, NSIGTRAP)] {
        for c in 1..=bound {
            assert!(layout(sig, c).is_fault(),
                    "sig {sig} code {c} must decode as a fault, not a sender");
        }
        // One past the bound is not a code this signal defines, so it falls
        // back to `_sigpoll`/`_kill` — never to the signal's own arm.
        assert!(!layout(sig, bound + 1).is_fault(), "sig {sig} bound {bound}");
    }
}

#[test]
fn the_segv_codes_a_page_fault_raises_are_the_plain_fault_arm() {
    assert_eq!(layout(SIGSEGV, code::SEGV_MAPERR), Layout::Fault);
    assert_eq!(layout(SIGSEGV, code::SEGV_ACCERR), Layout::Fault);
    assert_eq!(layout(SIGSEGV, code::SEGV_CPERR), Layout::Fault);
}

#[test]
fn the_fault_arm_exceptions_keep_si_addr_and_add_their_own_members() {
    assert_eq!(layout(SIGSEGV, code::SEGV_BNDERR), Layout::FaultBnderr);
    assert_eq!(layout(SIGSEGV, code::SEGV_PKUERR), Layout::FaultPkuerr);
    assert_eq!(layout(SIGTRAP, code::TRAP_PERF), Layout::FaultPerfEvent);
    assert_eq!(layout(SIGBUS, 4), Layout::FaultMceerr, "BUS_MCEERR_AR");
    assert_eq!(layout(SIGBUS, 5), Layout::FaultMceerr, "BUS_MCEERR_AO");
    assert_eq!(layout(SIGBUS, code::BUS_OBJERR), Layout::Fault);
    for c in [code::SEGV_BNDERR, code::SEGV_PKUERR] { assert!(layout(SIGSEGV, c).is_fault()); }
}

#[test]
fn the_non_fault_signals_with_their_own_codes_select_their_own_arms() {
    assert_eq!(layout(SIGCHLD, 1), Layout::Chld, "CLD_EXITED");
    assert_eq!(layout(SIGCHLD, NSIGCHLD), Layout::Chld);
    assert_eq!(layout(SIGIO, 1), Layout::Poll, "POLL_IN");
    assert_eq!(layout(SIGSYS, 1), Layout::Sys, "SYS_SECCOMP");
    // A signal with NO codes of its own falls through the poll bound.
    assert_eq!(layout(SIGUSR1, NSIGPOLL), Layout::Poll);
    assert_eq!(layout(SIGUSR1, NSIGPOLL + 1), Layout::Kill);
}

#[test]
fn known_layout_marks_only_prefix_complete_siginfo_records() {
    assert!(known_layout(SIGSEGV, code::SEGV_MAPERR));
    assert!(known_layout(SIGUSR1, limit::NSIGPOLL));
    assert!(known_layout(SIGUSR1, source::SI_DETHREAD));
    assert!(known_layout(SIGUSR1, source::SI_ASYNCNL));
    assert!(!known_layout(SIGSEGV, limit::NSIGSEGV + 1));
    assert!(!known_layout(SIGUSR1, source::SI_ASYNCNL + 1));
}

// ---- flat decode -------------------------------------------------------

/// Render a payload and decode it back, which is exactly the round trip a
/// tracer's GETSIGINFO/SETSIGINFO pair performs.
fn round_trip(sig: u32, p: SigPayload) -> SigPayload {
    let mut buf = [0u8; 128];
    write_siginfo(&mut buf, sig, Some(p));
    read_siginfo(&buf, sig)
}

// The defect this file exists for: a SIGSEGV record read back through a
// `_kill`-shaped decoder reports si_addr as a pid.
#[test]
fn a_segv_record_decodes_to_a_fault_address_and_names_no_sender() {
    let addr = 0x7fff_dead_b00fu64;
    let p = SigPayload { code: code::SEGV_MAPERR, fault: Some(SigFault { addr, addr_lsb: 0, pkey: 0 }),
                         ..Default::default() };
    let back = round_trip(SIGSEGV, p);
    assert_eq!(back.code, code::SEGV_MAPERR);
    assert_eq!(back.fault, Some(SigFault { addr, addr_lsb: 0, pkey: 0 }));
    assert_eq!(back.pid, 0, "a fault has no sender; those bytes are si_addr");
    assert_eq!(back.uid, 0);
}

// A tracer stopped on a fault reads the record the kernel published. Whatever
// pid happens to sit in the producer's sender fields must NOT reach si_addr,
// and the decode must not resurrect it as a sender either.
#[test]
fn a_fault_record_never_carries_a_pid_into_si_addr() {
    let p = SigPayload { code: code::SEGV_ACCERR, pid: 0x1234, uid: 0x99,
                         fault: Some(SigFault { addr: 0x4000, addr_lsb: 0, pkey: 0 }), ..Default::default() };
    let mut buf = [0u8; 128];
    write_siginfo(&mut buf, SIGSEGV, Some(p));
    assert_eq!(u64::from_ne_bytes(buf[16..24].try_into().unwrap()), 0x4000,
               "si_addr, not si_pid | si_uid << 32");
    assert_eq!(read_siginfo(&buf, SIGSEGV).pid, 0);
}

#[test]
fn every_arm_survives_a_flat_round_trip() {
    let f = SigPayload { code: code::BUS_ADRALN,
                         fault: Some(SigFault { addr: 0x2000, addr_lsb: 12, pkey: 0 }), ..Default::default() };
    assert_eq!(round_trip(SIGBUS, f).fault, f.fault);

    let s = SigPayload { code: 1, sigsys: Some(Sigsys { call_addr: 0x7fff_0000_1000,
                         syscall: 257, arch: 0xc000_003e, errno: 0xbeef }), ..Default::default() };
    assert_eq!(round_trip(SIGSYS, s).sigsys, s.sigsys);

    let q = SigPayload { code: 1, poll: Some(SigPoll { band: 0x41, fd: 7 }), ..Default::default() };
    assert_eq!(round_trip(SIGIO, q).poll, q.poll);

    let rt = SigPayload { code: -1, pid: 42, uid: 7, value: 0x7fff_dead_beef, ..Default::default() };
    let back = round_trip(SIGRTMIN, rt);
    assert_eq!((back.pid, back.uid, back.value), (42, 7, 0x7fff_dead_beef),
               "an RT record's si_value is a full 8 bytes");

    let k = SigPayload { code: SI_USER, pid: 99, uid: 1000, ..Default::default() };
    let back = round_trip(SIGUSR1, k);
    assert_eq!((back.pid, back.uid), (99, 1000));
    assert!(back.fault.is_none() && back.poll.is_none() && back.sigsys.is_none());
}

#[test]
fn pku_fault_writes_the_key_in_the_overlapping_sigfault_union_slot() {
    let p = SigPayload { code: code::SEGV_PKUERR,
        fault: Some(SigFault { addr: 0x7fff_dead_b000, addr_lsb: 0, pkey: 7 }), ..Default::default() };
    let mut buf = [0u8; 128];
    write_siginfo(&mut buf, SIGSEGV, Some(p));
    assert_eq!(i32::from_ne_bytes(buf[24..28].try_into().unwrap()), 7);
    assert_eq!(read_siginfo(&buf, SIGSEGV).fault.unwrap().pkey, 7);
}

// `_sigchld.si_status` is an `int`. Decoding 8 bytes there folds `si_utime`'s
// low half into the exit status.
#[test]
fn a_sigchld_record_decodes_a_four_byte_status() {
    let p = SigPayload { code: 1, pid: 77, uid: 0, status: -9, chld_arm: true, ..Default::default() };
    let mut buf = [0xAAu8; 128];
    write_siginfo(&mut buf, SIGCHLD, Some(p));
    let back = read_siginfo(&buf, SIGCHLD);
    assert!(back.chld_arm);
    assert_eq!(back.status, -9);
    assert_eq!(back.pid, 77);
}

// The decoder takes the SIGNAL from its argument, not from the buffer — Linux
// overwrites si_signo with the syscall's own argument, so a sender cannot make
// the two disagree and thereby choose a different arm.
#[test]
fn the_caller_supplied_signal_selects_the_arm_not_the_buffers_si_signo() {
    let mut buf = [0u8; 128];
    write_siginfo(&mut buf, SIGSEGV, Some(SigPayload {
        code: code::SEGV_MAPERR, fault: Some(SigFault { addr: 0x9000, addr_lsb: 0, pkey: 0 }),
        ..Default::default() }));
    // Read as SIGCHLD: si_code 1 is CLD_EXITED there, so the same bytes are a
    // sender and a status — the arm follows the signal argument.
    let back = read_siginfo(&buf, SIGCHLD);
    assert!(back.fault.is_none() && back.chld_arm);
    assert_eq!(back.pid, 0x9000, "the low half of si_addr, read as si_pid");
}
