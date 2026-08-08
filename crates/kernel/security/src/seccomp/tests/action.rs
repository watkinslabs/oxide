// `__seccomp_filter`'s action switch. Every assertion here is a DENIAL that
// used to be an allow, or a kill scope that used to be wrong.

use crate::seccomp::action::*;
use crate::seccomp::insn::SeccompData;
use crate::seccomp::uapi::*;

const IP: u64 = 0x4000_1234;
const NR: i32 = 257;

fn data() -> SeccompData {
    SeccompData { nr: NR, arch: native_audit_arch(), ip: IP, args: [0; 6] }
}
fn enosys() -> i64 { -(syscall::errno::Errno::Enosys.as_i32() as i64) }
fn sigsys(errno: i32) -> Sigsys {
    Sigsys { call_addr: IP, syscall: NR, arch: native_audit_arch(), errno }
}

// The headline bug: a filter whose deny action is RET_TRACE was a complete
// no-op. Linux ENOSYS-es and SKIPS the call when no tracer is listening
// ("ENOSYS these calls if there is no tracer attached", `__seccomp_filter`).
#[test]
fn ret_trace_without_a_tracer_denies_the_syscall() {
    let v = decide(SECCOMP_RET_TRACE, &data(), false);
    assert_eq!(v, Verdict::Skip { ret: enosys() });
    assert_ne!(v, Verdict::Allow);
}

// Not a kill: the relayed audit claimed RET_TRACE degrades to
// KILL_THREAD without a tracer. Correct behavior is to skip the syscall
// with -ENOSYS and let the task live.
#[test]
fn ret_trace_without_a_tracer_does_not_kill() {
    match decide(SECCOMP_RET_TRACE, &data(), false) {
        Verdict::Skip { .. } => {}
        other => panic!("RET_TRACE with no tracer must skip, got {:?}", other),
    }
}

#[test]
fn ret_trace_with_an_armed_tracer_reports_the_event() {
    assert_eq!(decide(SECCOMP_RET_TRACE | 0x1234, &data(), true),
               Verdict::TraceStop { data: 0x1234 });
}

// RET_LOG is an ALLOW-after-audit action in Linux (`case SECCOMP_RET_LOG:
// seccomp_log(...); return 0;`), not a denial. Asserted so a future
// "fail-closed" sweep cannot silently turn it into one.
#[test]
fn ret_log_allows_the_syscall_and_records_it() {
    assert_eq!(decide(SECCOMP_RET_LOG, &data(), false), Verdict::Log { syscall: NR });
}

// RET_USER_NOTIF with no listener is the other fail-closed path:
// `seccomp_do_user_notification` opens `err = -ENOSYS; if (!match->notif)
// goto out;` and `out:` skips the syscall.
#[test]
fn ret_user_notif_without_a_listener_denies_the_syscall() {
    assert_eq!(decide(SECCOMP_RET_USER_NOTIF, &data(), false), Verdict::Skip { ret: enosys() });
}

#[test]
fn ret_kill_process_kills_the_process_not_the_thread() {
    let v = decide(SECCOMP_RET_KILL_PROCESS, &data(), false);
    assert_eq!(v, Verdict::KillProcess(sigsys(0)));
    assert_ne!(v, Verdict::KillThread(sigsys(0)));
}

#[test]
fn ret_kill_thread_kills_only_the_thread() {
    assert_eq!(decide(SECCOMP_RET_KILL_THREAD, &data(), false), Verdict::KillThread(sigsys(0)));
    // The legacy `SECCOMP_RET_KILL` alias IS `KILL_THREAD`.
    assert_eq!(decide(SECCOMP_RET_KILL, &data(), false), Verdict::KillThread(sigsys(0)));
}

// Masking the return with `SECCOMP_RET_ACTION` (0x7fff0000) instead of
// `SECCOMP_RET_ACTION_FULL` drops bit 31 and folds KILL_PROCESS onto
// KILL_THREAD — the exact degradation this asserts against.
#[test]
fn kill_process_survives_the_action_mask() {
    assert_eq!(SECCOMP_RET_KILL_PROCESS & SECCOMP_RET_ACTION, SECCOMP_RET_KILL_THREAD);
    assert_ne!(SECCOMP_RET_KILL_PROCESS & SECCOMP_RET_ACTION_FULL, SECCOMP_RET_KILL_THREAD);
}

// An action the kernel does not know falls into the KILL arm with Linux's
// `default:`, never into ALLOW.
#[test]
fn an_unknown_action_kills_rather_than_allowing() {
    for raw in [0x0001_0000u32, 0x4000_0000, 0x7f00_0000, 0xdead_0000] {
        match decide(raw, &data(), false) {
            Verdict::KillProcess(_) => {}
            other => panic!("unknown action {:#x} must kill, got {:?}", raw, other),
        }
    }
}

#[test]
fn ret_trap_carries_the_full_sigsys_siginfo() {
    assert_eq!(decide(SECCOMP_RET_TRAP | 0xbeef, &data(), false), Verdict::Trap(sigsys(0xbeef)));
}

#[test]
fn ret_errno_caps_the_filter_data_at_max_errno() {
    assert_eq!(decide(SECCOMP_RET_ERRNO | 1, &data(), false), Verdict::Skip { ret: -1 });
    assert_eq!(decide(SECCOMP_RET_ERRNO | 4095, &data(), false), Verdict::Skip { ret: -4095 });
    assert_eq!(decide(SECCOMP_RET_ERRNO | 4096, &data(), false), Verdict::Skip { ret: -(MAX_ERRNO as i64) });
    assert_eq!(decide(SECCOMP_RET_ERRNO | 0xffff, &data(), false), Verdict::Skip { ret: -(MAX_ERRNO as i64) });
}

// `syscall_set_return_value(current, regs, -data, 0)` with data == 0 returns
// SUCCESS. Substituting EPERM there would deny a call Linux allows through
// with a 0 result.
#[test]
fn ret_errno_with_zero_data_returns_success_not_eperm() {
    assert_eq!(decide(SECCOMP_RET_ERRNO, &data(), false), Verdict::Skip { ret: 0 });
}

#[test]
fn ret_allow_allows() {
    assert_eq!(decide(SECCOMP_RET_ALLOW, &data(), false), Verdict::Allow);
}

// `ACTION_ONLY()` is a SIGNED compare on `SECCOMP_RET_ACTION_FULL`, which is
// the entire reason KILL_PROCESS (0x80000000) outranks everything.
#[test]
fn action_precedence_is_the_signed_linux_order() {
    let order = [SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_KILL_THREAD, SECCOMP_RET_TRAP,
                 SECCOMP_RET_ERRNO, SECCOMP_RET_USER_NOTIF, SECCOMP_RET_TRACE,
                 SECCOMP_RET_LOG, SECCOMP_RET_ALLOW];
    for i in 0..order.len() {
        for j in 0..order.len() {
            assert_eq!(more_restrictive(order[i], order[j]), i < j,
                       "{:#x} vs {:#x}", order[i], order[j]);
        }
    }
}

#[test]
fn precedence_ignores_the_sixteen_data_bits() {
    assert!(!more_restrictive(SECCOMP_RET_ERRNO | 0xffff, SECCOMP_RET_ERRNO));
    assert!(more_restrictive(SECCOMP_RET_TRAP | 0xffff, SECCOMP_RET_ERRNO));
}

#[test]
fn strict_mode_permits_exactly_the_four_mode1_syscalls() {
    for nr in MODE1_SYSCALLS { assert!(strict_allows(nr as i32)); }
    for nr in [MODE1_SYSCALLS[0] + 1000, 4242, 0xffff] {
        if MODE1_SYSCALLS.contains(&nr) { continue; }
        assert!(!strict_allows(nr as i32), "nr {} must not be allowed in strict mode", nr);
    }
    // A negative / rewritten syscall number is not one of them either.
    assert!(!strict_allows(-1));
}
