// `membarrier(2)` admission tests. Every assertion mirrors a line of
// `SYSCALL_DEFINE3(membarrier)` in Linux `kernel/sched/membarrier.c`.

use super::*;

#[test]
fn flags_are_rejected_before_the_command_is_looked_at() {
    // Linux's first switch runs on `flags` alone. A call that is wrong in
    // BOTH ways must report the flags error, not "unknown command".
    assert_eq!(decide(0x4000_0000, 1, 0), Err(Errno::Einval));
    assert_eq!(decide(CMD_QUERY, FLAG_CPU, 0), Err(Errno::Einval));
    assert_eq!(decide(CMD_GLOBAL, FLAG_CPU, 0), Err(Errno::Einval));
    assert_eq!(decide(CMD_PRIVATE_EXPEDITED, FLAG_CPU, 0), Err(Errno::Einval));
    assert_eq!(decide(CMD_GET_REGISTRATIONS, 0x8000_0000, 0), Err(Errno::Einval));
}

#[test]
fn rseq_is_the_only_command_that_tolerates_flag_cpu() {
    // The flags check passes for RSEQ (0 or FLAG_CPU) …
    assert_eq!(validate_flags(CMD_PRIVATE_EXPEDITED_RSEQ, 0), Ok(()));
    assert_eq!(validate_flags(CMD_PRIVATE_EXPEDITED_RSEQ, FLAG_CPU), Ok(()));
    // … but any OTHER bit, or a combination, is still EINVAL.
    assert_eq!(validate_flags(CMD_PRIVATE_EXPEDITED_RSEQ, FLAG_CPU | 2), Err(Errno::Einval));
    assert_eq!(validate_flags(CMD_PRIVATE_EXPEDITED_RSEQ, 2), Err(Errno::Einval));
    // … and the command itself is refused afterwards (see module head).
    assert_eq!(decide(CMD_PRIVATE_EXPEDITED_RSEQ, FLAG_CPU, 3), Err(Errno::Einval));
}

#[test]
fn cpu_id_is_forced_to_minus_one_without_flag_cpu() {
    assert_eq!(normalize_cpu_id(0, 7), CPU_ID_ANY);
    assert_eq!(normalize_cpu_id(0, -1), CPU_ID_ANY);
    assert_eq!(normalize_cpu_id(0, i32::MAX), CPU_ID_ANY);
    assert_eq!(normalize_cpu_id(FLAG_CPU, 7), 7);
    assert_eq!(normalize_cpu_id(FLAG_CPU, 0), 0);
}

#[test]
fn admitted_commands_never_carry_a_caller_supplied_cpu_id() {
    // FLAG_CPU is legal on RSEQ only, and RSEQ is refused — so every command
    // that reaches a work fn was normalised to CPU_ID_ANY. A regression that
    // let a raw cpu_id through would narrow PRIVATE_EXPEDITED to one CPU and
    // silently skip the rest of the mm's threads.
    assert_eq!(decide(CMD_PRIVATE_EXPEDITED, 0, 3), Ok(Op::PrivateExpedited { cpu_id: CPU_ID_ANY }));
    assert_eq!(decide(CMD_PRIVATE_EXPEDITED, 0, -1), Ok(Op::PrivateExpedited { cpu_id: CPU_ID_ANY }));
}

#[test]
fn query_mask_advertises_exactly_the_implemented_commands() {
    assert_eq!(decide(CMD_QUERY, 0, 0), Ok(Op::Query));
    for cmd in [
        CMD_GLOBAL,
        CMD_GLOBAL_EXPEDITED,
        CMD_REGISTER_GLOBAL_EXPEDITED,
        CMD_PRIVATE_EXPEDITED,
        CMD_REGISTER_PRIVATE_EXPEDITED,
        CMD_GET_REGISTRATIONS,
    ] {
        assert!(QUERY_MASK & cmd != 0, "advertised command missing from mask");
        assert!(decide(cmd, 0, 0).is_ok(), "advertised command is not admitted");
    }
    // QUERY itself is value 0, not a bit, so it is never in the mask.
    assert_eq!(QUERY_MASK & CMD_QUERY, 0);
    // Linux's fully-configured MEMBARRIER_CMD_BITMASK is 0x3ff minus the
    // QUERY value 0 — i.e. bits 0..9. Ours is that minus the refused four.
    assert_eq!(LINUX_CMD_BITMASK, 0x3ff);
    assert_eq!(QUERY_MASK, LINUX_CMD_BITMASK & !REFUSED_MASK);
    assert_eq!(QUERY_MASK, 0x21f);
}

#[test]
fn unadvertised_commands_are_einval_not_a_silent_success() {
    // The mask is a promise; a command outside it must fail loudly. A bare
    // `Ok` here is the exact fake-success bug this slot used to have.
    for cmd in [
        CMD_PRIVATE_EXPEDITED_SYNC_CORE,
        CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
        CMD_PRIVATE_EXPEDITED_RSEQ,
        CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ,
    ] {
        assert_eq!(QUERY_MASK & cmd, 0, "refused command must not be advertised");
        assert_eq!(decide(cmd, 0, 0), Err(Errno::Einval));
    }
}

#[test]
fn unknown_commands_are_einval() {
    // Values that are not a single defined bit (Linux: "The commands need to
    // be a single bit each, except for MEMBARRIER_CMD_QUERY").
    for cmd in [-1, 3, 5, 6, 1 << 10, 1 << 30, i32::MAX, i32::MIN] {
        assert_eq!(decide(cmd, 0, 0), Err(Errno::Einval), "cmd {cmd} must be EINVAL");
    }
}

#[test]
fn get_registrations_reports_each_register_command_independently() {
    assert_eq!(registrations_mask(false, false), 0);
    assert_eq!(registrations_mask(true, false), CMD_REGISTER_GLOBAL_EXPEDITED);
    assert_eq!(registrations_mask(false, true), CMD_REGISTER_PRIVATE_EXPEDITED);
    assert_eq!(
        registrations_mask(true, true),
        CMD_REGISTER_GLOBAL_EXPEDITED | CMD_REGISTER_PRIVATE_EXPEDITED
    );
    // Whatever GET_REGISTRATIONS can report must be a subset of what QUERY
    // advertised — otherwise userspace sees a registration for a command it
    // was told does not exist.
    assert_eq!(registrations_mask(true, true) & !QUERY_MASK, 0);
}
