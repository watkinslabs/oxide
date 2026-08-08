// `membarrier(2)` admission tests. Every assertion mirrors a step of
// Linux's `SYSCALL_DEFINE3(membarrier)`.

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
    // … and the command itself is admitted, carrying the caller's cpu_id.
    assert_eq!(
        decide(CMD_PRIVATE_EXPEDITED_RSEQ, FLAG_CPU, 3),
        Ok(Op::PrivateExpeditedRseq { cpu_id: 3 })
    );
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
fn only_the_rseq_command_can_carry_a_caller_supplied_cpu_id() {
    // FLAG_CPU is legal on RSEQ alone, and cpu_id survives only when it is
    // set. A regression that let a raw cpu_id through elsewhere would narrow
    // PRIVATE_EXPEDITED to one CPU and silently skip the rest of the mm's
    // threads; one that dropped it on RSEQ would broadcast a barrier the
    // caller asked to aim at a single CPU.
    assert_eq!(decide(CMD_PRIVATE_EXPEDITED, 0, 3), Ok(Op::PrivateExpedited { cpu_id: CPU_ID_ANY }));
    assert_eq!(decide(CMD_PRIVATE_EXPEDITED, 0, -1), Ok(Op::PrivateExpedited { cpu_id: CPU_ID_ANY }));
    assert_eq!(
        decide(CMD_PRIVATE_EXPEDITED_SYNC_CORE, 0, 3),
        Ok(Op::PrivateExpeditedSyncCore { cpu_id: CPU_ID_ANY })
    );
    assert_eq!(
        decide(CMD_PRIVATE_EXPEDITED_RSEQ, 0, 3),
        Ok(Op::PrivateExpeditedRseq { cpu_id: CPU_ID_ANY })
    );
    assert_eq!(
        decide(CMD_PRIVATE_EXPEDITED_RSEQ, FLAG_CPU, 0),
        Ok(Op::PrivateExpeditedRseq { cpu_id: 0 })
    );
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
        CMD_PRIVATE_EXPEDITED_SYNC_CORE,
        CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE,
        CMD_PRIVATE_EXPEDITED_RSEQ,
        CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ,
        CMD_GET_REGISTRATIONS,
    ] {
        assert!(QUERY_MASK & cmd != 0, "advertised command missing from mask");
        assert!(decide(cmd, 0, 0).is_ok(), "advertised command is not admitted");
    }
    // QUERY itself is value 0, not a bit, so it is never in the mask.
    assert_eq!(QUERY_MASK & CMD_QUERY, 0);
    // The fully-configured command bitmask is bits 0..9 — the QUERY value is
    // 0, not a bit, so it is never in it. Both target arches provide core
    // serialization and restartable sequences, so we advertise the whole
    // enum: any bit missing here is a divergence, not a configuration.
    assert_eq!(LINUX_CMD_BITMASK, 0x3ff);
    assert_eq!(QUERY_MASK, LINUX_CMD_BITMASK);
    assert_eq!(QUERY_MASK, 0x3ff);
}

#[test]
fn sync_core_and_rseq_commands_are_admitted_not_refused() {
    // These four were once answered EINVAL and justified as parity with a
    // build lacking both features. Both target arches provide core
    // serialization and enable restartable sequences, so EINVAL here is a
    // divergence: a userspace runtime probes once, caches the answer, and
    // permanently disables its fast path.
    for (cmd, op) in [
        (CMD_PRIVATE_EXPEDITED_SYNC_CORE, Op::PrivateExpeditedSyncCore { cpu_id: CPU_ID_ANY }),
        (CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE, Op::RegisterPrivateExpeditedSyncCore),
        (CMD_PRIVATE_EXPEDITED_RSEQ, Op::PrivateExpeditedRseq { cpu_id: CPU_ID_ANY }),
        (CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ, Op::RegisterPrivateExpeditedRseq),
    ] {
        assert!(QUERY_MASK & cmd != 0, "implemented command must be advertised");
        assert_eq!(decide(cmd, 0, 0), Ok(op));
    }
}

#[test]
fn every_advertised_bit_maps_to_a_distinct_op() {
    // The mask and the command switch are two lists that must never drift: a
    // bit advertised with no arm answers EINVAL to a command QUERY promised,
    // and an arm with no bit is work userspace will never ask for. Walking
    // all 32 bits catches either direction.
    let mut seen = alloc::vec::Vec::new();
    for bit in 0..32 {
        let cmd = 1i32 << bit;
        let admitted = decide(cmd, 0, 0);
        assert_eq!(
            QUERY_MASK & cmd != 0,
            admitted.is_ok(),
            "bit {bit}: advertised and admitted must agree"
        );
        if let Ok(op) = admitted {
            assert!(!seen.contains(&op), "bit {bit}: two commands map to one op");
            seen.push(op);
        }
    }
    assert_eq!(seen.len(), QUERY_MASK.count_ones() as usize);
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
    assert_eq!(registrations_mask(false, false, false, false), 0);
    assert_eq!(registrations_mask(true, false, false, false), CMD_REGISTER_GLOBAL_EXPEDITED);
    assert_eq!(registrations_mask(false, true, false, false), CMD_REGISTER_PRIVATE_EXPEDITED);
    assert_eq!(
        registrations_mask(false, false, true, false),
        CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    );
    assert_eq!(
        registrations_mask(false, false, false, true),
        CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ
    );
    assert_eq!(
        registrations_mask(true, true, true, true),
        CMD_REGISTER_GLOBAL_EXPEDITED
            | CMD_REGISTER_PRIVATE_EXPEDITED
            | CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
            | CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ
    );
    // Whatever GET_REGISTRATIONS can report must be a subset of what QUERY
    // advertised — otherwise userspace sees a registration for a command it
    // was told does not exist.
    assert_eq!(registrations_mask(true, true, true, true) & !QUERY_MASK, 0);
    // Only REGISTER_* bits are ever reported; a barrier command appearing here
    // would be read as a registration that never happened.
    for cmd in [CMD_GLOBAL, CMD_GLOBAL_EXPEDITED, CMD_PRIVATE_EXPEDITED,
                CMD_PRIVATE_EXPEDITED_SYNC_CORE, CMD_PRIVATE_EXPEDITED_RSEQ,
                CMD_GET_REGISTRATIONS] {
        assert_eq!(registrations_mask(true, true, true, true) & cmd, 0);
    }
}
