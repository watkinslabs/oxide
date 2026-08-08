// `membarrier(2)` UAPI + admission — the membarrier UAPI command/flag space
// and Linux's `SYSCALL_DEFINE3(membarrier)` body.
//
// Deliberately NOT kernel-cfg'd: slot files are
// `#![cfg(target_os = "oxide-kernel")]` and unreachable from the hosted
// suite, which would leave the flags-before-command ordering, the QUERY
// bitmask, and the FLAG_CPU rule — the whole ABI contract — untested. The
// slot file stays a thin shim (`docs/53`) that calls `decide` and then one
// `sched::membarrier` work fn per command.
//
// WHAT IS ADVERTISED. `QUERY_MASK` is a promise: userspace (glibc, liburcu)
// issues exactly what the mask claims, so the mask and the command switch are
// written from one constant and a test pins them equal. Every command in the
// enum is advertised, because every one is backed by real work:
//   * `PRIVATE_EXPEDITED_SYNC_CORE` + its REGISTER — the barrier IPI runs a
//     core-serializing instruction on each target, and a per-mm bit makes the
//     context-switch tail serialize for a thread that was NOT running when the
//     barrier was issued. Both arches this kernel targets provide the primitive
//     (x86_64 explicitly, aarch64 inherently via its user return), so refusing
//     the command would be a divergence, not parity.
//   * `PRIVATE_EXPEDITED_RSEQ` + its REGISTER — the same IPI latches a forced
//     restartable-sequence evaluation on each target, which the return-to-user
//     path honours whether or not the barrier preempted the thread, so no
//     critical section can straddle the barrier.
// An earlier revision refused all four and justified it as parity with a build
// that has neither feature configured. That was wrong in both directions: the
// reference selects core-serialization support on x86_64 AND aarch64, and
// enables restartable sequences by default on both — so the refusal was a
// divergence recorded as compliance.

use syscall::errno::Errno;

/// `MEMBARRIER_CMD_QUERY`.
pub const CMD_QUERY: i32 = 0;
/// `MEMBARRIER_CMD_GLOBAL` (a.k.a. `MEMBARRIER_CMD_SHARED`).
pub const CMD_GLOBAL: i32 = 1 << 0;
/// `MEMBARRIER_CMD_GLOBAL_EXPEDITED`.
pub const CMD_GLOBAL_EXPEDITED: i32 = 1 << 1;
/// `MEMBARRIER_CMD_REGISTER_GLOBAL_EXPEDITED`.
pub const CMD_REGISTER_GLOBAL_EXPEDITED: i32 = 1 << 2;
/// `MEMBARRIER_CMD_PRIVATE_EXPEDITED`.
pub const CMD_PRIVATE_EXPEDITED: i32 = 1 << 3;
/// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED`.
pub const CMD_REGISTER_PRIVATE_EXPEDITED: i32 = 1 << 4;
/// `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE`.
pub const CMD_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 5;
/// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE`.
pub const CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 6;
/// `MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ`.
pub const CMD_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 7;
/// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ`.
pub const CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 8;
/// `MEMBARRIER_CMD_GET_REGISTRATIONS`.
pub const CMD_GET_REGISTRATIONS: i32 = 1 << 9;

/// `MEMBARRIER_CMD_FLAG_CPU` — the only defined flag bit.
pub const FLAG_CPU: u32 = 1 << 0;

/// "No specific CPU" sentinel Linux forces into `cpu_id` when `FLAG_CPU` is
/// absent.
pub const CPU_ID_ANY: i32 = -1;

/// Linux `MEMBARRIER_CMD_BITMASK` with every config selected: the whole
/// non-QUERY command enum.
pub const LINUX_CMD_BITMASK: i32 = CMD_GLOBAL
    | CMD_GLOBAL_EXPEDITED
    | CMD_REGISTER_GLOBAL_EXPEDITED
    | CMD_PRIVATE_EXPEDITED
    | CMD_REGISTER_PRIVATE_EXPEDITED
    | CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    | CMD_PRIVATE_EXPEDITED_RSEQ
    | CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ
    | CMD_GET_REGISTRATIONS;

/// What `MEMBARRIER_CMD_QUERY` returns. Every bit is backed by a
/// `sched::membarrier` work fn, and nothing is withheld.
pub const QUERY_MASK: i32 = LINUX_CMD_BITMASK;

/// One admitted request. The shim maps each arm to exactly one work fn.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Op {
    Query,
    Global,
    GlobalExpedited,
    RegisterGlobalExpedited,
    PrivateExpedited { cpu_id: i32 },
    RegisterPrivateExpedited,
    PrivateExpeditedSyncCore { cpu_id: i32 },
    RegisterPrivateExpeditedSyncCore,
    PrivateExpeditedRseq { cpu_id: i32 },
    RegisterPrivateExpeditedRseq,
    GetRegistrations,
}

/// Linux's `cpu_id` normalisation: unless `MEMBARRIER_CMD_FLAG_CPU` is set,
/// whatever userspace passed is discarded. Applied to EVERY command, after
/// flag validation and before the command switch.
/// # C: O(1)
pub fn normalize_cpu_id(flags: u32, cpu_id: i32) -> i32 {
    if flags & FLAG_CPU != 0 { cpu_id } else { CPU_ID_ANY }
}

/// Linux's first switch: `PRIVATE_EXPEDITED_RSEQ` tolerates `0` or exactly
/// `MEMBARRIER_CMD_FLAG_CPU`; every other command rejects any non-zero
/// `flags`. This runs BEFORE the command is checked for existence, so a
/// bad-flags call against an unknown command still reports the flags error.
/// # C: O(1)
pub fn validate_flags(cmd: i32, flags: u32) -> Result<(), Errno> {
    if cmd == CMD_PRIVATE_EXPEDITED_RSEQ {
        if flags != 0 && flags != FLAG_CPU { return Err(Errno::Einval); }
        return Ok(());
    }
    if flags != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Full admission in Linux's order: flags, then `cpu_id` normalisation, then
/// the command switch. Only values outside the command enum are `EINVAL`;
/// every advertised command is admitted and answered by a work fn, where a
/// missing registration reports `EPERM` rather than `EINVAL`.
/// # C: O(1)
pub fn decide(cmd: i32, flags: u32, cpu_id: i32) -> Result<Op, Errno> {
    validate_flags(cmd, flags)?;
    let cpu_id = normalize_cpu_id(flags, cpu_id);
    match cmd {
        CMD_QUERY                       => Ok(Op::Query),
        CMD_GLOBAL                      => Ok(Op::Global),
        CMD_GLOBAL_EXPEDITED            => Ok(Op::GlobalExpedited),
        CMD_REGISTER_GLOBAL_EXPEDITED   => Ok(Op::RegisterGlobalExpedited),
        CMD_PRIVATE_EXPEDITED           => Ok(Op::PrivateExpedited { cpu_id }),
        CMD_REGISTER_PRIVATE_EXPEDITED  => Ok(Op::RegisterPrivateExpedited),
        CMD_PRIVATE_EXPEDITED_SYNC_CORE => Ok(Op::PrivateExpeditedSyncCore { cpu_id }),
        CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE => Ok(Op::RegisterPrivateExpeditedSyncCore),
        CMD_PRIVATE_EXPEDITED_RSEQ      => Ok(Op::PrivateExpeditedRseq { cpu_id }),
        CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ => Ok(Op::RegisterPrivateExpeditedRseq),
        CMD_GET_REGISTRATIONS           => Ok(Op::GetRegistrations),
        _ => Err(Errno::Einval),
    }
}

/// `MEMBARRIER_CMD_GET_REGISTRATIONS` encoding: the set of REGISTER commands
/// previously issued against the caller's mm, one bit each.
///
/// The inputs test EITHER bit of each intent/ready pair, which is a WEAKER
/// test than the one gating `EPERM`. Registering SYNC_CORE or RSEQ sets the
/// shared private-expedited intent bit without its ready bit, so this reports
/// `REGISTER_PRIVATE_EXPEDITED` too while plain `PRIVATE_EXPEDITED` still
/// answers `EPERM`.
/// # C: O(1)
pub fn registrations_mask(global: bool, private: bool, sync_core: bool, rseq: bool) -> i32 {
    let mut m = 0;
    if global    { m |= CMD_REGISTER_GLOBAL_EXPEDITED; }
    if private   { m |= CMD_REGISTER_PRIVATE_EXPEDITED; }
    if sync_core { m |= CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE; }
    if rseq      { m |= CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ; }
    m
}

#[cfg(test)]
mod tests;
