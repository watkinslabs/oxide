// `membarrier(2)` UAPI + admission — Linux `include/uapi/linux/membarrier.h`
// and the `SYSCALL_DEFINE3(membarrier)` body in `kernel/sched/membarrier.c`.
//
// Deliberately NOT kernel-cfg'd: slot files are
// `#![cfg(target_os = "oxide-kernel")]` and unreachable from the hosted
// suite, which would leave the flags-before-command ordering, the QUERY
// bitmask, and the FLAG_CPU rule — the whole ABI contract — untested. The
// slot file stays a thin shim (`docs/53`) that calls `decide` and then one
// `sched::membarrier` work fn per command.
//
// WHAT IS ADVERTISED, AND WHY THE MASK IS SMALLER THAN LINUX'S.
// `QUERY_MASK` is a promise: userspace (glibc, liburcu) issues exactly what
// the mask claims. Four Linux commands are therefore left OUT and answer
// `EINVAL`, which is precisely how Linux answers them on a kernel built
// without the matching config:
//   * `PRIVATE_EXPEDITED_SYNC_CORE` + its REGISTER
//     (`!CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE`). The contract covers threads
//     that are NOT running: the arch must guarantee a core-serializing
//     instruction before they resume user mode, which Linux implements with a
//     per-mm flag consulted on every return-to-user
//     (`membarrier_mm_sync_core_before_usermode`). That hook does not exist
//     here, so the guarantee could not be honoured for a descheduled thread.
//   * `PRIVATE_EXPEDITED_RSEQ` + its REGISTER (`!CONFIG_RSEQ`). The command
//     must RESTART rseq critical sections on the target CPUs;
//     `sched::rseq` registers the user struct and writes `cpu_id` back but
//     has no `rseq_cs` / IP-fixup machinery, so there is nothing to restart.
// `GLOBAL`, `GLOBAL_EXPEDITED`, `PRIVATE_EXPEDITED`, both surviving
// REGISTERs, and `GET_REGISTRATIONS` are backed by real work.

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
/// `MEMBARRIER_CMD_PRIVATE_EXPEDITED_SYNC_CORE` — refused, see module head.
pub const CMD_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 5;
/// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE` — refused.
pub const CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE: i32 = 1 << 6;
/// `MEMBARRIER_CMD_PRIVATE_EXPEDITED_RSEQ` — refused, see module head.
pub const CMD_PRIVATE_EXPEDITED_RSEQ: i32 = 1 << 7;
/// `MEMBARRIER_CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ` — refused.
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

/// Commands answered with `EINVAL` — the module head says why each one
/// cannot be honoured. Linux drops the same bits when
/// `CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE` / `CONFIG_RSEQ` are off.
pub const REFUSED_MASK: i32 = CMD_PRIVATE_EXPEDITED_SYNC_CORE
    | CMD_REGISTER_PRIVATE_EXPEDITED_SYNC_CORE
    | CMD_PRIVATE_EXPEDITED_RSEQ
    | CMD_REGISTER_PRIVATE_EXPEDITED_RSEQ;

/// What `MEMBARRIER_CMD_QUERY` returns. Every bit is backed by a
/// `sched::membarrier` work fn.
pub const QUERY_MASK: i32 = LINUX_CMD_BITMASK & !REFUSED_MASK;

/// One admitted request. The shim maps each arm to exactly one work fn.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Op {
    Query,
    Global,
    GlobalExpedited,
    RegisterGlobalExpedited,
    PrivateExpedited { cpu_id: i32 },
    RegisterPrivateExpedited,
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
/// the command switch. Commands outside `QUERY_MASK` — unknown values and the
/// four unimplemented Linux commands alike — are `EINVAL`.
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
        CMD_GET_REGISTRATIONS           => Ok(Op::GetRegistrations),
        _ => Err(Errno::Einval),
    }
}

/// `MEMBARRIER_CMD_GET_REGISTRATIONS` encoding: the set of REGISTER commands
/// previously issued against the caller's mm. The SYNC_CORE / RSEQ REGISTERs
/// can never appear because they are refused at admission.
/// # C: O(1)
pub fn registrations_mask(global_ready: bool, private_ready: bool) -> i32 {
    let mut m = 0;
    if global_ready  { m |= CMD_REGISTER_GLOBAL_EXPEDITED; }
    if private_ready { m |= CMD_REGISTER_PRIVATE_EXPEDITED; }
    m
}

#[cfg(test)]
mod tests;
