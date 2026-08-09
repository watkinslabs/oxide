// 172 iopl — ABI shim only (`docs/53` §0). The level ladder, the emulated
// IOPL state and the TSS window all live in `sched::ioport`, which is
// ungated and hosted-tested; this file parses, fetches `CAP_SYS_RAWIO`, calls
// one work fn and encodes.
//
// x86-only by construction: the aarch64 generic ABI assigns 172 to `getpid`,
// so `arm_abi` never routes an arm caller here and there is nothing to refuse.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `SYSCALL_DEFINE1(iopl, unsigned int, level)` — grant or drop access to the
/// whole 65536-port space for this thread.
///
/// The grant is published through the TSS permit-everything window, not the
/// EFLAGS IOPL field: a real IOPL=3 would additionally let user mode execute
/// `cli`/`sti`, and a thread that disables interrupts is a thread that can
/// hang the machine. The port access `iopl(3)` promises is granted in full.
/// # C: O(1)
/// # Ctx: process
pub fn sys_iopl(args: &SyscallArgs) -> i64 {
    let Some(cur) = sched::live::current() else { return -(Errno::Einval.as_i32() as i64) };
    let level = args.a0 as u32;
    let capable = crate::perm_common::capable(&cur, sched::cap::SYS_RAWIO);
    sched::ioport::iopl(&cur, level, capable)
}
