// 173 ioperm — ABI shim only (`docs/53` §0). The range ladder, the permission
// map and the TSS window live in `sched::ioport`; this file parses, fetches
// `CAP_SYS_RAWIO`, calls one work fn and encodes.
//
// x86-only by construction: the aarch64 generic ABI assigns 173 to `getppid`,
// so `arm_abi` never routes an arm caller here.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `SYSCALL_DEFINE3(ioperm, unsigned long, from, unsigned long, num, int,
/// turn_on)` — grant or withdraw `num` I/O ports starting at `from` for this
/// thread.
///
/// `turn_on` is any non-zero int, matching the reference's plain `int`
/// parameter; only a grant costs `CAP_SYS_RAWIO`, so a process that dropped
/// privilege can still give its ports back.
/// # C: O(num)
/// # Ctx: process
pub fn sys_ioperm(args: &SyscallArgs) -> i64 {
    let Some(cur) = sched::live::current() else { return -(Errno::Einval.as_i32() as i64) };
    let turn_on = (args.a2 as i32) != 0;
    let capable = crate::perm_common::capable(&cur, sched::cap::SYS_RAWIO);
    sched::ioport::ioperm(&cur, args.a0, args.a1, turn_on, capable)
}
