// 324 membarrier — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::membarrier::{decide, registrations_mask, Op, QUERY_MASK};

/// `sys_membarrier(cmd, flags, cpu_id)` — slot 324, Linux
/// `SYSCALL_DEFINE3(membarrier)` (`kernel/sched/membarrier.c`).
///
/// Shim only: admission + `cpu_id` normalisation live in
/// `crate::membarrier` (hosted-tested), the barriers and the per-mm
/// registration state live in `sched::membarrier` + `vmm::AddressSpace`.
/// Commands outside `QUERY_MASK` answer `EINVAL`, exactly as Linux does
/// without `CONFIG_ARCH_HAS_MEMBARRIER_SYNC_CORE` / `CONFIG_RSEQ`.
/// # C: O(online CPUs) + IPI round trip for the expedited commands
pub fn sys_membarrier(args: &SyscallArgs) -> i64 {
    let op = match decide(args.a0 as i32, args.a1 as u32, args.a2 as i32) {
        Ok(o) => o,
        Err(e) => return -(e.as_i32() as i64),
    };
    let r: Result<i64, Errno> = match op {
        Op::Query                       => Ok(QUERY_MASK as i64),
        Op::Global                      => sched::membarrier::global().map(|()| 0),
        Op::GlobalExpedited             => sched::membarrier::global_expedited().map(|()| 0),
        Op::RegisterGlobalExpedited     => sched::membarrier::register_global_expedited().map(|()| 0),
        Op::PrivateExpedited { cpu_id } => sched::membarrier::private_expedited(cpu_id).map(|()| 0),
        Op::RegisterPrivateExpedited    => sched::membarrier::register_private_expedited().map(|()| 0),
        Op::GetRegistrations            => sched::membarrier::registrations()
            .map(|(g, p)| registrations_mask(g, p) as i64),
    };
    match r { Ok(v) => v, Err(e) => -(e.as_i32() as i64) }
}
