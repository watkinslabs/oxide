// 309 getcpu — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

fn current_cpu_id() -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        use hal::CpuOps;
        hal_x86_64::X86CpuOps::current_cpu()
    }
    #[cfg(target_arch = "aarch64")]
    {
        use hal::CpuOps;
        hal_aarch64::ArmCpuOps::current_cpu()
    }
}

/// `sys_getcpu(cpu, node, tcache)` — slot 309.
///
/// Linux's `sys_getcpu`: `err |= put_user(...)` for BOTH pointers, then one
/// `-EFAULT` if either failed. A bad `cpup` therefore does NOT stop the
/// `nodep` store — returning early skips a write user space observed on Linux.
/// The third argument (`tcache`) has been ignored since 2.6.24; it is not
/// validated, matching `unused`.
///
/// `node` is 0 for every CPU: with no NUMA topology `cpu_to_node` reports node
/// 0 on Linux too.
/// # C: O(1)
pub fn sys_getcpu(args: &SyscallArgs) -> i64 {
    let cpu  = args.a0;
    let node = args.a1;
    const NUMA_NODE_UP: u32 = 0;
    let current = current_cpu_id();
    let mut err: i64 = 0;
    if cpu != 0 {
        if let Err(rv) = crate::userbuf::write_user_i32(cpu, current as i32) { err = rv; }
    }
    if node != 0 {
        if let Err(rv) = crate::userbuf::write_user_i32(node, NUMA_NODE_UP as i32) { err = rv; }
    }
    err
}
