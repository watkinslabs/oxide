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

/// `sys_getcpu(cpu, node, tcache)` — slot 309. Reports the current logical CPU
/// from the arch HAL. Oxide has no NUMA topology yet, so node remains 0.
/// # C: O(1)
pub fn sys_getcpu(args: &SyscallArgs) -> i64 {
    let cpu  = args.a0;
    let node = args.a1;
    let current = current_cpu_id();
    if cpu != 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf(cpu, 4, 4) {
            return rv;
        }
        // SAFETY: user buffer validated writable for a u32.
        unsafe { core::ptr::write_volatile(cpu as *mut u32, current); }
    }
    if node != 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf(node, 4, 4) {
            return rv;
        }
        // SAFETY: user buffer validated writable for a u32.
        unsafe { core::ptr::write_volatile(node as *mut u32, 0); }
    }
    0
}
