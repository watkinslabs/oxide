// 309 getcpu — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_getcpu(cpu, node, tcache)` — slot 309. v1 single-CPU UP →
/// always returns CPU 0, NUMA node 0.
/// # C: O(1)
pub fn sys_getcpu(args: &SyscallArgs) -> i64 {
    let cpu  = args.a0;
    let node = args.a1;
    if cpu  != 0 && cpu  < hal::USER_VA_END {
        // SAFETY: cpu pointer validated < USER_VA_END; CPL=0 writes through caller's AS via active CR3.
        unsafe { core::ptr::write_volatile(cpu  as *mut u32, 0); }
    }
    if node != 0 && node < hal::USER_VA_END {
        // SAFETY: node pointer validated < USER_VA_END; same AS as above.
        unsafe { core::ptr::write_volatile(node as *mut u32, 0); }
    }
    0
}
