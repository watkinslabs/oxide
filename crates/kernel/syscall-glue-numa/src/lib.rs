// NUMA syscalls (`get_mempolicy`). v1 is UMA single-node; this
// module returns MPOL_DEFAULT and a one-node mask honestly instead
// of leaving caller buffers uninitialised (which silent-0 would do).

#![no_std]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_get_mempolicy(mode_p, nodemask_p, maxnode, addr, flags)` — slot 239.
/// # C: O(maxnode/8)
pub fn kernel_sys_get_mempolicy(args: &SyscallArgs) -> i64 {
    let mode_p  = args.a0;
    let mask_p  = args.a1;
    let maxnode = args.a2 as usize;
    if mode_p != 0 {
        if mode_p >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: mode_p validated < USER_VA_END; CPL=0 i32 write of MPOL_DEFAULT (0) through caller's AS.
        unsafe { core::ptr::write_volatile(mode_p as *mut i32, 0); }
    }
    if mask_p != 0 && maxnode > 0 {
        let nbytes = (maxnode + 7) / 8;
        if mask_p >= hal::USER_VA_END
            || mask_p.checked_add(nbytes as u64).map(|e| e > hal::USER_VA_END).unwrap_or(true) {
            return -(Errno::Efault.as_i32() as i64);
        }
        // SAFETY: mask_p+nbytes validated < USER_VA_END; CPL=0 byte writes through caller's AS, bit 0 set on first byte for single-node UMA.
        unsafe {
            for i in 0..nbytes { core::ptr::write_volatile((mask_p + i as u64) as *mut u8, 0); }
            core::ptr::write_volatile(mask_p as *mut u8, 1);
        }
    }
    0
}
