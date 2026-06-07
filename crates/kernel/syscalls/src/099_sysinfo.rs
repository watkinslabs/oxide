// 099 sysinfo — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sysinfo(info)` — slot 99. Linux `struct sysinfo` (112 B):
/// uptime/totalram/freeram/procs/mem_unit filled; loads + swap zero.
/// # C: O(N_tasks) on procs count.
pub fn sys_sysinfo(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    use syscall::errno::Errno;
    let buf = args.a0;
    if buf == 0 || buf >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let uptime = (ns / 1_000_000_000) as i64;
    let (totalram_bytes, freeram_bytes) = match pmm::setup::pmm_static() {
        Some(p) => {
            let free_b  = p.free_pages() * hal::PAGE_SIZE_BYTES;
            let used_b  = p.allocated_pages() * hal::PAGE_SIZE_BYTES;
            (free_b + used_b, free_b)
        }
        None => (0, 0),
    };
    let procs: u16 = sched::live::registry::live_vpids().len().min(u16::MAX as usize) as u16;
    // SAFETY: 112-byte user buffer validated < USER_VA_END; CPL=0 writes through caller's AS; layout matches Linux struct sysinfo.
    unsafe {
        for off in (0..112u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        core::ptr::write_volatile((buf +   0) as *mut i64, uptime);
        core::ptr::write_volatile((buf +  32) as *mut u64, totalram_bytes);
        core::ptr::write_volatile((buf +  40) as *mut u64, freeram_bytes);
        core::ptr::write_volatile((buf +  80) as *mut u16, procs);
        core::ptr::write_volatile((buf + 104) as *mut u32, 1u32); // mem_unit
    }
    0
}
