// 099 sysinfo — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf_writable;

/// `sys_sysinfo(info)` — slot 99. Linux `struct sysinfo` (112 B):
/// uptime/totalram/freeram/procs/mem_unit filled; loads + swap zero.
/// # C: O(N_tasks) on procs count.
pub fn sys_sysinfo(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    let buf = args.a0;
    if let Err(rv) = validate_user_buf_writable(buf, 112, 1) { return rv; }
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
    // SAFETY: buf validated writable for the 112-byte Linux sysinfo result.
    unsafe {
        for off in (0..112u64).step_by(8) {
            core::ptr::write_unaligned((buf + off) as *mut u64, 0);
        }
        core::ptr::write_unaligned((buf +   0) as *mut i64, uptime);
        core::ptr::write_unaligned((buf +  32) as *mut u64, totalram_bytes);
        core::ptr::write_unaligned((buf +  40) as *mut u64, freeram_bytes);
        core::ptr::write_unaligned((buf +  80) as *mut u16, procs);
        core::ptr::write_unaligned((buf + 104) as *mut u32, 1u32); // mem_unit
    }
    0
}
