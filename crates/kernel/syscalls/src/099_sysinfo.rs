// 099 sysinfo — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf_writable;

const SYSINFO_BYTES: u64 = 112;
const SYSINFO_WORD_BYTES: usize = core::mem::size_of::<u64>();
const NSEC_PER_SEC: u64 = 1_000_000_000;
const OFF_UPTIME: u64 = 0;
const OFF_LOADS: u64 = 8;
const OFF_TOTAL_RAM: u64 = 32;
const OFF_FREE_RAM: u64 = 40;
const OFF_TOTAL_SWAP: u64 = 64;
const OFF_FREE_SWAP: u64 = 72;
const OFF_PROCS: u64 = 80;
const OFF_MEM_UNIT: u64 = 104;
const MEM_UNIT_BYTES: u32 = 1;

/// `sys_sysinfo(info)` — slot 99. Linux `struct sysinfo` (112 B):
/// uptime, scheduler loads, RAM, canonical swap capacity/free space, process
/// count, and `mem_unit`. # C: O(caches + swap areas + mms + N_tasks).
pub fn sys_sysinfo(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    let buf = args.a0;
    if let Err(rv) = validate_user_buf_writable(buf, SYSINFO_BYTES, MEM_UNIT_BYTES as u64) { return rv; }
    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let uptime = (ns / NSEC_PER_SEC) as i64;
    let memory = procfs::memory::snapshot();
    let totalram_bytes = memory.managed_pages.saturating_mul(hal::PAGE_SIZE_BYTES);
    let freeram_bytes = memory.free_pages.saturating_mul(hal::PAGE_SIZE_BYTES);
    let totalswap_bytes = memory.swap_total_pages.saturating_mul(hal::PAGE_SIZE_BYTES);
    let freeswap_bytes = memory.swap_free_pages.saturating_mul(hal::PAGE_SIZE_BYTES);
    let loads = sched::loadavg::sysinfo_snapshot();
    let procs: u16 = sched::live::registry::live_counts().0.min(u16::MAX as u64) as u16;
    // SAFETY: `buf` names one writable Linux `struct sysinfo` result.
    unsafe {
        for off in (0..SYSINFO_BYTES).step_by(SYSINFO_WORD_BYTES) {
            core::ptr::write_unaligned((buf + off) as *mut u64, 0);
        }
        core::ptr::write_unaligned((buf + OFF_UPTIME) as *mut i64, uptime);
        for (index, load) in loads.into_iter().enumerate() {
            core::ptr::write_unaligned((buf + OFF_LOADS + index as u64 * SYSINFO_WORD_BYTES as u64) as *mut u64, load);
        }
        core::ptr::write_unaligned((buf + OFF_TOTAL_RAM) as *mut u64, totalram_bytes);
        core::ptr::write_unaligned((buf + OFF_FREE_RAM) as *mut u64, freeram_bytes);
        core::ptr::write_unaligned((buf + OFF_TOTAL_SWAP) as *mut u64, totalswap_bytes);
        core::ptr::write_unaligned((buf + OFF_FREE_SWAP) as *mut u64, freeswap_bytes);
        core::ptr::write_unaligned((buf + OFF_PROCS) as *mut u16, procs);
        core::ptr::write_unaligned((buf + OFF_MEM_UNIT) as *mut u32, MEM_UNIT_BYTES);
    }
    0
}
