// 099 sysinfo — ABI shim only (docs/53 §0). Layout + scaling live in
// `sysinfo_abi`; the values come from their owning subsystems.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf_writable;
use crate::sysinfo_abi::{encode_sysinfo, load_to_si, uptime_secs, SysInfo, SYSINFO_BYTES};

/// Byte-granular user buffer: the encoded image is copied byte by byte, so no
/// alignment is required of the caller's pointer.
const USER_BUF_BYTE_ALIGN: u64 = 1;

/// `sys_sysinfo(info)` — slot 99. Linux `do_sysinfo`: boot uptime (rounded up),
/// the 1/5/15-minute load averages at `SI_LOAD_SHIFT`, `si_meminfo` +
/// `si_swapinfo` memory accounting in bytes with `mem_unit = 1`, and
/// `nr_threads`. Every field is read from the subsystem that owns it; none is
/// a constant. # C: O(caches + swap areas + mms + N_tasks).
pub fn sys_sysinfo(args: &SyscallArgs) -> i64 {
    use hal::TimerOps;
    let buf = args.a0;
    if let Err(rv) = validate_user_buf_writable(buf, SYSINFO_BYTES as u64, USER_BUF_BYTE_ALIGN) { return rv; }
    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let m = procfs::memory::snapshot();
    let pages = |n: u64| n.saturating_mul(hal::PAGE_SIZE_BYTES);
    let si = SysInfo {
        uptime_sec: uptime_secs(ns),
        loads: sched::loadavg::snapshot()
            .map(|l| load_to_si(l, sched::loadavg::FSHIFT)),
        totalram:  pages(m.managed_pages),
        freeram:   pages(m.free_pages),
        // `si_meminfo`: sharedram = NR_SHMEM. The VFS shmem accounting owns
        // that page class and already feeds `/proc/meminfo`'s `Shmem:` line.
        sharedram: pages(m.shmem_pages),
        // `si_meminfo`: bufferram = `nr_blockdev_pages()`, the page count in
        // RAW BLOCK-DEVICE inode mappings. oxide has no bdev-inode page cache —
        // every cached page belongs to a file inode, which Linux counts under
        // `Cached`, not `Buffers` — so this is a true zero, not a stub.
        bufferram: 0,
        totalswap: pages(m.swap_total_pages),
        freeswap:  pages(m.swap_free_pages),
        procs: sched::live::registry::live_counts().0.min(u16::MAX as u64) as u16,
        // No CONFIG_HIGHMEM on a 64-bit kernel: `totalhigh_pages()` and
        // `nr_free_highpages()` are 0, and so are these.
        totalhigh: 0,
        freehigh:  0,
    };
    let img = encode_sysinfo(&si);
    // SAFETY: `buf` names one validated writable Linux `struct sysinfo`; the
    // image is exactly SYSINFO_BYTES and byte writes need no alignment.
    unsafe {
        for (i, byte) in img.iter().enumerate() {
            core::ptr::write_unaligned((buf + i as u64) as *mut u8, *byte);
        }
    }
    0
}
