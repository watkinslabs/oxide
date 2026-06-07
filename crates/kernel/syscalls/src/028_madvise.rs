// 028 madvise — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_madvise(addr, len, advice)` — slot 28. DONTNEED/FREE/REMOVE
/// drop pages (refault as zero); hints (NORMAL/RANDOM/SEQUENTIAL/etc)
/// no-op; HWPOISON needs CAP_SYS_ADMIN → EPERM; unknown → EINVAL.
/// # C: O(len/4096)
pub fn sys_madvise(args: &SyscallArgs) -> i64 {
    use hal::UserVirtAddr;
    use syscall::errno::Errno;
    // Drop-pages set: DONTNEED=4, FREE=8, REMOVE=9 — all observably
    // "drop and refault as zero" in v1 (no swap, no shmem hole).
    // Pure hints: NORMAL/RANDOM/SEQUENTIAL/WILLNEED/HUGEPAGE/etc.
    // HWPOISON=100 needs CAP_SYS_ADMIN → EPERM. Unknown → EINVAL.
    let addr   = args.a0;
    let len    = args.a1 as usize;
    let advice = args.a2;
    if addr == 0 || (addr & 0xFFF) != 0 { return -(Errno::Einval.as_i32() as i64); }
    if len == 0 { return 0; }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return 0 };
    let ua = match UserVirtAddr::new(addr) {
        Some(u) => u, None => return -(Errno::Einval.as_i32() as i64),
    };
    match advice {
        4 | 8 | 9 => {
            // F128: MADV_DONTNEED / MADV_FREE / MADV_REMOVE. Linux
            // drops physical pages but keeps the VMA — anonymous
            // refaults as zero, file-backed refaults from disk.
            // Prior impl destructively munmap+mmap, which dropped
            // VMA-specific flags (GROWSDOWN, file backing) and
            // could corrupt COW-shared frames. The new helper does
            // refcount-aware page eviction without touching VMAs.
            let _ = (cur, mm); // suppress unused warnings on this branch
            pmm::user_as::evict_pages_in_range(addr, len as u64)
        }
        0..=3 | 10..=21 => 0,                          // hints
        100 => -(Errno::Eperm.as_i32() as i64),        // MADV_HWPOISON
        _   => -(Errno::Einval.as_i32() as i64),
    }
}
