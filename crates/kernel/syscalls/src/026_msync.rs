// 026 msync — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `MS_ASYNC` — schedule writeback (we flush synchronously, a legal superset).
const MS_ASYNC: u64 = 0x1;
/// `MS_INVALIDATE` — invalidate other mappings (no-op: our mappings already
/// alias one coherent page-cache frame set, so there is nothing stale to drop).
const MS_INVALIDATE: u64 = 0x2;
/// `MS_SYNC` — flush and wait.
const MS_SYNC: u64 = 0x4;
const PAGE_MASK: u64 = 0xFFF;

/// `sys_msync(addr, len, flags)` — slot 26. Flush dirty `MAP_SHARED` page-cache
/// frames to disk (D8). `addr` must be page-aligned; `flags` must be a valid
/// `MS_*` combination (`MS_SYNC` and `MS_ASYNC` are mutually exclusive). The
/// flush itself is range-coarse: it persists every dirty ext4 frame store, a
/// POSIX-legal superset of the requested `[addr, addr+len)` window (msync may
/// flush more than asked). `addr`→VMA→inode narrowing is not done here — that
/// would require walking the VMA tree (owned by mm-vmm). # C: O(N_dirty)
pub fn sys_msync(args: &SyscallArgs) -> i64 {
    let addr  = args.a0;
    let flags = args.a2;
    if addr & PAGE_MASK != 0 { return -(Errno::Einval.as_i32() as i64); }
    if flags & !(MS_ASYNC | MS_INVALIDATE | MS_SYNC) != 0 { return -(Errno::Einval.as_i32() as i64); }
    if (flags & MS_SYNC != 0) && (flags & MS_ASYNC != 0) { return -(Errno::Einval.as_i32() as i64); }
    // D8: persist dirty ext4 frame stores (mmap writes reach disk here).
    ext4::flush_all_dirty();
    0
}
