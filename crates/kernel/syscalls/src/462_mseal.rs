// 462 mseal — one syscall, one file (docs/53 §0).
//
// mseal(start, len, flags): seal the mappings in [start, start+len) so later
// userspace mprotect/munmap/mremap on them fail with EPERM (memory-sealing
// hardening; glibc 2.40+/systemd use it). flags must be 0. Real semantics —
// the seal is per-VMA state enforced by the mprotect/munmap/mremap shims.

use hal::UserVirtAddr;
use syscall::errno::Errno;
use syscall::SyscallArgs;

/// `sys_mseal(start, len, flags)` — slot 462.
/// # C: O(K log N)
pub fn sys_mseal(args: &SyscallArgs) -> i64 {
    let start = args.a0;
    let len   = args.a1 as usize;
    let flags = args.a2;
    // mseal(2): no flags defined yet; non-zero / unaligned start → EINVAL.
    if flags != 0 || (start & 0xfff) != 0 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: mm slot single-mutator per `13§5`.
    let mm = match unsafe { cur.mm_ref() } {
        Some(m) => m.clone(), None => return -(Errno::Einval.as_i32() as i64),
    };
    let ua = match UserVirtAddr::new(start) {
        Some(u) => u, None => return -(Errno::Einval.as_i32() as i64),
    };
    match mm.mseal(ua, len) {
        Ok(()) => 0,
        // seal_range rejects an unmapped/hole range with Inval; mseal(2)
        // reports ENOMEM for a range not fully mapped.
        Err(_) => -(Errno::Enomem.as_i32() as i64),
    }
}
