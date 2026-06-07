// 011 munmap — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// # C: O(log N_vmas)
pub fn kernel_munmap(args: &SyscallArgs) -> i64 {
    // mseal(2): a sealed VMA in the range rejects munmap with EPERM.
    if let Some(cur) = sched::live::current() {
        // SAFETY: mm slot single-mutator per `13§5`; read-only seal query.
        if let Some(mm) = unsafe { cur.mm_ref() } {
            if let Some(ua) = hal::UserVirtAddr::new(args.a0) {
                if mm.range_sealed(ua, args.a1 as usize) {
                    return -(syscall::errno::Errno::Eperm.as_i32() as i64);
                }
            }
        }
    }
    pmm::user_as::glue_munmap(args.a0, args.a1)
}
