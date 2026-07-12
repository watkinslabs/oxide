// 011 munmap — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// # C: O(log N_vmas)
pub fn kernel_munmap(args: &SyscallArgs) -> i64 {
    pmm::user_as::glue_munmap(args.a0, args.a1)
}
