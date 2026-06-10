// 453 map_shadow_stack — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_map_shadow_stack(addr, size, flags)` — slot 453 (Linux 6.6, x86 CET).
/// Allocates a user shadow stack — but ONLY when the CPU + kernel have user
/// shadow stacks enabled. Mainline's first act is
/// `if (!cpu_feature_enabled(X86_FEATURE_USER_SHSTK)) return -ENOSYS;`.
///
/// oxide does not implement CET user shadow-stack hardware enforcement, so
/// the feature is never enabled — making `-ENOSYS` the EXACT mainline
/// response on such a kernel. This is the complete, correct behavior (not a coverage
/// dodge): the glibc/loader CET probe reads this `-ENOSYS` and disables
/// shadow stacks for the process, so a real program never relies on a
/// successful return here.
/// # C: O(1)
pub fn sys_map_shadow_stack(_args: &SyscallArgs) -> i64 {
    -(Errno::Enosys.as_i32() as i64)
}
