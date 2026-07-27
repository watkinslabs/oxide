// 453 map_shadow_stack — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_map_shadow_stack(addr, size, flags)` — slot 453 (x86 CET).
/// Allocates a user shadow stack — but ONLY when the CPU + kernel have user
/// shadow stacks enabled.
///
/// oxide does not implement CET user shadow-stack hardware enforcement, so
/// the feature is never enabled — making this the EXACT mainline response on
/// such a kernel, and complete rather than a coverage dodge: the glibc/loader
/// CET probe reads the error and disables shadow stacks for the process, so a
/// real program never relies on a successful return here.
///
/// The errno is EOPNOTSUPP, not ENOSYS. Mainline's first act is
/// `if (!cpu_feature_enabled(X86_FEATURE_USER_SHSTK)) return -EOPNOTSUPP;`
/// (`arch/x86/kernel/shstk.c`); the flags check that follows is unreachable
/// on such a CPU, so this single answer is the whole contract. A previous
/// comment here quoted ENOSYS — that was never verified against source.
/// # C: O(1)
pub fn sys_map_shadow_stack(_args: &SyscallArgs) -> i64 {
    -(Errno::Eopnotsupp.as_i32() as i64)
}
