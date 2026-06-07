// 176 delete_module — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `delete_module(name, flags)` slot 176. v1 takes the module
/// index encoded as the user pointer (since we don't yet parse
/// .modinfo names): pass the index in the low 16 bits.
/// # C: O(1)
pub fn sys_delete_module(args: &SyscallArgs) -> i64 {
    let idx = args.a0 as usize & 0xFFFF;
    if modules::registry::unload(idx) { 0 } else { -(Errno::Einval.as_i32() as i64) }
}
