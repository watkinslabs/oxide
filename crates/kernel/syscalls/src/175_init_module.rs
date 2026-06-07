// 175 init_module — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `init_module(image, len, params)` slot 175.
/// `image` is a user-mapped pointer to the .ko bytes; `len` is
/// the size; `params` ignored for v1.
/// # C: O(len)
pub fn sys_init_module(args: &SyscallArgs) -> i64 {
    let img = args.a0;
    let len = args.a1 as usize;
    if img == 0 || img >= hal::USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if len == 0 || len > 16 * 1024 * 1024 {
        return -(Errno::Einval.as_i32() as i64);
    }
    // SAFETY: ptr range validated < USER_VA_END; user pages mapped under caller's AS; bounded read.
    let bytes: alloc::vec::Vec<u8> = unsafe {
        core::slice::from_raw_parts(img as *const u8, len).to_vec()
    };
    match modules::registry::load_blob(&bytes) {
        Some(_) => 0,
        None    => -(Errno::Einval.as_i32() as i64),
    }
}
