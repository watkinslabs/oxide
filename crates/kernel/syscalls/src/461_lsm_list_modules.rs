// 461 lsm_list_modules — one syscall, one file (docs/53 §0).
//
// No LSM is loaded → zero active security modules. Write *size = 0 (bytes
// needed) and return 0, matching a Linux kernel with no enabled LSM.

use syscall::{errno::Errno, SyscallArgs};

/// `sys_lsm_list_modules(ids, size, flags)` — slot 461.
/// # C: O(1)
pub fn sys_lsm_list_modules(args: &SyscallArgs) -> i64 {
    let size_ptr = args.a1;
    if args.a2 != 0 { return -(Errno::Einval.as_i32() as i64); }   // flags must be 0
    if size_ptr != 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf_writable(size_ptr, 4, 1) { return rv; }
        // SAFETY: size_ptr validated writable for four bytes; Linux copyout accepts unaligned storage.
        unsafe { core::ptr::write_unaligned(size_ptr as *mut u32, 0); }
    }
    0
}
