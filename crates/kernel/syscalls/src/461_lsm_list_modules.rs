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
    if size_ptr != 0 && size_ptr.saturating_add(4) <= hal::USER_VA_END {
        // SAFETY: size_ptr range-checked < USER_VA_END; u32 store into user AS.
        unsafe { core::ptr::write_volatile(size_ptr as *mut u32, 0); }
    }
    0
}
