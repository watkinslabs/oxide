// 160 setrlimit — one syscall, one file (docs/53 §0). ABI shim only: the whole
// decision ladder is `sched::Task::do_prlimit` (Linux `kernel/sys.c
// do_prlimit`), shared with 097 getrlimit and 302 prlimit64.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use crate::userbuf::validate_user_buf;

/// `sys_setrlimit(resource, rlim)` — slot 160.
///
/// ```text
/// SYSCALL_DEFINE2(setrlimit, unsigned int, resource, struct rlimit __user *, rlim)
/// {
///         struct rlimit new_rlim;
///         if (copy_from_user(&new_rlim, rlim, sizeof(*rlim)))
///                 return -EFAULT;
///         return do_prlimit(current, resource, &new_rlim, NULL);
/// }
/// ```
///
/// The copy comes FIRST: an unreadable `rlim` is EFAULT even when `resource`
/// is out of range. Everything after it belongs to `do_prlimit`.
/// # C: O(1)
pub fn sys_setrlimit(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let resource = args.a0 as usize;
    let rlim = args.a1;
    if let Err(rv) = validate_user_buf(rlim, 16, 1) { return rv; }
    // SAFETY: rlim validated readable for the 16-byte struct rlimit input; both u64 fields lie inside the validated range.
    let (new_cur, new_max) = unsafe {
        let c = core::ptr::read_unaligned( rlim       as *const u64);
        let m = core::ptr::read_unaligned((rlim + 8)  as *const u64);
        (c, m)
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let cap = cur.has_cap(sched::cap::SYS_RESOURCE);
    match cur.do_prlimit(resource, Some((new_cur, new_max)), cap) {
        Ok(_)  => 0,
        Err(e) => -(crate::rlimit_policy::errno_of(e).as_i32() as i64),
    }
}
