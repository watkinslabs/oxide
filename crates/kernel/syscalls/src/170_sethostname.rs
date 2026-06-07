// 170 sethostname — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sethostname(name, len)` — slot 170. Updates the hostname
/// visible via uname.nodename. Per F97: when the task carries
/// CLONE_NEWUTS, writes go to the per-task `uts_hostname` slot
/// (private to the namespace); else they update the global.
/// Requires CAP_SYS_ADMIN.
/// # C: O(N)
pub fn sys_sethostname(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let ptr = args.a0;
    let len = args.a1 as usize;
    if len > crate::hostname::HOST_NAME_MAX { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = crate::userbuf::validate_user_buf(ptr, len as u64, 1) { return rv; }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    if !cur.has_cap(sched::cap::SYS_ADMIN) { return -(Errno::Eperm.as_i32() as i64); }
    let mut buf = [0u8; crate::hostname::HOST_NAME_MAX];
    // SAFETY: ptr range validated < USER_VA_END; CPL=0 reads through caller's AS.
    unsafe {
        for i in 0..len { buf[i] = core::ptr::read_volatile((ptr + i as u64) as *const u8); }
    }
    if (cur.ns_membership.load(Ordering::Acquire) & (1u64 << 1)) != 0 {
        let s = match core::str::from_utf8(&buf[..len]) {
            Ok(s) => alloc::string::String::from(s),
            Err(_) => return -(Errno::Einval.as_i32() as i64),
        };
        // SAFETY: per-task uts_hostname slot single-mutator per `13§5`; running task on this CPU is the sole writer.
        unsafe { *cur.uts_hostname.get() = s; }
    } else {
        crate::hostname::set(&buf[..len]);
    }
    0
}
