// 170 sethostname — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sethostname(name, len)` — slot 170. Updates the hostname visible
/// via uname.nodename, writing the calling task's UTS namespace (shared by
/// all members via the `nscg` uts registry; uts_ns 0 = global). Requires
/// CAP_SYS_ADMIN.
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
    // Write the calling task's UTS namespace (shared by all members);
    // uts_ns 0 = the global hostname (Linux refcounted uts_namespace).
    let uts_ns = cur.uts_ns.load(Ordering::Acquire);
    crate::hostname::set_host_for(uts_ns, &buf[..len]);
    0
}
