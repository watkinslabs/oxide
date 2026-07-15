// 170 sethostname — one syscall, one file (docs/53 §0). Moved verbatim from proc.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sethostname(name, len)` — slot 170. Updates the hostname visible
/// via uname.nodename, writing the calling task's UTS namespace (shared by
/// all members via the exact `nscg` UTS owner). Requires CAP_SYS_ADMIN.
/// # C: O(N)
pub fn sys_sethostname(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let ptr = args.a0;
    let len = args.a1 as usize;
    if len > crate::hostname::HOST_NAME_MAX { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    if !cur.has_cap(sched::cap::SYS_ADMIN) { return -(Errno::Eperm.as_i32() as i64); }
    if len != 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf(ptr, len as u64, 1) { return rv; }
    }
    let mut buf = [0u8; crate::hostname::HOST_NAME_MAX];
    // SAFETY: nonzero source range was validated readable; Linux copyin accepts byte-granular storage.
    unsafe {
        for i in 0..len { buf[i] = core::ptr::read_unaligned((ptr + i as u64) as *const u8); }
    }
    let owner = match cur.namespace_owner(namespace_identity::NamespaceKind::Uts) {
        Some(owner) => owner, None => return -(Errno::Esrch.as_i32() as i64),
    };
    match crate::hostname::set_host_for(&owner, &buf[..len]) {
        Ok(()) => 0,
        Err(_) => -(Errno::Eio.as_i32() as i64),
    }
}
