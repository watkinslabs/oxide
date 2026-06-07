// 046 sendmsg — one syscall, one file (docs/53 §0). Moved verbatim from net.rs.
#![cfg(target_os = "oxide-kernel")]
use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

/// `sendmsg(fd, msghdr, flags)` slot 46. F189 honors SCM_RIGHTS
/// when the dest is an AF_UNIX SOCK_DGRAM (captures Arc<File> from
/// current fd_table; receiver dup's via recvmsg_unix_dgram).
/// # C: O(iov + nfds)
pub fn sys_sendmsg(args: &SyscallArgs) -> i64 {
    let fd     = args.a0;
    let msgp   = args.a1;
    let _flags = args.a2;
    if msgp == 0 || msgp >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
    // SAFETY: msgp range validated; user page mapped under caller's AS.
    let (name, _namelen, iov, iovlen, control, controllen) = unsafe {
        let name      = core::ptr::read_volatile(msgp as *const u64);
        let namelen   = core::ptr::read_volatile((msgp + 8) as *const u32);
        let iov       = core::ptr::read_volatile((msgp + 16) as *const u64);
        let iovlen    = core::ptr::read_volatile((msgp + 24) as *const u64);
        let control   = core::ptr::read_volatile((msgp + 32) as *const u64);
        let controllen= core::ptr::read_volatile((msgp + 40) as *const u64);
        (name, namelen, iov, iovlen, control, controllen)
    };
    // F189: SCM_RIGHTS short-circuit for AF_UNIX SOCK_DGRAM.
    if let Some(r) = crate::cmsg_parse::try_sendmsg_with_fds(
        fd, name, iov, iovlen, control, controllen,
    ) { return r; }
    if iovlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let mut total: i64 = 0;
    for i in 0..iovlen {
        let iov_i = iov + i * 16;
        if iov_i >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: iov_i lies in user range; 8-byte aligned per Linux ABI; sendmsg path.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: iov_i + 8 still inside the iovec entry; len field is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        let mut sa = *args;
        sa.a0 = fd; sa.a1 = base; sa.a2 = len; sa.a3 = 0; sa.a4 = name; sa.a5 = 0;
        let r = crate::s044_sendto::sys_sendto(&sa);
        if r < 0 { return if total > 0 { total } else { r }; }
        total += r;
    }
    total
}
