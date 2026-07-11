// `sys_recvmmsg` — slot 299. Walks the mmsghdr vector calling the
// per-message `recvmsg` variant. Error reported only if zero
// messages completed (Linux semantics). Split per `08§7` / `53§0`.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::s047_recvmsg::sys_recvmsg;

/// `recvmmsg(fd, mmsghdr*, vlen, flags, timeout)` — slot 299.
/// Calls recvmsg per entry; same Linux semantics as sendmmsg.
/// Timeout currently ignored (recvfrom path already polls via
/// internal yield-loop on blocking sockets).
/// # C: O(vlen)
pub fn sys_recvmmsg(args: &SyscallArgs) -> i64 {
    let fd       = args.a0;
    let mmsg_ptr = args.a1;
    let vlen     = args.a2;
    let flags    = args.a3;
    let _timeout = args.a4;
    if mmsg_ptr == 0 || vlen == 0 { return 0; }
    if vlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let mut got: i64 = 0;
    for i in 0..vlen {
        let Some(entry) = mmsg_ptr.checked_add(i.saturating_mul(64)) else {
            return -(Errno::Efault.as_i32() as i64);
        };
        let Some(len_ptr) = entry.checked_add(56) else {
            return -(Errno::Efault.as_i32() as i64);
        };
        if let Err(rv) = crate::userbuf::validate_user_buf_writable(len_ptr, 4, 1) { return rv; }
        let mut sa = *args;
        sa.a0 = fd; sa.a1 = entry; sa.a2 = flags;
        let r = sys_recvmsg(&sa);
        if r < 0 {
            return if got > 0 { got } else { r };
        }
        if r == 0 { break; }
        // SAFETY: msg_len was validated as the writable 4-byte user slot for this mmsghdr entry.
        unsafe { core::ptr::write_unaligned(len_ptr as *mut u32, r as u32); }
        got += 1;
    }
    got
}
