// `sys_sendmmsg` / `sys_recvmmsg` — split out of net.rs per
// `08§7`. Each walks the mmsghdr vector and calls the underlying
// per-message variant. Errors are reported only if zero messages
// completed (Linux semantics).

#![cfg(target_os = "oxide-kernel")]

use hal::USER_VA_END;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::s046_sendmsg::sys_sendmsg;
use crate::s047_recvmsg::sys_recvmsg;

/// `sendmmsg(fd, mmsghdr*, vlen, flags)` — slot 307. Walks the
/// mmsghdr array calling `sendmsg` for each entry; writes the
/// per-entry byte count into the trailing `msg_len` u32 of each
/// mmsghdr. Stops on the first error and returns the count of
/// successfully-sent messages.
/// # C: O(vlen)
pub fn sys_sendmmsg(args: &SyscallArgs) -> i64 {
    let fd       = args.a0;
    let mmsg_ptr = args.a1;
    let vlen     = args.a2;
    let flags    = args.a3;
    if mmsg_ptr == 0 || vlen == 0 { return 0; }
    if vlen > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let mut sent: i64 = 0;
    for i in 0..vlen {
        // struct mmsghdr = { struct msghdr (56 bytes); u32 msg_len; pad }; size 64.
        let entry = mmsg_ptr + i * 64;
        if entry >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let mut sa = *args;
        sa.a0 = fd; sa.a1 = entry; sa.a2 = flags;
        let r = sys_sendmsg(&sa);
        if r < 0 {
            return if sent > 0 { sent } else { r };
        }
        // SAFETY: entry < USER_VA_END; msg_len at +56 within the 64-byte mmsghdr.
        unsafe { core::ptr::write_volatile((entry + 56) as *mut u32, r as u32); }
        sent += 1;
    }
    sent
}

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
        let entry = mmsg_ptr + i * 64;
        if entry >= USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        let mut sa = *args;
        sa.a0 = fd; sa.a1 = entry; sa.a2 = flags;
        let r = sys_recvmsg(&sa);
        if r < 0 {
            return if got > 0 { got } else { r };
        }
        if r == 0 { break; }
        // SAFETY: entry < USER_VA_END; msg_len at +56 within the 64-byte mmsghdr.
        unsafe { core::ptr::write_volatile((entry + 56) as *mut u32, r as u32); }
        got += 1;
    }
    got
}
