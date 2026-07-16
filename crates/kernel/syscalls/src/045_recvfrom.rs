// recvfrom ABI shim: import one buffer, retain one socket, dispatch one receive.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `recvfrom(fd, buf, len, flags, src, srclen)` slot 45. # C: O(1)
pub fn sys_recvfrom(args: &SyscallArgs) -> i64 {
    let user = crate::recv_user::import_recvfrom(args.a1, args.a2 as usize, args.a4, args.a5);
    let target = match crate::recvmsg::lookup(args.a0) {
        Ok(target) => target,
        Err(error) => return error,
    };
    crate::recvmsg::recv(&target, &user, args.a3)
}
