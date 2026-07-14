// recvmsg ABI shim: import metadata once, select protocol owner, encode outputs there.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `recvmsg(fd, msghdr, flags)` slot 47. # C: O(iov metadata)
pub fn sys_recvmsg(args: &SyscallArgs) -> i64 {
    let flags = args.a2;
    let target = match crate::recvmsg::lookup(args.a0) { Ok(target) => target, Err(e) => return e };
    let user = match crate::recv_user::import(args.a1) { Ok(user) => user, Err(e) => return e };
    crate::recvmsg::recv(&target, &user, flags)
}
