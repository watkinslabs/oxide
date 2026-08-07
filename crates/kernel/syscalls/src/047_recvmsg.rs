// recvmsg ABI shim: settle the layout, import metadata once, select protocol
// owner, encode outputs there.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::msg_layout::EntryAbi;

/// `recvmsg(fd, msghdr, flags)` slot 47. # C: O(iov metadata)
pub fn sys_recvmsg(args: &SyscallArgs) -> i64 {
    let flags = args.a2;
    let (_layout, target, user) = match crate::recvmsg::entry::prepare(flags, EntryAbi::Native,
        || crate::recvmsg::lookup(args.a0),
        |layout| crate::recv_user::import(args.a1, layout))
    { Ok(prepared) => prepared, Err(e) => return e };
    crate::recvmsg::recv(&target, &user, flags)
}
