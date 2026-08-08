// 046 sendmsg - ABI import and one socket work-layer call.
#![cfg(target_os = "oxide-kernel")]

use syscall::{SyscallArgs, errno::Errno};

use crate::msg_layout::{EntryAbi, entry::layout_or_errno};

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }
fn encode<T: Into<i64>>(result: socket::KResult<T>) -> i64 {
    match result { Ok(value) => value.into(), Err(error) => -(error.errno() as i64) }
}

/// `sendmsg(fd, msghdr, flags)` slot 46. # C: O(iov + payload + control)
pub fn sys_sendmsg(args: &SyscallArgs) -> i64 {
    // One owner settles the message layout, before the task or the descriptor:
    // a native caller that set `MSG_CMSG_COMPAT` gets EINVAL there, and the
    // importer below is driven by the returned value rather than by the flag.
    let layout = match layout_or_errno(args.a2, EntryAbi::Native) {
        Ok(layout) => layout, Err(e) => return e,
    };
    let task = match sched::live::current() { Some(task) => task, None => return err(Errno::Ebadf) };
    let context = socket::SendContext::new(task);
    let mut message = crate::send_user::SendMsgIo::new(task, args.a0 as i32, args.a1, layout);
    encode(socket::send_io(&context, args.a2 as u32, &mut message)
        .map(|outcome| outcome.bytes as i64))
}
