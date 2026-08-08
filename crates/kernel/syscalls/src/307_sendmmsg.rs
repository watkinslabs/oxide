// 307 sendmmsg - lazy ABI importer for socket work-layer batching.
#![cfg(target_os = "oxide-kernel")]

use syscall::{SyscallArgs, errno::Errno};

use crate::msg_layout::{EntryAbi, entry::layout_or_errno};

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }

/// `sendmmsg(fd, mmsghdr*, vlen, flags)` slot 307. # C: O(vlen + message bytes)
pub fn sys_sendmmsg(args: &SyscallArgs) -> i64 {
    // The layout question is asked ONCE, here, before the task, the descriptor
    // or the batch: a native caller that set `MSG_CMSG_COMPAT` gets EINVAL, and
    // the importer's entry stride and `msg_len` offset come from the typed
    // answer. B1641: this file used to mask the flag off the batch spec AND
    // hand the same flag to a second decoder, so the canonical guard could
    // never fire while a caller still chose the parsed layout.
    let layout = match layout_or_errno(args.a3, EntryAbi::Native) {
        Ok(layout) => layout, Err(e) => return e,
    };
    let task = match sched::live::current() { Some(task) => task, None => return err(Errno::Ebadf) };
    let context = socket::SendContext::new(task);
    let mut importer = crate::send_user::SendBatchIo::new(task, args.a0 as i32, args.a1, layout);
    let spec = socket::BatchSpec { len: args.a2 as u32, flags: args.a3 as u32 };
    match socket::send_batch(&context, spec, &mut importer) {
        Ok(sent) => sent as i64, Err(error) => -(error.errno() as i64),
    }
}
