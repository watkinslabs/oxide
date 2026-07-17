// 307 sendmmsg - lazy ABI importer for socket work-layer batching.
#![cfg(target_os = "oxide-kernel")]

use syscall::{SyscallArgs, errno::Errno};

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }

/// `sendmmsg(fd, mmsghdr*, vlen, flags)` slot 307. # C: O(vlen + message bytes)
pub fn sys_sendmmsg(args: &SyscallArgs) -> i64 {
    let task = match sched::live::current() { Some(task) => task, None => return err(Errno::Ebadf) };
    let context = socket::SendContext::new(task);
    let compat = args.a3 & net::uapi::MSG_CMSG_COMPAT != 0;
    let mut importer = if compat {
        crate::send_user::SendBatchIo::new_compat(task, args.a0 as i32, args.a1)
    } else { crate::send_user::SendBatchIo::new(task, args.a0 as i32, args.a1) };
    let spec = socket::BatchSpec { len: args.a2 as u32,
        flags: (args.a3 & !net::uapi::MSG_CMSG_COMPAT) as u32 };
    match socket::send_batch(&context, spec, &mut importer) {
        Ok(sent) => sent as i64, Err(error) => -(error.errno() as i64),
    }
}
