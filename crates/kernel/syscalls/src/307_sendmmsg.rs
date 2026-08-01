// 307 sendmmsg - lazy ABI importer for socket work-layer batching.
#![cfg(target_os = "oxide-kernel")]

use syscall::{SyscallArgs, errno::Errno};

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }

/// `sendmmsg(fd, mmsghdr*, vlen, flags)` slot 307. # C: O(vlen + message bytes)
pub fn sys_sendmmsg(args: &SyscallArgs) -> i64 {
    // The native entry never speaks the compat message layout: the flag is
    // rejected before the task, the descriptor, or the batch is touched, by
    // the same batch owner that screens it for every other caller. Masking it
    // off here would both hide the error and pick a foreign header layout.
    if args.a3 & net::uapi::MSG_CMSG_COMPAT != 0 { return err(Errno::Einval); }
    let task = match sched::live::current() { Some(task) => task, None => return err(Errno::Ebadf) };
    let context = socket::SendContext::new(task);
    let mut importer = crate::send_user::SendBatchIo::new(task, args.a0 as i32, args.a1);
    let spec = socket::BatchSpec { len: args.a2 as u32, flags: args.a3 as u32 };
    match socket::send_batch(&context, spec, &mut importer) {
        Ok(sent) => sent as i64, Err(error) => -(error.errno() as i64),
    }
}
