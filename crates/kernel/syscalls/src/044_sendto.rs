// 044 sendto - ABI import and one socket work-layer call.
#![cfg(target_os = "oxide-kernel")]

use syscall::{SyscallArgs, errno::Errno};

fn err(error: Errno) -> i64 { -(error.as_i32() as i64) }

/// `sendto(fd, buf, len, flags, dest, dest_len)` slot 44. # C: O(payload + address)
pub fn sys_sendto(args: &SyscallArgs) -> i64 {
    let len = args.a2 as usize;
    if len != 0 {
        if let Err(error) = crate::userbuf::validate_user_buf_readable(args.a1, args.a2, 1) {
            return error;
        }
    }
    let task = match sched::live::current() { Some(task) => task, None => return err(Errno::Ebadf) };
    let context = socket::SendContext::new(task);
    let mut message = crate::send_user::SendtoIo::new(task, args.a0 as i32, args.a1, len,
        args.a4, args.a5);
    match socket::send_io(&context, args.a3 as u32, &mut message) {
        Ok(outcome) => outcome.bytes as i64, Err(error) => -(error.errno() as i64),
    }
}
