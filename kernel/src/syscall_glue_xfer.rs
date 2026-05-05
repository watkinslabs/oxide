// Bulk fd→fd byte transfer syscalls per `15§5`. Split from
// syscall_glue_fs.rs to keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `sys_sendfile(out_fd, in_fd, offset, count)` — slot 40. Copies
/// up to `count` bytes from `in_fd` into `out_fd` via a small
/// kernel staging buffer. `offset` is currently ignored — reads
/// from the File's current position.
/// # C: O(count)
pub fn kernel_sys_sendfile(args: &SyscallArgs) -> i64 {
    let out_fd = args.a0 as i32;
    let in_fd  = args.a1 as i32;
    let _off   = args.a2;
    let count  = args.a3 as usize;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let in_file  = match fdt.get(in_fd)  { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    let out_file = match fdt.get(out_fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    let mut buf = [0u8; 4096];
    let mut total: usize = 0;
    while total < count {
        let want = (count - total).min(buf.len());
        let n = match in_file.read(&mut buf[..want]) {
            Ok(n) => n, Err(e) => return -(e as i64),
        };
        if n == 0 { break; }
        let mut written = 0;
        while written < n {
            let w = match out_file.write(&buf[written..n]) {
                Ok(w) => w, Err(e) => return -(e as i64),
            };
            if w == 0 { return total as i64; }
            written += w;
        }
        total += n;
    }
    total as i64
}
