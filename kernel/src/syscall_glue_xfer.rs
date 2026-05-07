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

/// `sys_copy_file_range(in_fd, in_off, out_fd, out_off, len, flags)`
/// — slot 326. Same staging-buffer copy as sendfile, with explicit
/// in/out offsets honored when non-NULL. Linux semantics: on success
/// the offsets are advanced by the byte count copied.
/// # C: O(len)
pub fn kernel_sys_copy_file_range(args: &SyscallArgs) -> i64 {
    let in_fd   = args.a0 as i32;
    let in_off  = args.a1;
    let out_fd  = args.a2 as i32;
    let out_off = args.a3;
    let len     = args.a4 as usize;
    let _flags  = args.a5;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let in_file  = match fdt.get(in_fd)  { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    let out_file = match fdt.get(out_fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    // Pre-seek if explicit offsets supplied. The File trait's seek
    // path mirrors lseek; we land at the requested position before
    // the read/write loop.
    if in_off != 0 && in_off < hal::USER_VA_END {
        // SAFETY: in_off validated < USER_VA_END; CPL=0 reads through caller's AS.
        let off = unsafe { core::ptr::read_volatile(in_off as *const i64) };
        let _ = in_file.seek(vfs::SeekFrom::Start, off);
    }
    if out_off != 0 && out_off < hal::USER_VA_END {
        // SAFETY: out_off validated < USER_VA_END; CPL=0 reads through caller's AS.
        let off = unsafe { core::ptr::read_volatile(out_off as *const i64) };
        let _ = out_file.seek(vfs::SeekFrom::Start, off);
    }
    let mut buf = [0u8; 4096];
    let mut total: usize = 0;
    while total < len {
        let want = (len - total).min(buf.len());
        let n = match in_file.read(&mut buf[..want]) {
            Ok(n) => n, Err(e) => return if total > 0 { total as i64 } else { -(e as i64) },
        };
        if n == 0 { break; }
        let mut written = 0;
        while written < n {
            let w = match out_file.write(&buf[written..n]) {
                Ok(w) => w, Err(e) => return if total + written > 0 { (total + written) as i64 } else { -(e as i64) },
            };
            if w == 0 { return (total + written) as i64; }
            written += w;
        }
        total += n;
    }
    // Update user-supplied offset slots with the new positions.
    if in_off != 0 && in_off < hal::USER_VA_END {
        // SAFETY: in_off validated < USER_VA_END; CPL=0 writes.
        unsafe { core::ptr::write_volatile(in_off as *mut i64, in_file.pos() as i64); }
    }
    if out_off != 0 && out_off < hal::USER_VA_END {
        unsafe { core::ptr::write_volatile(out_off as *mut i64, out_file.pos() as i64); }
    }
    total as i64
}
