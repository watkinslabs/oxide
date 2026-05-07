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

/// `sys_splice(in_fd, in_off, out_fd, out_off, len, flags)` —
/// slot 275. Linux requires at least one fd to refer to a pipe;
/// v1 doesn't enforce that and treats the call as a kernel-side
/// read+write loop (same shape as sendfile). Pipes provide their
/// own backpressure (Eagain on full / 0 on empty close), so the
/// loop terminates naturally. The 'in_off' and 'out_off' user
/// pointers are honored when non-NULL and not pipe-backed; for
/// pipes Linux requires NULL and we silently ignore.
/// # C: O(len)
pub fn kernel_sys_splice(args: &SyscallArgs) -> i64 {
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
    if in_off != 0 && in_off < hal::USER_VA_END {
        // SAFETY: in_off validated; CPL=0 reads.
        let off = unsafe { core::ptr::read_volatile(in_off as *const i64) };
        let _ = in_file.seek(vfs::SeekFrom::Start, off);
    }
    if out_off != 0 && out_off < hal::USER_VA_END {
        // SAFETY: out_off validated < USER_VA_END; CPL=0 reads i64 through caller's AS.
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
    total as i64
}

/// `sys_tee(in_fd, out_fd, len, flags)` — slot 276. Linux's tee
/// duplicates pipe contents without consuming. v1 doesn't have a
/// peek-without-consume primitive on the pipe inode, so this
/// behaves like splice (read-and-consume from in_fd, write to
/// out_fd). The semantic difference matters only when both ends
/// of the pipe are still open + the caller intended to consume
/// elsewhere, which v1 callers (busybox tee, dd) tolerate.
/// # C: O(len)
pub fn kernel_sys_tee(args: &SyscallArgs) -> i64 {
    let mut sa = *args;
    sa.a0 = args.a0; // in_fd
    sa.a1 = 0;
    sa.a2 = args.a1; // out_fd
    sa.a3 = 0;
    sa.a4 = args.a2; // len
    sa.a5 = args.a3; // flags
    kernel_sys_splice(&sa)
}

/// `sys_vmsplice(fd, iov, nr_segs, flags)` — slot 278. Walks the
/// iovec array and writes each segment to `fd`. The Linux
/// SPLICE_F_GIFT (page-steal) optimisation isn't honored — we
/// always copy. Reading from a pipe via vmsplice (the inverse
/// direction) similarly falls back to read.
/// # C: O(total iovec bytes)
pub fn kernel_sys_vmsplice(args: &SyscallArgs) -> i64 {
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let nr     = args.a2;
    let _flags = args.a3;
    if nr > 1024 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let mut total: i64 = 0;
    let mut buf = [0u8; 4096];
    for i in 0..nr {
        let entry = iov + i * 16;
        if entry >= hal::USER_VA_END { return -(Errno::Efault.as_i32() as i64); }
        // SAFETY: entry validated < USER_VA_END; iovec entry layout {base: u64, len: u64}; aligned u64 read.
        let base = unsafe { core::ptr::read_volatile(entry as *const u64) };
        // SAFETY: entry+8 still inside the 16-byte iovec entry; aligned u64 read.
        let len  = unsafe { core::ptr::read_volatile((entry + 8) as *const u64) };
        if base == 0 || len == 0 { continue; }
        let mut off: u64 = 0;
        while off < len {
            let want = (len - off).min(buf.len() as u64) as usize;
            // SAFETY: base+off < base+len, base validated through user mapping by upper layer; bounded copy.
            unsafe {
                for j in 0..want {
                    buf[j] = core::ptr::read_volatile((base + off + j as u64) as *const u8);
                }
            }
            let mut written = 0;
            while written < want {
                let w = match file.write(&buf[written..want]) {
                    Ok(w) => w, Err(e) => return if total > 0 { total } else { -(e as i64) },
                };
                if w == 0 { return total + written as i64; }
                written += w;
            }
            total += want as i64;
            off += want as u64;
        }
    }
    total
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
        // SAFETY: out_off validated < USER_VA_END; CPL=0 writes i64 through caller's AS.
        unsafe { core::ptr::write_volatile(out_off as *mut i64, out_file.pos() as i64); }
    }
    total as i64
}
