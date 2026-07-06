// 001 write — one syscall, one file (docs/53 §0).
use syscall::{errno::Errno, SyscallArgs};

// DIAG (debug-stderr): echo fd==2 (stderr) writes to the console tagged with the
// writing tid+name. GLib/GTK/mutter log fatal errors via write(2,...) to stderr;
// gdm routes the session's stderr to a pipe/journal, so those death messages
// never reach the serial console. Mirrors `trace_stderr_writev` (020_writev) for
// the plain-write path, giving visibility into why gnome-shell exits code=1.
// Kept lightweight (syscalls-only) so a live-gnome boot reaches the desktop at
// normal speed — unlike debug-atexit which also arms the ld.so DR0 machinery.
#[cfg(feature = "debug-stderr")]
fn trace_stderr_write(fd: i32, bytes: &[u8]) {
    if fd != 2 { return; }
    let n = core::cmp::min(bytes.len(), 512);
    klog::write_raw(b"[STDERR t=");
    if let Some(c) = sched::live::current() {
        klog::write_dec_u64(c.tid as u64);
        klog::write_raw(b" ");
        klog::write_raw(c.name.as_bytes());
    }
    klog::write_raw(b"] ");
    klog::write_raw(&bytes[..n]);
    if n < bytes.len() { klog::write_raw(b"...<truncated>"); }
    if n == 0 || bytes[n - 1] != b'\n' { klog::write_raw(b"\n"); }
}

/// `sys_write(fd, buf, cnt)` — slot 1. Work fn: `vfs::File::write`.
/// # C: O(cnt) on the underlying inode write.
pub fn sys_write(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2 as usize;
    if cnt == 0 { return 0; }
    if let Err(rv) = crate::userbuf::validate_user_buf(buf, cnt as u64, 1) { return rv; }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; no concurrent fd_table writer.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: range [buf, buf+cnt) validated < USER_VA_END by validate_user_buf; CPL=0 reads through caller's AS mapping.
    let slice: &[u8] = unsafe { core::slice::from_raw_parts(buf as *const u8, cnt) };
    #[cfg(feature = "debug-stderr")]
    trace_stderr_write(fd, slice);
    match file.write(slice) {
        Ok(n)  => n as i64,
        Err(e) => {
            if e == vfs::VfsError::Erofs {
                klog::write_raw(b"[WRITE-EROFS] pid=");
                klog::write_dec_u64(cur.tid as u64);
                klog::write_raw(b" name=");
                klog::write_raw(cur.name.as_bytes());
                klog::write_raw(b" fd=");
                klog::write_dec_u64(fd as u64);
                klog::write_raw(b" path=\"");
                let path = file.dentry().absolute_path();
                klog::write_raw(&path);
                klog::write_raw(b"\" ino=");
                klog::write_dec_u64(file.inode().ino());
                klog::write_raw(b" type=");
                klog::write_dec_u64(file.inode().file_type() as u64);
                klog::write_raw(b" cnt=");
                klog::write_dec_u64(cnt as u64);
                klog::write_raw(b"\n");
            }
            -(e as i64)
        },
    }
}
