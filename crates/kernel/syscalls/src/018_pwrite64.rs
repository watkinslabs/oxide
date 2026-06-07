// 018 pwrite64 — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;

/// `sys_pwrite64(fd, buf, cnt, off)` — slot 18. Mirrors pread64.
/// # C: O(cnt)
pub fn sys_pwrite64(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2;
    let off = args.a3;
    if cnt == 0 { return 0; }
    if let Err(rv) = validate_user_buf(buf, cnt, 1) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: range [buf, buf+cnt) validated < USER_VA_END; user pages mapped via active CR3; CPL=0 reads through user mapping.
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(buf as *const u8, cnt as usize)
    };
    match file.inode().write(off, bytes) {
        Ok(n) => n as i64,
        Err(e) => -(e as i64),
    }
}
