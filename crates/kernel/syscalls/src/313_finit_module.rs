// 313 finit_module — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

/// `finit_module(fd, params, flags)` slot 313. Reads the file
/// content via the fd then delegates to load_blob. v1 caps file
/// size at 16 MiB.
/// # C: O(file size)
pub fn sys_finit_module(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let mut buf = alloc::vec::Vec::new();
    let mut chunk = [0u8; 4096];
    let mut off = 0u64;
    loop {
        match file.inode().read(off, &mut chunk) {
            Ok(0) => break,
            Ok(n) => { buf.extend_from_slice(&chunk[..n]); off += n as u64; }
            Err(_) => return -(Errno::Eio.as_i32() as i64),
        }
        if buf.len() > 16 * 1024 * 1024 { return -(Errno::E2big.as_i32() as i64); }
    }
    match modules::registry::load_blob(&buf) {
        Some(_) => 0,
        None    => -(Errno::Einval.as_i32() as i64),
    }
}
