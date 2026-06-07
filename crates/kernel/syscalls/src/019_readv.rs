// 019 readv — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;

/// `sys_readv(fd, iov, iovcnt)` — slot 19. Mirror of writev for
/// reads. Each iov buffer gets one call into `File::read`; a
/// short read terminates the loop early per Linux semantics.
/// # C: O(iovcnt × iov[i].len)
pub fn sys_readv(args: &SyscallArgs) -> i64 {
    const IOV_MAX: u64 = 1024;
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2;
    if iovcnt == 0 { return 0; }
    if iovcnt > IOV_MAX { return -(Errno::Einval.as_i32() as i64); }
    let array_bytes = match iovcnt.checked_mul(16) {
        Some(v) => v,
        None    => return -(Errno::Efault.as_i32() as i64),
    };
    if let Err(rv) = validate_user_buf(iov, array_bytes, 8) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let mut total: u64 = 0;
    for i in 0..iovcnt {
        let iov_i = iov + i * 16;
        // SAFETY: iov array validated above; iov_i in range; 8-byte aligned per Linux ABI.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: same validated range; iov_len at offset +8 is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        if let Err(rv) = validate_user_buf(base, len, 1) { return rv; }
        // SAFETY: range validated < USER_VA_END; CPL=0 writes through caller's AS.
        let buf: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(base as *mut u8, len as usize)
        };
        match file.read(buf) {
            Ok(0)  => break,
            Ok(n)  => {
                total = total.saturating_add(n as u64);
                if (n as u64) < len { break; }
            }
            Err(e) => return -(e as i64),
        }
    }
    total as i64
}
