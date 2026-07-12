// 296 pwritev / 328 pwritev2 — one syscall, one file (docs/53 §0).
// Positional vectored write: writes at the explicit `off` argument and does
// NOT touch the open file description's `f_pos` (mirror of preadv, slot 295).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;

#[cfg(target_arch = "x86_64")]
fn offset_from_args(args: &SyscallArgs) -> u64 {
    (args.a3 & 0xffff_ffff) | ((args.a4 & 0xffff_ffff) << 32)
}

#[cfg(target_arch = "aarch64")]
fn offset_from_args(args: &SyscallArgs) -> u64 { args.a3 }

/// `sys_pwritev2(fd, iov, iovcnt, pos_l, pos_h, flags)` — slot 328. Validates
/// the RWF_* `flags` word (Linux `kiocb_set_rw_flags`: an unsupported bit →
/// EOPNOTSUPP), then writes positionally.
/// # C: O(iovcnt x iov[i].len)
pub fn sys_pwritev2(args: &SyscallArgs) -> i64 {
    if args.a5 & !crate::s295_preadv::RWF_SUPPORTED != 0 {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    sys_pwritev(args)
}

/// `sys_pwritev(fd, iov, iovcnt, pos_l, pos_h)` — slot 296. Writes each iovec
/// sequentially starting at `off`; does NOT consume or advance the fd's
/// `f_pos` (Linux `vfs_writev` with an explicit ppos). Returns the byte count
/// written, or -errno.
/// # C: O(iovcnt x iov[i].len)
pub fn sys_pwritev(args: &SyscallArgs) -> i64 {
    const IOV_MAX: u64 = 1024;
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2;
    let mut off = offset_from_args(args);
    if (off as i64) < 0 { return -(Errno::Einval.as_i32() as i64); }
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
    if iovcnt == 0 { return 0; }
    if iovcnt > IOV_MAX { return -(Errno::Einval.as_i32() as i64); }
    let array_bytes = match iovcnt.checked_mul(16) {
        Some(v) => v,
        None    => return -(Errno::Efault.as_i32() as i64),
    };
    if let Err(rv) = validate_user_buf(iov, array_bytes, 8) { return rv; }
    let mut total: u64 = 0;
    for i in 0..iovcnt {
        let iov_i = iov + i * 16;
        // SAFETY: iov array validated above; iov_i in range; 8-byte aligned per Linux ABI.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: same validated range; iov_len at offset +8 is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        // Source buffer is READ from the caller's AS (validate readable).
        if let Err(rv) = validate_user_buf(base, len, 1) { return rv; }
        let pos = crate::write_common::positional_write_pos(&file, off);
        let capped = match crate::write_common::rlimit_fsize_cap(&cur, &file, pos, len as usize, total == 0) {
            Ok(n)                 => n,
            Err(e) if total == 0  => return e,
            Err(_)                => break,
        };
        if capped == 0 { continue; }
        // SAFETY: range validated < USER_VA_END; CPL=0 reads through caller's AS.
        let buf: &[u8] = unsafe {
            core::slice::from_raw_parts(base as *const u8, capped)
        };
        match file.pwrite(buf, off as i64) {
            Ok(0)  => break,
            Ok(n)  => {
                total = total.saturating_add(n as u64);
                off   = off.saturating_add(n as u64);
                if n < capped || capped < len as usize { break; }
            }
            // Match Linux: surface the error only if nothing was written yet;
            // otherwise return the short count already written.
            Err(e) => { if total == 0 { return -(e as i64); } break; }
        }
    }
    total as i64
}
