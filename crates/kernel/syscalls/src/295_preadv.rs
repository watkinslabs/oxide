// 295 preadv — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

#[cfg(target_arch = "x86_64")]
fn offset_from_args(args: &SyscallArgs) -> u64 {
    (args.a3 & 0xffff_ffff) | ((args.a4 & 0xffff_ffff) << 32)
}

#[cfg(target_arch = "aarch64")]
fn offset_from_args(args: &SyscallArgs) -> u64 { args.a3 }

/// RWF_* flags accepted by preadv2/pwritev2 (uapi `linux/fs.h`). HIPRI/DSYNC/
/// SYNC/NOWAIT have no effect on the synchronous in-kernel backends (never
/// block, always durable); RWF_APPEND is meaningful only on the write path.
pub(crate) const RWF_SUPPORTED: u64 = 0x1f; // HIPRI|DSYNC|SYNC|NOWAIT|APPEND

/// `sys_preadv2(fd, iov, iovcnt, pos_l, pos_h, flags)` — slot 286. Validates
/// the RWF_* `flags` word (Linux `kiocb_set_rw_flags`: an unsupported bit →
/// EOPNOTSUPP) the plain `preadv` handler silently dropped, then reads (D54).
/// # C: O(iovcnt x iov[i].len)
pub fn sys_preadv2(args: &SyscallArgs) -> i64 {
    if args.a5 & !RWF_SUPPORTED != 0 { return -(Errno::Eopnotsupp.as_i32() as i64); }
    sys_preadv(args)
}

/// `sys_preadv(fd, iov, iovcnt, off)` — slot 295. Positional read:
/// does not consume or depend on the open file description's `f_pos`.
/// `preadv2` currently shares this implementation and accepts flags as
/// a no-op, matching the existing syscall table's conservative support.
/// # C: O(iovcnt x iov[i].len)
pub fn sys_preadv(args: &SyscallArgs) -> i64 {
    const IOV_MAX: u64 = 1024;
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2;
    let mut off = offset_from_args(args);
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
        if let Err(rv) = validate_user_buf_writable(base, len, 1) { return rv; }
        // SAFETY: range validated < USER_VA_END; CPL=0 writes through caller's AS.
        let buf: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(base as *mut u8, len as usize)
        };
        match file.inode().read(off, buf) {
            Ok(0)  => break,
            Ok(n)  => {
                total = total.saturating_add(n as u64);
                off = off.saturating_add(n as u64);
                if (n as u64) < len { break; }
            }
            Err(e) => return -(e as i64),
        }
    }
    total as i64
}
