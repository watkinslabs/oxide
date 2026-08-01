// 019 readv — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

use alloc::vec::Vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;
use crate::userbuf::validate_user_buf_writable;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_readv(fd, iov, iovcnt)` — slot 19. Imports the Linux `iovec` array,
/// applies `UIO_MAXIOV`/`MAX_RW_COUNT`, then dispatches one vectored VFS read so
/// the open-file cursor advances atomically across the whole request.
/// # C: O(iovcnt + sum(iov[i].len))
pub fn sys_readv(args: &SyscallArgs) -> i64 {
    const IOV_MAX: u64 = 1024;
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2;
    let cur = match current_task() {
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
        Err(_) => {
            let ret = -(Errno::Ebadf.as_i32() as i64);
            cur.account_read_result(ret);
            return ret;
        }
    };
    if !file.f_mode().contains(vfs::Fmode::READ) {
        let ret = -(Errno::Ebadf.as_i32() as i64);
        cur.account_read_result(ret);
        return ret;
    }
    if iovcnt == 0 {
        let ret = 0;
        cur.account_read_result(ret);
        return ret;
    }
    // fanotify content gates. A vectored read is ONE access at the
    // description's cursor: the iovecs are where the bytes land, not which
    // bytes are read.
    if let Err(e) = ::fs::inotify::check_file_area_perm(&file.inode(), false, Some(file.pos()), 0) {
        let ret = -(e.as_i32() as i64);
        cur.account_read_result(ret);
        return ret;
    }
    if iovcnt > IOV_MAX {
        let ret = -(Errno::Einval.as_i32() as i64);
        cur.account_read_result(ret);
        return ret;
    }
    if let Ok(target) = crate::recvmsg::from_file(file.clone()) {
        let user = match crate::recv_user::import_iov(iov, iovcnt as usize) {
            Ok(user) => user,
            Err(e) => { cur.account_read_result(e); return e; }
        };
        let ret = crate::recvmsg::recv(&target, &user, 0);
        cur.account_read_result(ret);
        return ret;
    }
    let array_bytes = match iovcnt.checked_mul(16) {
        Some(v) => v,
        None    => {
            let ret = -(Errno::Efault.as_i32() as i64);
            cur.account_read_result(ret);
            return ret;
        }
    };
    if let Err(rv) = validate_user_buf(iov, array_bytes, 8) {
        cur.account_read_result(rv);
        return rv;
    }
    let mut ranges: Vec<(u64, usize)> = Vec::new();
    let mut imported_total = 0usize;
    for i in 0..iovcnt {
        let iov_i = iov + i * 16;
        // SAFETY: iov array validated above; iov_i in range; 8-byte aligned per Linux ABI.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: same validated range; iov_len at offset +8 is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        if let Err(rv) = validate_user_buf_writable(base, len, 1) {
            cur.account_read_result(rv);
            return rv;
        }
        let remaining = crate::userbuf::MAX_RW_COUNT.saturating_sub(imported_total);
        if remaining == 0 { break; }
        let capped = core::cmp::min(len as usize, remaining);
        imported_total = imported_total.saturating_add(capped);
        if capped != 0 {
            ranges.push((base, capped));
        }
    }
    let mut bufs: Vec<&mut [u8]> = Vec::new();
    for (base, len) in ranges {
        // SAFETY: range validated < USER_VA_END; CPL=0 writes through caller's AS.
        let buf: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(base as *mut u8, len)
        };
        bufs.push(buf);
    }
    let ret = match file.read_iter(&mut bufs) {
        Ok(n)  => n as i64,
        Err(e) => -(e as i64),
    };
    cur.account_read_result(ret);
    ret
}
