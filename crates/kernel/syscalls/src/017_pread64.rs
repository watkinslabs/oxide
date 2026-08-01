// 017 pread64 — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

use syscall::SyscallArgs;
use syscall::errno::Errno;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_pread64(fd, buf, cnt, off)` — slot 17.
/// # C: O(cnt)
pub fn sys_pread64(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let mut cnt = args.a2 as usize;
    let off = args.a3 as i64;
    if off < 0 { return -(Errno::Einval.as_i32() as i64); }
    let cur = match current_task() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    if !file.f_mode().contains(vfs::Fmode::PREAD) {
        return -(Errno::Espipe.as_i32() as i64);
    }
    if !file.f_mode().contains(vfs::Fmode::READ) {
        return -(Errno::Ebadf.as_i32() as i64);
    }
    if let Err(e) = ::fs::inotify::check_file_area_perm(&file.inode(), false, Some(off as u64), cnt as u64) {
        return -(e.as_i32() as i64);
    }
    if cnt == 0 {
        let mut empty: [u8; 0] = [];
        let ret = match file.pread(&mut empty, off) {
            Ok(n)  => n as i64,
            Err(e) => crate::namei_common::errno_from_vfs(e),
        };
        cur.account_read_result(ret);
        return ret;
    }
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf, cnt as u64, 1) { return rv; }
    cnt = crate::userbuf::clamp_rw_count(cnt);
    // SAFETY: range [buf, buf+cnt) validated < USER_VA_END; user pages mapped via active CR3 (caller's AS); CPL=0 writes through user mapping.
    let user_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut u8, cnt)
    };
    // Route through File::pread so the full Linux gate chain applies (negative
    // off → EINVAL, non-seekable !FMODE_PREAD → ESPIPE, !FMODE_READ → EBADF),
    // instead of calling inode().read directly and bypassing it.
    let ret = match file.pread(user_buf, off) {
        Ok(n) => n as i64,
        Err(e) => crate::namei_common::errno_from_vfs(e),
    };
    cur.account_read_result(ret);
    ret
}
