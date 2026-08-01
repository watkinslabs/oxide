// 018 pwrite64 — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

use syscall::SyscallArgs;
use syscall::errno::Errno;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_pwrite64(fd, buf, cnt, off)` — slot 18. Mirrors pread64.
/// # C: O(cnt)
pub fn sys_pwrite64(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let mut cnt = args.a2 as usize;
    let off = args.a3;
    if (off as i64) < 0 { return -(Errno::Einval.as_i32() as i64); }
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
    if !file.f_mode().contains(vfs::Fmode::PWRITE) {
        return -(Errno::Espipe.as_i32() as i64);
    }
    if !file.f_mode().contains(vfs::Fmode::WRITE) {
        return -(Errno::Ebadf.as_i32() as i64);
    }
    if cnt != 0 {
        if let Err(rv) = crate::userbuf::validate_user_buf_readable(buf, cnt as u64, 1) { return rv; }
        cnt = crate::userbuf::clamp_rw_count(cnt);
    }
    let pos = crate::write_common::positional_write_pos(&file, off);
    if let Err(e) = ::fs::inotify::check_file_area_perm(&file.inode(), true, Some(pos), cnt as u64) {
        return -(e.as_i32() as i64);
    }
    cnt = match crate::write_common::rlimit_fsize_cap(&cur, &file, pos, cnt, true) {
        Ok(n)  => n,
        Err(e) => return e,
    };
    let empty: [u8; 0] = [];
    let bytes: &[u8] = if cnt == 0 {
        &empty
    } else {
        // SAFETY: range [buf, buf+cnt) validated readable in the caller's AS before CPL=0 dereference.
        unsafe { core::slice::from_raw_parts(buf as *const u8, cnt) }
    };
    // Route through File::pwrite for the full Linux gate chain (negative off →
    // EINVAL, !FMODE_PWRITE → ESPIPE, !FMODE_WRITE → EBADF, mnt_readonly →
    // EROFS, O_APPEND forces i_size), instead of inode().write directly.
    let ret = match file.pwrite(bytes, off as i64) {
        Ok(n) => n as i64,
        Err(e) => crate::namei_common::errno_from_vfs(e),
    };
    cur.account_write_result(ret);
    ret
}
