// 000 read — one syscall, one file (docs/53 §0).
use syscall::{errno::Errno, SyscallArgs};

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static sched::Task> { sched::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static sched::Task> { sched::current() }

/// `sys_read(fd, buf, cnt)` — slot 0. Work fn: `vfs::File::read`.
/// # C: O(cnt) on the underlying inode read.
pub fn sys_read(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let mut cnt = args.a2 as usize;
    let cur = match current_task() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: we are the running task on this CPU; preempt-off; no concurrent fd_table writer.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    if !file.f_mode().contains(vfs::Fmode::READ) { return -(Errno::Ebadf.as_i32() as i64); }
    // fanotify FAN_ACCESS_PERM: blocks until a daemon allows/denies (fast
    // no-op when no perm marks exist). Deny → EACCES.
    if !::fs::inotify::check_access_perm(&file.inode()) { return -(Errno::Eacces.as_i32() as i64); }
    if let Ok(target) = crate::recvmsg::from_file(file.clone()) {
        if cnt == 0 {
            cur.account_read_result(0);
            return 0;
        }
        if !uaccess::access_ok(buf, cnt) { return -(Errno::Efault.as_i32() as i64); }
        cnt = crate::userbuf::clamp_rw_count(cnt);
        let user = crate::recv_user::RecvUser {
            msgp: 0, name: 0, namelen: 0, name_len_ptr: 0, control: 0, controllen: 0,
            iov: alloc::vec![crate::recv_user::IoVec { base: buf, len: cnt }], capacity: cnt,
        };
        let ret = crate::recvmsg::recv(&target, &user, 0);
        cur.account_read_result(ret);
        return ret;
    }
    if cnt == 0 {
        let ret = match file.read(&mut []) { Ok(n) => n as i64, Err(e) => -(e as i64) };
        cur.account_read_result(ret);
        return ret;
    }
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(buf, cnt as u64, 1) { return rv; }
    cnt = crate::userbuf::clamp_rw_count(cnt);
    // SAFETY: range [buf, buf+cnt) validated < USER_VA_END by validate_user_buf_writable; user pages mapped via active CR3; demand-paging resolves not-present pages on first kernel-side write.
    let slice: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, cnt) };
    let ret = match file.read(slice) {
        Ok(n)  => n as i64,
        Err(e) => -(e as i64),
    };
    cur.account_read_result(ret);
    ret
}
