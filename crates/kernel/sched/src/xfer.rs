// Bulk fd→fd byte transfer syscalls per `15§5`. Split from
// syscall_glue_fs.rs to keep that file under the 1000-line cap.


use syscall::SyscallArgs;
use syscall::errno::Errno;

const MAX_RW_COUNT: usize = 0x7ffff000;
const XFER_BUFFER_BYTES: usize = hal::PAGE_SIZE_BYTES as usize;

#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static crate::Task> { crate::live::current() }

#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static crate::Task> { crate::current() }

/// `get_user(pos, offset)`. The copy carries the exception-table fixups; a
/// bare range check leaves an unmapped `loff_t *` faulting the kernel.
/// # C: O(1)
fn load_off(offp: u64) -> Result<i64, Errno> {
    let mut raw = [0u8; 8];
    uaccess::copy_from_user(&mut raw, offp)?;
    Ok(i64::from_ne_bytes(raw))
}

/// `put_user(pos, offset)`. Linux reports EFAULT from the write-back even
/// when the transfer itself moved bytes, so the stored value replaces `ret`.
/// # C: O(1)
fn store_off(offp: u64, v: i64, ret: i64) -> i64 {
    match uaccess::copy_to_user(offp, &v.to_ne_bytes()) {
        Ok(()) => ret,
        Err(e) => -(e.as_i32() as i64),
    }
}

fn account_sendfile(cur: &crate::Task, ret: i64) {
    cur.account_read_result(ret);
    cur.account_write_result(ret);
}

/// `sys_sendfile(out_fd, in_fd, offset, count)` — slot 40. Copies
/// up to `count` bytes from `in_fd` into `out_fd` via a small kernel staging
/// buffer. A non-NULL offset is Linux `sendfile64`: read the caller's `loff_t`,
/// require input `FMODE_PREAD`, copy from that position without changing
/// `in_fd->f_pos`, then write back the advanced offset.
/// # C: O(count)
pub fn sys_sendfile(args: &SyscallArgs) -> i64 {
    let out_fd = args.a0 as i32;
    let in_fd  = args.a1 as i32;
    let offp   = args.a2;
    let count  = core::cmp::min(args.a3 as usize, MAX_RW_COUNT);
    let cur = match current_task() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let in_file  = match fdt.get(in_fd)  { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    let out_file = match fdt.get(out_fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    if !in_file.f_mode().contains(vfs::Fmode::READ) {
        return -(Errno::Ebadf.as_i32() as i64);
    }
    if !out_file.f_mode().contains(vfs::Fmode::WRITE) {
        return -(Errno::Ebadf.as_i32() as i64);
    }
    let explicit_off = offp != 0;
    let seekable_in = in_file.f_mode().contains(vfs::Fmode::PREAD);
    let positional_in = explicit_off || seekable_in;
    let mut pos = if seekable_in { in_file.pos() as i64 } else { 0 };
    if explicit_off {
        pos = match load_off(offp) { Ok(v) => v, Err(e) => return -(e.as_i32() as i64) };
        if !in_file.f_mode().contains(vfs::Fmode::PREAD) {
            // Linux's put_user runs after do_sendfile even on its errors.
            return store_off(offp, pos, -(Errno::Espipe.as_i32() as i64));
        }
    }
    let mut buf = [0u8; XFER_BUFFER_BYTES];
    let mut total: usize = 0;
    while total < count {
        let want = (count - total).min(buf.len());
        let n = match if positional_in { in_file.pread(&mut buf[..want], pos) } else { in_file.read(&mut buf[..want]) } {
            Ok(n)                => n,
            Err(e) if total == 0 => {
                let ret = -(e as i64);
                account_sendfile(cur, ret);
                return if explicit_off { store_off(offp, pos, ret) } else { ret };
            }
            Err(_)               => break,
        };
        if n == 0 { break; }
        let mut written = 0;
        while written < n {
            let w = match out_file.write(&buf[written..n]) {
                Ok(w)                => w,
                Err(e) if total == 0 && written == 0 => {
                    let ret = -(e as i64);
                    account_sendfile(cur, ret);
                    return if explicit_off { store_off(offp, pos, ret) } else { ret };
                }
                Err(_)               => {
                    let ret = (total + written) as i64;
                    if !explicit_off && positional_in { in_file.set_pos((pos + written as i64) as u64); }
                    account_sendfile(cur, ret);
                    return if explicit_off { store_off(offp, pos + written as i64, ret) } else { ret };
                }
            };
            if w == 0 {
                let ret = (total + written) as i64;
                if !explicit_off && positional_in { in_file.set_pos((pos + written as i64) as u64); }
                account_sendfile(cur, ret);
                return if explicit_off { store_off(offp, pos + written as i64, ret) } else { ret };
            }
            written += w;
        }
        if positional_in { pos += n as i64; }
        total += n;
    }
    let ret = total as i64;
    if !explicit_off && positional_in { in_file.set_pos(pos as u64); }
    account_sendfile(cur, ret);
    if explicit_off { store_off(offp, pos, ret) } else { ret }
}

// `splice`/`tee`/`vmsplice`/`copy_file_range` used to live here as a bare
// kernel read+write loop with no pipe involvement at all. They moved to
// `fs::splice` (F754): the transfer rules are defined over the PIPE RING —
// non-consuming duplication for `tee`, the EOF-vs-EAGAIN distinction, the
// "at least one end must be a pipe" EINVAL — and `sched` sits below `fs`, so
// it cannot reach that ring. `sendfile` stays: it is a file-to-file transfer
// that needs no pipe.
