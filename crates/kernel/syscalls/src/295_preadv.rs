// 295 preadv / 327 preadv2 — one syscall, one file (docs/53 §0). ABI shim:
// the flag/offset RULES live in `crate::rwf` (hosted-tested); the I/O itself is
// `vfs::File::pread` / `pread_nowait`, so every FMODE gate applies.

#![cfg(target_os = "oxide-kernel")]

use alloc::vec::Vec;
use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::rwf::{kiocb_set_rw_flags, pos_from_hilo, preadv_pos, PreadvPos, RwCaps, RwDir,
    MAX_RW_COUNT, UIO_MAXIOV};
use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_preadv2(fd, iov, iovcnt, pos_l, pos_h, flags)` — slot 327.
/// `pos == -1` is the documented escape to current-offset (`readv`) semantics
/// (`fs/read_write.c:1189`); every other negative offset is `EINVAL`.
/// # C: O(iovcnt + sum(iov[i].len))
pub fn sys_preadv2(args: &SyscallArgs) -> i64 { do_preadv(args, true) }

/// `sys_preadv(fd, iov, iovcnt, pos_l, pos_h)` — slot 295. Positional read that
/// neither consumes nor advances the description's `f_pos`.
/// # C: O(iovcnt + sum(iov[i].len))
pub fn sys_preadv(args: &SyscallArgs) -> i64 { do_preadv(args, false) }

/// Shared body of `do_preadv` (`fs/read_write.c:1121-1140`) plus the
/// `preadv2` `pos == -1` escape. Ladder order is Linux's:
/// `pos` sign check BEFORE the fd lookup, then `EBADF`, then `ESPIPE` for a
/// description without `FMODE_PREAD`, then `vfs_readv`'s `FMODE_READ` gate and
/// iovec import, and only then the `RWF_*` admission (`kiocb_set_rw_flags` runs
/// inside `do_iter_readv_writev`, after the import). # C: O(iovcnt + bytes)
fn do_preadv(args: &SyscallArgs, v2: bool) -> i64 {
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2;
    let flags  = if v2 { args.a5 } else { 0 };
    let pos = pos_from_hilo(args.a3, args.a4);
    let mut off = match preadv_pos(pos, v2) {
        // `preadv2(..., -1, ..)` IS `readv`: shared cursor, f_pos advanced.
        PreadvPos::CurrentOffset => return current_offset_readv(args, flags),
        PreadvPos::Invalid       => return errno(Errno::Einval),
        PreadvPos::At(p)         => p,
    };
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return errno(Errno::Ebadf),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return errno(Errno::Ebadf),
    };
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => { let r = errno(Errno::Ebadf); cur.account_read_result(r); return r; }
    };
    // `do_preadv`: `ret = -ESPIPE; if (f_mode & FMODE_PREAD) ret = vfs_readv(..)`.
    // A pipe/socket/FIFO or O_PATH fd stops here — the pre-fix slot read the
    // inode directly and would happily drain a pipe.
    if !file.f_mode().contains(vfs::Fmode::PREAD) {
        let r = errno(Errno::Espipe); cur.account_read_result(r); return r;
    }
    // `vfs_readv`: FMODE_READ → EBADF (`fs/read_write.c:1000-1001`).
    if !file.f_mode().contains(vfs::Fmode::READ) {
        let r = errno(Errno::Ebadf); cur.account_read_result(r); return r;
    }
    // `import_iovec`: `nr_segs > UIO_MAXIOV` → EINVAL; `nr_segs == 0` is a
    // legal zero-length op returning 0 (`lib/iov_iter.c:1316-1319`).
    if iovcnt > UIO_MAXIOV { let r = errno(Errno::Einval); cur.account_read_result(r); return r; }
    let ranges = match import_iov_writable(iov, iovcnt) {
        Ok(r)  => r,
        Err(e) => { cur.account_read_result(e); return e; }
    };
    // `if (!tot_len) goto out;` returns 0 BEFORE the flag admission, so a
    // zero-length preadv2 with an unsupported RWF bit still returns 0.
    if ranges.is_empty() { cur.account_read_result(0); return 0; }
    let want: u64 = ranges.iter().map(|(_, l)| *l as u64).sum();
    if let Err(e) = ::fs::inotify::check_file_area_perm(&file.inode(), false, Some(off), want) {
        let r = errno(e); cur.account_read_result(r); return r;
    }
    let caps = RwCaps {
        nowait: file.f_mode().contains(vfs::Fmode::NOWAIT),
        o_append: file.flags().contains(vfs::OpenFlags::O_APPEND),
        inode_append_only: vfs::inode::is_append(file.inode()),
        ..RwCaps::default()
    };
    let eff = match kiocb_set_rw_flags(flags, RwDir::Read, &caps) {
        Ok(e)  => e,
        Err(e) => { let r = errno(e); cur.account_read_result(r); return r; }
    };
    let mut total: u64 = 0;
    for (base, len) in ranges {
        // SAFETY: `import_iov_writable` proved [base, base+len) is a writable
        // user range below USER_VA_END in the active address space.
        let buf: &mut [u8] = unsafe { core::slice::from_raw_parts_mut(base as *mut u8, len) };
        let r = if eff.nowait { file.pread_nowait(buf, off as i64) } else { file.pread(buf, off as i64) };
        match r {
            Ok(0)                => break,                     // EOF
            Ok(n)                => {
                total = total.saturating_add(n as u64);
                off   = off.saturating_add(n as u64);
                if n < len { break; }                          // short fill ends the walk
            }
            // Linux `do_loop_readv_writev`: an error surfaces only when nothing
            // has been transferred yet; otherwise the partial count wins.
            Err(e) if total == 0 => { let r = errno_vfs(e); cur.account_read_result(r); return r; }
            Err(_)               => break,
        }
    }
    let ret = total as i64;
    cur.account_read_result(ret);
    ret
}

fn errno_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }

/// `preadv2(..., pos == -1, flags)` → `do_readv(fd, vec, vlen, flags)`
/// (`fs/read_write.c:1190`): the cursor-advancing vectored read, which slot 19
/// already implements atomically over `f_pos`. The RWF word is still validated
/// against the description before handing off. # C: O(iovcnt + bytes)
fn current_offset_readv(args: &SyscallArgs, flags: u64) -> i64 {
    if flags != 0 {
        let Some(cur) = sched::live::current() else { return errno(Errno::Ebadf) };
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
        let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return errno(Errno::Ebadf) };
        let fdt = fdt.clone();
        let Ok(file) = fdt.get(args.a0 as i32) else { return errno(Errno::Ebadf) };
        let caps = RwCaps {
            nowait: file.f_mode().contains(vfs::Fmode::NOWAIT),
            o_append: file.flags().contains(vfs::OpenFlags::O_APPEND),
            inode_append_only: vfs::inode::is_append(file.inode()),
            ..RwCaps::default()
        };
        if let Err(e) = kiocb_set_rw_flags(flags, RwDir::Read, &caps) { return errno(e); }
    }
    crate::s019_readv::sys_readv(args)
}

/// `import_iovec(ITER_DEST, ...)` for a writable destination vector: validates
/// the array itself, then each segment, applying the two Linux rules that the
/// pre-fix slot skipped — a segment whose length is negative as `ssize_t` is
/// `EINVAL` (`lib/iov_iter.c:1288-1290`), and the running total is TRUNCATED at
/// `MAX_RW_COUNT` rather than rejected (`lib/iov_iter.c:1389-1404`).
/// Zero-length segments are dropped. # C: O(iovcnt)
fn import_iov_writable(iov: u64, iovcnt: u64) -> Result<Vec<(u64, usize)>, i64> {
    let mut out: Vec<(u64, usize)> = Vec::new();
    if iovcnt == 0 { return Ok(out); }
    let array_bytes = iovcnt.checked_mul(16).ok_or(errno(Errno::Efault))?;
    validate_user_buf(iov, array_bytes, 8)?;
    let mut total: u64 = 0;
    for i in 0..iovcnt {
        let iov_i = iov + i * 16;
        // SAFETY: the whole iovec array was validated readable above; `iov_i`
        // is inside it and 8-byte aligned per the Linux `struct iovec` ABI.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: same validated array; `iov_len` sits at +8 within the entry.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if (len as i64) < 0 { return Err(errno(Errno::Einval)); }
        if len == 0 { continue; }
        validate_user_buf_writable(base, len, 1)?;
        let room = MAX_RW_COUNT.saturating_sub(total);
        if room == 0 { break; }
        let capped = len.min(room);
        total += capped;
        out.push((base, capped as usize));
    }
    Ok(out)
}
