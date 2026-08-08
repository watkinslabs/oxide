// 295 preadv / 327 preadv2 — one syscall, one file (docs/53 §0). ABI shim:
// the flag/offset RULES live in `crate::rwf` (hosted-tested); the I/O itself is
// `vfs::File::pread` / `pread_nowait`, so every FMODE gate applies.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::iov::{import_iovec, IovDir};
use crate::rwf::{kiocb_set_rw_flags, pos_from_hilo, preadv_pos, PreadvPos, RwCaps, RwDir,
    UIO_MAXIOV};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// `sys_preadv2(fd, iov, iovcnt, pos_l, pos_h, flags)` — slot 327.
/// `pos == -1` is the documented escape to current-offset (`readv`) semantics
/// ; every other negative offset is `EINVAL`.
/// # C: O(iovcnt + sum(iov[i].len))
pub fn sys_preadv2(args: &SyscallArgs) -> i64 { do_preadv(args, true) }

/// `sys_preadv(fd, iov, iovcnt, pos_l, pos_h)` — slot 295. Positional read that
/// neither consumes nor advances the description's `f_pos`.
/// # C: O(iovcnt + sum(iov[i].len))
pub fn sys_preadv(args: &SyscallArgs) -> i64 { do_preadv(args, false) }

/// Shared body of `do_preadv` plus the
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
    // `vfs_readv`: FMODE_READ → EBADF.
    if !file.f_mode().contains(vfs::Fmode::READ) {
        let r = errno(Errno::Ebadf); cur.account_read_result(r); return r;
    }
    // `import_iovec`: `nr_segs > UIO_MAXIOV` → EINVAL; `nr_segs == 0` is a
    // legal zero-length op returning 0.
    if iovcnt > UIO_MAXIOV { let r = errno(Errno::Einval); cur.account_read_result(r); return r; }
    let ranges = match import_iovec(iov, iovcnt, IovDir::Dest) {
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
        // SAFETY: `import_iovec` proved [base, base+len) is a writable
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
///: the cursor-advancing vectored read, which slot 19
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
