// 296 pwritev / 328 pwritev2 — one syscall, one file (docs/53 §0).
// Positional vectored write: writes at the explicit `off` argument and does
// NOT touch the open file description's `f_pos` (mirror of preadv, slot 295).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::iov::{import_iovec, IovDir};
use crate::rwf::{kiocb_set_rw_flags, pos_from_hilo, preadv_pos, PreadvPos, RwCaps, RwDir,
    RwEffect, UIO_MAXIOV};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }
fn errno_vfs(e: vfs::VfsError) -> i64 { -(e as i64) }

/// `pos_from_hilo` — on a 64-bit kernel the
/// offset is `pos_l` alone and `pos_h` is shifted out. The previous x86_64
/// branch applied the 32-bit COMPAT split, truncating any offset above 4 GiB
/// and OR-ing in whatever the caller left in the unset `pos_h` register — on
/// the WRITE path, that lands the data at a wild offset. # C: O(1)
fn offset_from_args(args: &SyscallArgs) -> i64 { pos_from_hilo(args.a3, args.a4) }

/// `sys_pwritev2(fd, iov, iovcnt, pos_l, pos_h, flags)` — slot 328.
/// `pos == -1` means current-offset (`writev`) semantics; the `RWF_*` word goes
/// through the same `kiocb_set_rw_flags` ladder as the read side.
/// # C: O(iovcnt x iov[i].len)
pub fn sys_pwritev2(args: &SyscallArgs) -> i64 { do_pwritev(args, true) }

/// `sys_pwritev(fd, iov, iovcnt, pos_l, pos_h)` — slot 296. Writes each iovec
/// sequentially starting at `off`; does NOT consume or advance the fd's
/// `f_pos`. Returns the byte count written, or -errno.
/// # C: O(iovcnt x iov[i].len)
pub fn sys_pwritev(args: &SyscallArgs) -> i64 { do_pwritev(args, false) }

/// Shared body: the positional vectored-write ladder, in the reference's order.
///
/// The order is the whole point of this function, and four rungs of it were
/// previously absent or inverted:
///
/// - a negative `pos` is `EINVAL` BEFORE the fd lookup, so a bad fd with a bad
///   offset reports `EINVAL`, not `EBADF`;
/// - a description without `FMODE_PWRITE` (pipe/socket/fifo, `O_PATH`) is
///   `ESPIPE`, and one without `FMODE_WRITE` is `EBADF`, and BOTH precede the
///   iovec import — the pre-fix slot validated the user iovec array first, so
///   `pwritev` on a pipe with a bad pointer reported `EFAULT`, and with
///   `iovcnt == 0` reported success on a read-only fd;
/// - the ENTIRE vector is imported and validated before the first byte moves,
///   so a bad pointer in segment `n` cannot follow a completed write of
///   segments `0..n`;
/// - the `RWF_*` admission runs AFTER the import and after the zero-length
///   short-circuit, so a zero-length `pwritev2` with an unsupported flag bit
///   still returns 0.
/// # C: O(iovcnt + bytes)
fn do_pwritev(args: &SyscallArgs, v2: bool) -> i64 {
    let flags = if v2 { args.a5 } else { 0 };
    match preadv_pos(offset_from_args(args), v2) {
        // `pwritev2(..., -1, ..)` IS `writev`: shared cursor, f_pos advanced.
        PreadvPos::CurrentOffset => current_offset_writev(args, flags),
        PreadvPos::Invalid       => errno(Errno::Einval),
        PreadvPos::At(p)         => positional_pwritev(args, p, flags),
    }
}

/// The positional leg, split out so its locals do not sum with the
/// current-offset leg's on the one stack path that takes only one of them: this
/// is the deepest chain the aarch64 syscall entry can reach, and merging the
/// two legs into one frame pushed it past the stack ceiling.
/// # C: O(iovcnt + bytes)
#[inline(never)]
fn positional_pwritev(args: &SyscallArgs, mut off: u64, flags: u64) -> i64 {
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2;
    let Some(cur) = sched::live::current() else { return errno(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return errno(Errno::Ebadf) };
    let fdt = fdt.clone();
    let Ok(file) = fdt.get(fd) else {
        let r = errno(Errno::Ebadf); cur.account_write_result(r); return r;
    };
    if !file.f_mode().contains(vfs::Fmode::PWRITE) {
        let r = errno(Errno::Espipe); cur.account_write_result(r); return r;
    }
    if !file.f_mode().contains(vfs::Fmode::WRITE) {
        let r = errno(Errno::Ebadf); cur.account_write_result(r); return r;
    }
    if iovcnt > UIO_MAXIOV { let r = errno(Errno::Einval); cur.account_write_result(r); return r; }
    let ranges = match import_iovec(iov, iovcnt, IovDir::Source) {
        Ok(r)  => r,
        Err(e) => { cur.account_write_result(e); return e; }
    };
    if ranges.is_empty() { cur.account_write_result(0); return 0; }
    let eff = match rwf_effect(&file, flags) {
        Ok(e)  => e,
        Err(e) => { cur.account_write_result(e); return e; }
    };
    let want: u64 = ranges.iter().map(|(_, l)| *l as u64).sum();
    if let Err(e) = ::fs::inotify::check_file_area_perm(&file.inode(), true, Some(off), want) {
        let r = errno(e); cur.account_write_result(r); return r;
    }
    let iocb = vfs::WriteIocb { append: eff.append, nowait: eff.nowait, more: false };
    let start = off;
    let mut total: u64 = 0;
    for (base, len) in ranges {
        let pos = crate::write_common::positional_write_pos(&file, off);
        let capped = match crate::write_common::rlimit_fsize_cap(&cur, &file, pos, len, total == 0) {
            Ok(n)                => n,
            Err(e) if total == 0 => { cur.account_write_result(e); return e; }
            Err(_)               => break,
        };
        if capped == 0 { continue; }
        // SAFETY: `import_iovec` proved [base, base+len) readable in the active
        // address space below USER_VA_END; `capped <= len`.
        let buf: &[u8] = unsafe { core::slice::from_raw_parts(base as *const u8, capped) };
        match file.pwrite_iocb(buf, off as i64, iocb) {
            Ok(0)  => break,
            Ok(n)  => {
                total = total.saturating_add(n as u64);
                off   = off.saturating_add(n as u64);
                if n < capped || capped < len { break; }
            }
            // An error surfaces only when nothing has been written yet;
            // otherwise the partial count wins.
            Err(e) => {
                if total == 0 { let r = errno_vfs(e); cur.account_write_result(r); return r; }
                break;
            }
        }
    }
    let ret = total as i64;
    cur.account_write_result(ret);
    if ret > 0 && eff.dsync {
        if let Err(e) = rwf_write_sync(&file, start.saturating_add(total), total,
                                       vfs::SyncMode { dsync: eff.dsync, sync: eff.sync }) {
            return e;
        }
    }
    ret
}

/// `pwritev2(..., pos == -1, flags)` → the cursor-advancing vectored write that
/// slot 20 already implements atomically over `f_pos`. The `RWF_*` word is
/// still validated against the description, and a per-operation
/// `RWF_SYNC`/`RWF_DSYNC` still forces the range durable afterwards — the
/// current-offset form used to drop both. # C: O(iovcnt + bytes)
fn current_offset_writev(args: &SyscallArgs, flags: u64) -> i64 {
    if flags == 0 { return crate::s020_writev::sys_writev(args); }
    let Some(cur) = sched::live::current() else { return errno(Errno::Ebadf) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return errno(Errno::Ebadf) };
    let fdt = fdt.clone();
    let Ok(file) = fdt.get(args.a0 as i32) else { return errno(Errno::Ebadf) };
    let eff = match rwf_effect(&file, flags) { Ok(e) => e, Err(e) => return e };
    let n = crate::s020_writev::sys_writev(args);
    if n <= 0 || !eff.dsync { return n; }
    // The bytes ended at the description's post-write cursor.
    let end = file.pos();
    match rwf_write_sync(&file, end, n as u64, vfs::SyncMode { dsync: eff.dsync, sync: eff.sync }) {
        Ok(())  => n,
        Err(e)  => e,
    }
}

/// `generic_write_sync` for the per-operation `RWF_SYNC`/`RWF_DSYNC` bits.
///
/// Split from the description-level `O_SYNC`/`O_DSYNC` handling, which the
/// write paths already apply on every write: this covers only the case where
/// the OPERATION asked for durability the open description did not. A sync
/// failure replaces the byte count with `-errno` — a synchronous write that
/// could not be made durable did not do what was asked.
/// # C: O(N_dirty in range) + O(journal tx)
fn rwf_write_sync(file: &vfs::File, end_pos: u64, written: u64, extra: vfs::SyncMode)
    -> Result<(), i64>
{
    file.generic_write_sync(end_pos, written as usize, extra).map_err(|e| -(e as i64))
}

/// Run the write-side `kiocb_set_rw_flags` ladder against the description's
/// real capabilities. Returns `Err(-errno)` on rejection. # C: O(1)
fn rwf_effect(file: &vfs::File, flags: u64) -> Result<RwEffect, i64> {
    let caps = RwCaps {
        nowait: file.f_mode().contains(vfs::Fmode::NOWAIT),
        o_append: file.flags().contains(vfs::OpenFlags::O_APPEND),
        inode_append_only: vfs::inode::is_append(file.inode()),
        ..RwCaps::default()
    };
    kiocb_set_rw_flags(flags, RwDir::Write, &caps).map_err(|e| errno(e))
}
