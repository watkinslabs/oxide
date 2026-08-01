// 296 pwritev / 328 pwritev2 — one syscall, one file (docs/53 §0).
// Positional vectored write: writes at the explicit `off` argument and does
// NOT touch the open file description's `f_pos` (mirror of preadv, slot 295).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::rwf::{kiocb_set_rw_flags, pos_from_hilo, preadv_pos, PreadvPos, RwCaps, RwDir};
use crate::userbuf::validate_user_buf;

/// `pos_from_hilo` (`fs/read_write.c:1115-1119`) — on a 64-bit kernel the
/// offset is `pos_l` alone and `pos_h` is shifted out. The previous x86_64
/// branch applied the 32-bit COMPAT split, truncating any offset above 4 GiB
/// and OR-ing in whatever the caller left in the unset `pos_h` register — on
/// the WRITE path, that lands the data at a wild offset. # C: O(1)
fn offset_from_args(args: &SyscallArgs) -> i64 { pos_from_hilo(args.a3, args.a4) }

/// `sys_pwritev2(fd, iov, iovcnt, pos_l, pos_h, flags)` — slot 328.
/// `pos == -1` means current-offset (`writev`) semantics
/// (`fs/read_write.c:1209`); the `RWF_*` word goes through the same
/// `kiocb_set_rw_flags` ladder as the read side.
/// # C: O(iovcnt x iov[i].len)
pub fn sys_pwritev2(args: &SyscallArgs) -> i64 {
    let pos = offset_from_args(args);
    let cur_off = preadv_pos(pos, true) == PreadvPos::CurrentOffset;
    let eff = match validate_rwf(args.a0 as i32, args.a5) {
        Ok(e)  => e,
        Err(e) => return e,
    };
    // `kiocb_set_rw_flags` folded `RWF_SYNC`/`RWF_DSYNC` into `IOCB_SYNC`/
    // `IOCB_DSYNC`; Linux then acts on them in `generic_write_sync` at the tail
    // of the write (`include/linux/fs.h:2665-2670`). Previously the effect was
    // computed and dropped on the floor, so `pwritev2(..., RWF_SYNC)` behaved
    // exactly like `pwritev`.
    let extra = vfs::SyncMode { dsync: eff.dsync, sync: eff.sync };
    let start = if cur_off { u64::MAX } else { pos as u64 };
    let n = if cur_off { crate::s020_writev::sys_writev(args) } else { sys_pwritev(args) };
    if n <= 0 || !extra.dsync { return n; }
    rwf_write_sync(args.a0 as i32, start, n as u64, extra)
        .map_or_else(|e| e, |()| n)
}

/// `generic_write_sync` for the per-operation `RWF_SYNC`/`RWF_DSYNC` bits.
///
/// Split from the description-level `O_SYNC`/`O_DSYNC` handling, which
/// `vfs::File`'s write paths already apply on every write: this covers only the
/// case where the OPERATION asked for durability that the open description did
/// not. `start == u64::MAX` marks the current-offset (`writev`) form, where the
/// bytes ended at the fd's post-write `f_pos`.
///
/// A sync failure replaces the byte count with `-errno`, per Linux — a
/// synchronous write that could not be made durable did not do what was asked.
/// # C: O(N_dirty in range) + O(journal tx)
fn rwf_write_sync(fd: i32, start: u64, written: u64, extra: vfs::SyncMode) -> Result<(), i64> {
    let Some(cur) = sched::live::current() else { return Err(-(Errno::Ebadf.as_i32() as i64)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(-(Errno::Ebadf.as_i32() as i64)) };
    let fdt = fdt.clone();
    let Ok(file) = fdt.get(fd) else { return Err(-(Errno::Ebadf.as_i32() as i64)) };
    let end_pos = if start == u64::MAX { file.pos() } else { start.saturating_add(written) };
    file.generic_write_sync(end_pos, written as usize, extra)
        .map_err(|e| -(e as i64))
}

/// Run the write-side `kiocb_set_rw_flags` ladder against the description's
/// real capabilities. Returns `Err(-errno)` on rejection. # C: O(1)
fn validate_rwf(fd: i32, flags: u64) -> Result<crate::rwf::RwEffect, i64> {
    if flags == 0 { return Ok(crate::rwf::RwEffect::default()); }
    let Some(cur) = sched::live::current() else { return Err(-(Errno::Ebadf.as_i32() as i64)) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let Some(fdt) = (unsafe { cur.fd_table_ref() }) else { return Err(-(Errno::Ebadf.as_i32() as i64)) };
    let fdt = fdt.clone();
    let Ok(file) = fdt.get(fd) else { return Err(-(Errno::Ebadf.as_i32() as i64)) };
    let caps = RwCaps {
        nowait: file.f_mode().contains(vfs::Fmode::NOWAIT),
        o_append: file.flags().contains(vfs::OpenFlags::O_APPEND),
        inode_append_only: vfs::inode::is_append(file.inode()),
        ..RwCaps::default()
    };
    kiocb_set_rw_flags(flags, RwDir::Write, &caps)
        .map_err(|e| -(e.as_i32() as i64))
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
    let pos = offset_from_args(args);
    if pos < 0 { return -(Errno::Einval.as_i32() as i64); }
    let mut off = pos as u64;
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
    if let Err(e) = ::fs::inotify::check_file_area_perm(&file.inode(), true, Some(off), 0) {
        return -(e.as_i32() as i64);
    }
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
