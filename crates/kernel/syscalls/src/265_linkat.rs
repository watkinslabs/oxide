// 265 linkat — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{read_path, resolve, is_ext4_path, errno_from_vfs};

/// `linkat(odir, target, ndir, link, flags)` slot 265. Supports
/// `AT_EMPTY_PATH` (flag bit 0x1000): when set and `target` is the
/// empty string, the source is the fd in `odir`, not a path. This
/// is how O_TMPFILE inodes get a name after creation.
/// # C: O(1)
pub fn sys_linkat(args: &SyscallArgs) -> i64 {
    const AT_EMPTY_PATH: u64 = 0x1000;
    let odir_fd  = args.a0 as i32;
    let target_p = args.a1;
    let link_p   = args.a3;
    let flags    = args.a4;

    let link = match read_path(link_p) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let l = resolve(&link).unwrap_or(link);
    if let Err(rv) = crate::landlock::check(&l,
        ::security::landlock::access::MAKE_REG) { return rv; }
    if !is_ext4_path(&l) { return -(Errno::Erofs.as_i32() as i64); }

    if (flags & AT_EMPTY_PATH) != 0 {
        // target must be empty (NULL ptr or "").
        let target_empty = if target_p == 0 {
            true
        } else {
            // SAFETY: target_p in user range (we don't deref past 256B); user page mapped under caller's AS on the syscall path; bounded read.
            let bytes = unsafe { devfs::read_user_cstr(target_p, 256) };
            matches!(bytes, Some(b) if b.is_empty())
        };
        if !target_empty { return -(Errno::Einval.as_i32() as i64); }
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let file = match fdt.get(odir_fd) {
            Ok(f)  => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
        };
        let vfs_ino = file.inode().ino();
        // Only ext4-resident inodes (high-half marker = 0x6E54) can
        // be linked into the ext4 dir tree.
        if (vfs_ino >> 32) != 0x6E54 {
            return -(Errno::Exdev.as_i32() as i64);
        }
        let ino = (vfs_ino & 0xFFFF_FFFF) as u32;
        return match ext4::rootfs::link_inode_at(ino, l.as_bytes()) {
            Ok(())  => 0,
            Err(e)  => errno_from_vfs(e),
        };
    }

    // Classic path→path linkat.
    let target = match read_path(target_p) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let t = resolve(&target).unwrap_or(target);
    if !is_ext4_path(&t) { return -(Errno::Erofs.as_i32() as i64); }
    match ext4::rootfs::link_at(t.as_bytes(), l.as_bytes()) {
        Ok(())  => 0,
        Err(e)  => errno_from_vfs(e),
    }
}
