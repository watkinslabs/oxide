// 138 fstatfs — one syscall, one file (docs/53 §0).

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;
use crate::statfs_common::{statfs_for_magic, statfs_for_sb_at_mount, write_statfs, STATFS_BYTES};

/// `sys_fstatfs(fd, buf)` — slot 138. Linux `fstatfs` is
/// `vfs_statfs(&f->f_path)`: the accounting comes from the open file's OWN
/// superblock (`f_path.dentry->d_sb->s_op->statfs`) and `f_flags` from its
/// vfsmount. An anonymous descriptor family that belongs to no superblock falls
/// back to the pseudo-fs shape (magic only, zero accounting).
/// # C: O(N_mounts)
pub fn sys_fstatfs(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    if let Err(rv) = validate_user_buf_writable(buf, STATFS_BYTES as u64, 1) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    // The SUPERBLOCK is the source of truth for the accounting — reading only
    // `Inode::statfs_magic()` would collapse every path-backed file onto a
    // magic-and-zeros row, losing the backend's real `f_blocks`/`f_bfree` and
    // the mount's `ST_*` flags. The mount is consulted only for `f_flags`
    // (Linux `calculate_f_flags`), and its absence must not cost the accounting.
    let mnt_flags = vfs::mount::mount_by_id(file.mnt_id()).map(|m| m.flags()).unwrap_or(0);
    let st = match file.inode().i_sb() {
        Some(sb) => statfs_for_sb_at_mount(&sb, mnt_flags),
        None => statfs_for_magic(match file.inode().statfs_magic() {
            0 => crate::statfs_common::M_TMPFS,
            magic => magic,
        }),
    };
    write_statfs(buf, &st);
    0
}
