// 004 stat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::userbuf::validate_user_buf;

/// `sys_stat(path, statbuf)` / `sys_lstat(path, statbuf)` — slots 4/6.
/// Resolves `path` via the dentry path-walk and writes a 144-byte stat
/// struct (same shape as sys_fstat). `follow` distinguishes stat (true)
/// from lstat (false). musl's stat()/lstat() route here, not statx.
/// # C: O(path components × dir-lookup)
pub(crate) fn stat_impl(args: &SyscallArgs, follow: bool) -> i64 {
    let path_ptr = args.a0;
    let buf      = args.a1;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if let Err(rv) = validate_user_buf(buf, 144, 8) { return rv; }
    // SAFETY: path_ptr in user range; user page mapped (caller's AS); bounded read.
    let path = match unsafe { devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let raw = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = crate::pathresolve::resolve_cwd(raw);
    let s = resolved.as_str();
    // THE resolver: the dentry path-walk (crosses mounts, delegates
    // whole-path fs, follows symlinks). stat(2) follows a final symlink;
    // lstat(2) does not (`follow`).
    let inode = match crate::pathresolve::resolve(s, !follow) {
        Some(i) => i,
        None    => return -(Errno::Enoent.as_i32() as i64),
    };
    let (ino_num, file_type, size) = (inode.ino(), inode.file_type(), inode.size());
    let (mode_type, rdev): (u32, u64) = match file_type {
        vfs::FileType::CharDev   => (0o020000, 0x0103),
        vfs::FileType::BlockDev  => (0o060000, 0),
        vfs::FileType::Directory => (0o040000, 0),
        vfs::FileType::Regular   => (0o100000, 0),
        vfs::FileType::Symlink   => (0o120000, 0),
        vfs::FileType::Fifo      => (0o010000, 0),
        vfs::FileType::Socket    => (0o140000, 0),
    };
    let mode = mode_type | 0o755;
    // SAFETY: buf validated 144-byte 8-aligned range below USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..144u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        core::ptr::write_volatile((buf +   8)     as *mut u64, ino_num);
        core::ptr::write_volatile((buf +  16)     as *mut u64, 1);
        core::ptr::write_volatile((buf +  24)     as *mut u32, mode);
        core::ptr::write_volatile((buf +  40)     as *mut u64, rdev);
        core::ptr::write_volatile((buf +  48)     as *mut i64, size as i64);
        core::ptr::write_volatile((buf +  56)     as *mut i64, 4096);
    }
    0
}

/// `sys_stat(path, statbuf)` — slot 4. Follows a final symlink.
/// # C: O(path components × dir-lookup)
pub fn sys_stat(args: &SyscallArgs) -> i64 { stat_impl(args, true) }
