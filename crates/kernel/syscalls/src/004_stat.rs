// 004 stat — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

use crate::userbuf::validate_user_buf_writable;

/// `sys_stat(path, statbuf)` / `sys_lstat(path, statbuf)` — slots 4/6.
/// Resolves `path` via the dentry path-walk and writes a per-arch struct
/// stat (x86_64 = 144 B, aarch64 asm-generic = 128 B). `follow`
/// distinguishes stat (true) from lstat (false). musl's stat()/lstat()
/// route here on x86_64 (aarch64 musl uses statx).
/// # C: O(path components × dir-lookup)
pub(crate) fn stat_impl(args: &SyscallArgs, follow: bool) -> i64 {
    use vfs::FileType;
    let path_ptr = args.a0;
    let buf      = args.a1;

    #[cfg(target_arch = "x86_64")]
    const STAT_BYTES: u64 = 144;
    #[cfg(target_arch = "aarch64")]
    const STAT_BYTES: u64 = 128;

    // X3: the kernel writes into this buffer in CPL=0 — validate it is
    // user-writable, else a buffer pointing at .rodata #PFs the kernel.
    if let Err(rv) = validate_user_buf_writable(buf, STAT_BYTES, 8) { return rv; }
    // X2/X4/X5: PATH_MAX read; EFAULT(bad ptr) / ENOENT(empty) / ENAMETOOLONG.
    let raw = match crate::namei_common::read_user_path(path_ptr) {
        Ok(s) => s, Err(rv) => return rv,
    };
    let resolved = crate::pathresolve::resolve_cwd(&raw);
    let s = resolved.as_str();
    // THE resolver: the dentry path-walk (crosses mounts, delegates
    // whole-path fs, follows symlinks). stat(2) follows a final symlink;
    // lstat(2) does not (`follow`). X1: preserve ENOTDIR/ELOOP/EACCES.
    let inode = match crate::pathresolve::resolve_result(s, !follow) {
        Ok(i)  => i,
        Err(e) => return crate::namei_common::errno_from_vfs(e),
    };
    let (mode_type, rdev): (u32, u64) = match inode.file_type() {
        FileType::CharDev   => (0o020000, inode.rdev() as u64),
        FileType::BlockDev  => (0o060000, inode.rdev() as u64),
        FileType::Directory => (0o040000, 0),
        FileType::Regular   => (0o100000, 0),
        FileType::Symlink   => (0o120000, 0),
        FileType::Fifo      => (0o010000, 0),
        FileType::Socket    => (0o140000, 0),
    };
    // Real perms/owner/times via the inode (overlay-aware), matching
    // sys_fstat/sys_newfstatat/sys_statx — previously stat()/lstat()
    // wrote only mode/size and left uid/gid/timestamps/blocks zero, so
    // every file reported root:root at epoch 1970.
    let overlay   = vfs::inode_times::get(&inode).unwrap_or_default();
    let mode_perm = inode.perm()
        .or_else(|| if overlay.owner_set && overlay.mode_bits != 0 { Some(overlay.mode_bits) } else { None })
        .unwrap_or_else(|| crate::namei_common::default_perm_for(inode.file_type()));
    let mode = mode_type | mode_perm as u32;
    let uid  = inode.uid().unwrap_or(if overlay.owner_set { overlay.uid } else { 0 });
    let gid  = inode.gid().unwrap_or(if overlay.owner_set { overlay.gid } else { 0 });
    let ino  = inode.ino();
    let size = inode.size() as i64;
    let blocks = (inode.size() + 511) / 512;
    let dev = crate::namei_common::fsid_to_dev(inode.fsid());
    let nlink = inode.nlink();
    let blksize = inode.blksize();
    let (ia, im, ic) = (inode.atime(), inode.mtime(), inode.ctime());
    let at = ia.unwrap_or(overlay.atime_ns);
    let mt = im.unwrap_or(overlay.mtime_ns);
    let ct = ic.unwrap_or(overlay.ctime_ns);
    // SAFETY: buf validated STAT_BYTES writable 8-aligned below USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..STAT_BYTES).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        core::ptr::write_volatile(buf as *mut u64, dev);
        let write_ts = |sec_off: u64, ns: u64| {
            core::ptr::write_volatile((buf + sec_off)     as *mut i64, (ns / 1_000_000_000) as i64);
            core::ptr::write_volatile((buf + sec_off + 8) as *mut i64, (ns % 1_000_000_000) as i64);
        };
        #[cfg(target_arch = "x86_64")] {
            // x86_64: dev@0 ino@8 nlink@16 mode@24 uid@28 gid@32 rdev@40
            // size@48 blksize@56 blocks@64 atime@72 mtime@88 ctime@104.
            core::ptr::write_volatile((buf +   8) as *mut u64, ino);
            core::ptr::write_volatile((buf +  16) as *mut u64, nlink as u64);
            core::ptr::write_volatile((buf +  24) as *mut u32, mode);
            core::ptr::write_volatile((buf +  28) as *mut u32, uid);
            core::ptr::write_volatile((buf +  32) as *mut u32, gid);
            core::ptr::write_volatile((buf +  40) as *mut u64, rdev);
            core::ptr::write_volatile((buf +  48) as *mut i64, size);
            core::ptr::write_volatile((buf +  56) as *mut i64, blksize as i64);
            core::ptr::write_volatile((buf +  64) as *mut i64, blocks as i64);
            write_ts(72, at);
            write_ts(88, mt);
            write_ts(104, ct);
        }
        #[cfg(target_arch = "aarch64")] {
            // asm-generic: dev@0 ino@8 mode@16 nlink@20 uid@24 gid@28 rdev@32
            // size@48 blksize@56 blocks@64 atime@72 mtime@88 ctime@104.
            core::ptr::write_volatile((buf +   8) as *mut u64, ino);
            core::ptr::write_volatile((buf +  16) as *mut u32, mode);
            core::ptr::write_volatile((buf +  20) as *mut u32, nlink);
            core::ptr::write_volatile((buf +  24) as *mut u32, uid);
            core::ptr::write_volatile((buf +  28) as *mut u32, gid);
            core::ptr::write_volatile((buf +  32) as *mut u64, rdev);
            core::ptr::write_volatile((buf +  48) as *mut i64, size);
            core::ptr::write_volatile((buf +  56) as *mut i32, blksize as i32);
            core::ptr::write_volatile((buf +  64) as *mut i64, blocks as i64);
            write_ts(72, at);
            write_ts(88, mt);
            write_ts(104, ct);
        }
    }
    0
}

/// `sys_stat(path, statbuf)` — slot 4. Follows a final symlink.
/// # C: O(path components × dir-lookup)
pub fn sys_stat(args: &SyscallArgs) -> i64 { stat_impl(args, true) }
