// sys_newfstatat — split out of `fs.rs` for the 1000-line cap.
//
// Per-arch struct stat: x86_64 = 144 B, aarch64 asm-generic = 128 B.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;

const AT_EMPTY_PATH: u32       = 0x1000;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_NO_AUTOMOUNT: u32     = 0x800;
const AT_VALID: u32 = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT;

/// `sys_newfstatat(dirfd, path, statbuf, flags)` — x86_64 slot 262.
/// Previously this was routed to sys_statx, which mis-reads args
/// (statx's a2=flags is newfstatat's a2=statbuf) and corrupted
/// userspace memory; the shell's PATH search on ARM printed
/// "Permission denied" for every probe.
/// # C: O(1)
pub fn sys_newfstatat(args: &SyscallArgs) -> i64 {
    let dirfd    = args.a0 as i32;
    let path_ptr = args.a1;
    let buf      = args.a2;
    let flags    = args.a3 as u32;

    #[cfg(target_arch = "x86_64")]
    const STAT_BYTES: u64 = 144;
    #[cfg(target_arch = "aarch64")]
    const STAT_BYTES: u64 = 128;

    // Unknown flag bits → EINVAL (Linux vfs_fstatat).
    if flags & !AT_VALID != 0 { return -(Errno::Einval.as_i32() as i64); }
    // X3: kernel writes into buf in CPL=0 — require it user-writable. Linux
    // copy_to_user does not require the caller's struct stat pointer to be
    // naturally aligned, so only validate the byte range.
    if let Err(rv) = validate_user_buf_writable(buf, STAT_BYTES, 1) { return rv; }

    // Centralized `*at` resolution: AT_EMPTY_PATH → LOOKUP_EMPTY (empty/NULL
    // path operates on the dirfd, ENOENT without it); a normal stat FOLLOWS the
    // trailing symlink (LOOKUP_FOLLOW), AT_SYMLINK_NOFOLLOW does not. The engine
    // preserves ENOTDIR/ELOOP/EACCES/EFAULT/ENAMETOOLONG (X1/X2/X4/X5).
    let nofollow = (flags & AT_SYMLINK_NOFOLLOW) != 0;
    let lf = vfs::LookupFlags {
        empty: (flags & AT_EMPTY_PATH) != 0,
        no_follow_final: nofollow,
        follow: !nofollow,
        ..Default::default()
    };
    let (inode, mnt_id) = match crate::pathresolve::resolve_at_lookup(dirfd, path_ptr, lf) {
        Ok(p)  => (p.inode, p.mnt_id),
        Err(rv) => return rv,
    };

    // vfs_getattr → i_op->getattr: S_IF* mapping + overlay merge + idmap-out.
    let idmap = vfs::mount::idmap_for(mnt_id);
    let st = vfs::vfs_getattr(&inode, &idmap, vfs::inode_times::get(&inode));
    let mode = st.mode;
    let rdev = st.rdev as u64;
    let uid  = st.uid;
    let gid  = st.gid;
    let ino  = st.ino;
    let size = st.size as i64;
    let blocks = st.blocks;
    let dev = crate::namei_common::fsid_to_dev(st.fsid);
    let nlink = st.nlink;
    let blksize = st.blksize;
    let at = st.atime_ns;
    let mt = st.mtime_ns;
    let ct = st.ctime_ns;

    // SAFETY: buf validated STAT_BYTES writable below USER_VA_END; unaligned
    // stores match Linux copy_to_user semantics for user-provided buffers.
    unsafe {
        for off in (0..STAT_BYTES).step_by(8) {
            core::ptr::write_unaligned((buf + off) as *mut u64, 0);
        }
        // st_dev@0 — distinct per filesystem (both arch layouts have dev@0).
        core::ptr::write_unaligned(buf as *mut u64, dev);
        let write_ts = |sec_off: u64, ns: u64| {
            core::ptr::write_unaligned((buf + sec_off)     as *mut i64, (ns / 1_000_000_000) as i64);
            core::ptr::write_unaligned((buf + sec_off + 8) as *mut i64, (ns % 1_000_000_000) as i64);
        };
        #[cfg(target_arch = "x86_64")] {
            // x86_64 struct stat (144 B): dev@0 ino@8 nlink@16 mode@24
            // uid@28 gid@32 rdev@40 size@48 blksize@56 blocks@64
            // atime@72 mtime@88 ctime@104.
            core::ptr::write_unaligned((buf +   8)     as *mut u64, ino);
            core::ptr::write_unaligned((buf +  16)     as *mut u64, nlink as u64);
            core::ptr::write_unaligned((buf +  24)     as *mut u32, mode);
            core::ptr::write_unaligned((buf +  28)     as *mut u32, uid);
            core::ptr::write_unaligned((buf +  32)     as *mut u32, gid);
            core::ptr::write_unaligned((buf +  40)     as *mut u64, rdev);
            core::ptr::write_unaligned((buf +  48)     as *mut i64, size);
            core::ptr::write_unaligned((buf +  56)     as *mut i64, blksize as i64);
            core::ptr::write_unaligned((buf +  64)     as *mut i64, blocks as i64);
            write_ts(72, at);
            write_ts(88, mt);
            write_ts(104, ct);
        }
        #[cfg(target_arch = "aarch64")] {
            // asm-generic struct stat (128 B): ino@8 mode@16 nlink@20
            // uid@24 gid@28 rdev@32 size@48 blksize@56 blocks@64
            // atime@72 mtime@88 ctime@104.
            core::ptr::write_unaligned((buf +   8)     as *mut u64, ino);
            core::ptr::write_unaligned((buf +  16)     as *mut u32, mode);
            core::ptr::write_unaligned((buf +  20)     as *mut u32, nlink);
            core::ptr::write_unaligned((buf +  24)     as *mut u32, uid);
            core::ptr::write_unaligned((buf +  28)     as *mut u32, gid);
            core::ptr::write_unaligned((buf +  32)     as *mut u64, rdev);
            core::ptr::write_unaligned((buf +  48)     as *mut i64, size);
            core::ptr::write_unaligned((buf +  56)     as *mut i32, blksize as i32);
            core::ptr::write_unaligned((buf +  64)     as *mut i64, blocks as i64);
            write_ts(72, at);
            write_ts(88, mt);
            write_ts(104, ct);
        }
    }
    0
}
