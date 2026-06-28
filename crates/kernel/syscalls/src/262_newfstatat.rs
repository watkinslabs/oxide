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
    // X3: kernel writes into buf in CPL=0 — require it user-writable.
    if let Err(rv) = validate_user_buf_writable(buf, STAT_BYTES, 8) { return rv; }

    // Probe path emptiness (path may be NULL with AT_EMPTY_PATH; glibc/musl
    // pass ""). Linux allows path=NULL when AT_EMPTY_PATH is set.
    let empty_or_null = path_ptr == 0 || {
        // SAFETY: path_ptr in user range guarded below; 1-byte probe only.
        path_ptr < hal::USER_VA_END
            && unsafe { devfs::read_user_cstr(path_ptr, 1) }.map_or(true, |b| b.is_empty())
    };

    let (inode, mnt_id) = if (flags & AT_EMPTY_PATH) != 0 && empty_or_null {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per 13§5.
        let fdt = match unsafe { cur.fd_table_ref() } {
            Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
        };
        let f = match fdt.get(dirfd) {
            Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
        };
        (f.inode().clone(), f.mnt_id())
    } else {
        // X2/X4/X5: PATH_MAX read with EFAULT/ENOENT/ENAMETOOLONG.
        let raw = match crate::namei_common::read_user_path(path_ptr) {
            Ok(s) => s, Err(rv) => return rv,
        };
        // Resolve the path against the dirfd's directory (real `*at`
        // semantics, same as openat).
        let resolved = match crate::pathresolve::resolve_at_result(dirfd, &raw) {
            Ok(p) => p, Err(rv) => return rv,
        };
        let nofollow = (flags & AT_SYMLINK_NOFOLLOW) != 0;
        // X1: preserve ENOTDIR/ELOOP/EACCES from the path-walk.
        match crate::pathresolve::resolve_path_result(resolved.as_str(), nofollow) {
            Ok(p)  => (p.inode, p.mnt_id),
            Err(e) => return crate::namei_common::errno_from_vfs(e),
        }
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

    // SAFETY: buf validated STAT_BYTES writable below USER_VA_END + 8-aligned; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..STAT_BYTES).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        // st_dev@0 — distinct per filesystem (both arch layouts have dev@0).
        core::ptr::write_volatile(buf as *mut u64, dev);
        let write_ts = |sec_off: u64, ns: u64| {
            core::ptr::write_volatile((buf + sec_off)     as *mut i64, (ns / 1_000_000_000) as i64);
            core::ptr::write_volatile((buf + sec_off + 8) as *mut i64, (ns % 1_000_000_000) as i64);
        };
        #[cfg(target_arch = "x86_64")] {
            // x86_64 struct stat (144 B): dev@0 ino@8 nlink@16 mode@24
            // uid@28 gid@32 rdev@40 size@48 blksize@56 blocks@64
            // atime@72 mtime@88 ctime@104.
            core::ptr::write_volatile((buf +   8)     as *mut u64, ino);
            core::ptr::write_volatile((buf +  16)     as *mut u64, nlink as u64);
            core::ptr::write_volatile((buf +  24)     as *mut u32, mode);
            core::ptr::write_volatile((buf +  28)     as *mut u32, uid);
            core::ptr::write_volatile((buf +  32)     as *mut u32, gid);
            core::ptr::write_volatile((buf +  40)     as *mut u64, rdev);
            core::ptr::write_volatile((buf +  48)     as *mut i64, size);
            core::ptr::write_volatile((buf +  56)     as *mut i64, blksize as i64);
            core::ptr::write_volatile((buf +  64)     as *mut i64, blocks as i64);
            write_ts(72, at);
            write_ts(88, mt);
            write_ts(104, ct);
        }
        #[cfg(target_arch = "aarch64")] {
            // asm-generic struct stat (128 B): ino@8 mode@16 nlink@20
            // uid@24 gid@28 rdev@32 size@48 blksize@56 blocks@64
            // atime@72 mtime@88 ctime@104.
            core::ptr::write_volatile((buf +   8)     as *mut u64, ino);
            core::ptr::write_volatile((buf +  16)     as *mut u32, mode);
            core::ptr::write_volatile((buf +  20)     as *mut u32, nlink);
            core::ptr::write_volatile((buf +  24)     as *mut u32, uid);
            core::ptr::write_volatile((buf +  28)     as *mut u32, gid);
            core::ptr::write_volatile((buf +  32)     as *mut u64, rdev);
            core::ptr::write_volatile((buf +  48)     as *mut i64, size);
            core::ptr::write_volatile((buf +  56)     as *mut i32, blksize as i32);
            core::ptr::write_volatile((buf +  64)     as *mut i64, blocks as i64);
            write_ts(72, at);
            write_ts(88, mt);
            write_ts(104, ct);
        }
    }
    0
}
