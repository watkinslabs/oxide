// 332 statx — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;

const AT_EMPTY_PATH: u32       = 0x1000;
const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
const AT_NO_AUTOMOUNT: u32     = 0x800;
const AT_STATX_SYNC_TYPE: u32  = 0x6000; // FORCE_SYNC|DONT_SYNC
const AT_VALID: u32 = AT_EMPTY_PATH | AT_SYMLINK_NOFOLLOW | AT_NO_AUTOMOUNT | AT_STATX_SYNC_TYPE;
const STATX_RESERVED: u32 = 0x8000_0000;

/// `sys_statx(dirfd, path, flags, mask, statxbuf)` — slot 332.
/// # C: O(1)
pub fn sys_statx(args: &SyscallArgs) -> i64 {
    let dirfd     = args.a0 as i32;
    let path_ptr  = args.a1;
    let flags     = args.a2 as u32;
    let mask      = args.a3 as u32;
    let buf       = args.a4;
    // Unknown flag bits / reserved mask bit → EINVAL (Linux do_statx).
    if flags & !AT_VALID != 0 { return -(Errno::Einval.as_i32() as i64); }
    if mask & STATX_RESERVED != 0 { return -(Errno::Einval.as_i32() as i64); }
    // X3: kernel writes into buf in CPL=0 — require it user-writable. Linux
    // copy_to_user accepts unaligned user statx buffers, so only validate the
    // byte range here.
    if let Err(rv) = validate_user_buf_writable(buf, 256, 1) { return rv; }

    // Probe path emptiness (path may be NULL with AT_EMPTY_PATH).
    let empty_or_null = path_ptr == 0 || {
        // SAFETY: path_ptr in user range guarded; 1-byte probe only.
        path_ptr < hal::USER_VA_END
            && unsafe { devfs::read_user_cstr(path_ptr, 1) }.map_or(true, |b| b.is_empty())
    };

    let (inode, mnt_id) = if (flags & AT_EMPTY_PATH) != 0 && empty_or_null {
        let cur = match sched::live::current() {
            Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
        };
        // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
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
        // Resolve relative path against the dirfd's directory (real `*at`
        // semantics, same as openat). aarch64 musl routes stat()/lstat()
        // here.
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

    // vfs_getattr → i_op->getattr (default generic_fillattr): S_IF* mapping +
    // inode_times overlay merge + idmap-out owner ids (identity ⇒ raw ids).
    let idmap = vfs::mount::idmap_for(mnt_id);
    let st = vfs::vfs_getattr(&inode, &idmap, vfs::inode_times::get(&inode));
    let mode = st.mode as u16;
    let rdev = st.rdev;
    let stx_uid = st.uid;
    let stx_gid = st.gid;
    let dev = crate::namei_common::fsid_to_dev(st.fsid);
    // statx layout per linux/stat.h. Zero everything then fill the fields we have.
    // SAFETY: buf validated 256-byte writable range below USER_VA_END;
    // unaligned stores match Linux copy_to_user semantics.
    unsafe {
        for off in (0..256u64).step_by(8) {
            core::ptr::write_unaligned((buf + off) as *mut u64, 0);
        }
        // stx_mask = STATX_BASIC_STATS — tell the caller all base
        // fields (type/mode/nlink/uid/gid/atime/mtime/ctime/ino/size/
        // blocks) are valid. Pre-fix mask omitted NLINK/UID/GID/SIZE,
        // which broke ARM musl's stat() wrapper: it returned a struct
        // stat with st_uid/st_gid/st_size synthesised from the
        // unmasked fields, and the shell's perm check rejected the
        // file as \"not executable for caller\" → \"Permission denied\".
        const STATX_BASIC_STATS: u32 = 0x7ff;
        core::ptr::write_unaligned(buf as *mut u32, STATX_BASIC_STATS);
        core::ptr::write_unaligned((buf +   4)     as *mut u32, st.blksize);                          // stx_blksize
        core::ptr::write_unaligned((buf +  16)     as *mut u32, st.nlink);                            // stx_nlink
        core::ptr::write_unaligned((buf +  20)     as *mut u32, stx_uid);                             // stx_uid
        core::ptr::write_unaligned((buf +  24)     as *mut u32, stx_gid);                             // stx_gid
        core::ptr::write_unaligned((buf +  28)     as *mut u16, mode);                                // stx_mode
        core::ptr::write_unaligned((buf +  32)     as *mut u64, st.ino);                              // stx_ino
        core::ptr::write_unaligned((buf +  40)     as *mut u64, st.size);                             // stx_size
        core::ptr::write_unaligned((buf +  48)     as *mut u64, st.blocks);                           // stx_blocks (512-byte units)
        // Timestamp slots: each 16 B = (i64 sec, i32 nsec, i32 reserved).
        // Linux statx layout: atime@72, btime@88, ctime@104, mtime@120.
        let write_ts = |off: u64, ns: u64| {
            let sec  = (ns / 1_000_000_000) as i64;
            let nsec = (ns % 1_000_000_000) as i32;
            core::ptr::write_unaligned((buf + off)      as *mut i64, sec);
            core::ptr::write_unaligned((buf + off + 8)  as *mut i32, nsec);
        };
        write_ts(72,  st.atime_ns);
        write_ts(104, st.ctime_ns);
        write_ts(120, st.mtime_ns);
        core::ptr::write_unaligned((buf + 128)     as *mut u32, (rdev >> 8)  & 0xfff);                // stx_rdev_major
        core::ptr::write_unaligned((buf + 132)     as *mut u32,  rdev        & 0xff);                 // stx_rdev_minor
        core::ptr::write_unaligned((buf + 136)     as *mut u32, crate::namei_common::dev_major(dev)); // stx_dev_major
        core::ptr::write_unaligned((buf + 140)     as *mut u32, crate::namei_common::dev_minor(dev)); // stx_dev_minor
    }
    0
}
