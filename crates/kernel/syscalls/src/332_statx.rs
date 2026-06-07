// 332 statx — one syscall, one file (docs/53 §0). Moved verbatim from fs.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::userbuf::validate_user_buf;

/// `sys_statx(dirfd, path, flags, mask, statxbuf)` — slot 332.
/// # C: O(1)
pub fn sys_statx(args: &SyscallArgs) -> i64 {
    use vfs::FileType;
    const AT_EMPTY_PATH: u32 = 0x1000;
    let dirfd     = args.a0 as i32;
    let path_ptr  = args.a1;
    let flags     = args.a2 as u32;
    let _mask     = args.a3 as u32;
    let buf       = args.a4;
    if let Err(rv) = validate_user_buf(buf, 256, 8) { return rv; }

    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); bounded read.
    let path_opt = unsafe { devfs::read_user_cstr(path_ptr, 256) };
    const AT_FDCWD: i32 = -100;
    let inode = match path_opt {
        Some(p) if !p.is_empty() => {
            let raw = match core::str::from_utf8(p) {
                Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
            };
            // Resolve relative path against cwd (statx semantics for AT_FDCWD).
            // Absolute paths must also be lexically normalised so trailing
            // slashes (`/proc/self/fd/`) and `.`/`..` collapse to the
            // registered devfs key.
            // BUG D: route through resolve_at so a real fd-relative dirfd
            // resolves against the dirfd's directory (statx(dirfd, name) from
            // `ls`/`find`), not cwd. resolve_at handles absolute / AT_FDCWD /
            // real dirfd; the old `else { raw.into() }` ignored the dirfd.
            let _ = AT_FDCWD;
            let resolved: alloc::string::String =
                crate::pathresolve::resolve_at(dirfd, raw)
                    .unwrap_or_else(|| crate::pathresolve::resolve_cwd(raw));
            let s = resolved.as_str();
            // THE resolver (path-walk). statx(2) follows symlinks unless
            // AT_SYMLINK_NOFOLLOW. aarch64 musl routes stat()/lstat()
            // here (no legacy stat/lstat syscalls), so this is the arm
            // symlink-follow path.
            const AT_SYMLINK_NOFOLLOW: u32 = 0x100;
            let nofollow = (flags & AT_SYMLINK_NOFOLLOW) != 0;
            match crate::pathresolve::resolve(s, nofollow) {
                Some(i) => i,
                None    => return -(Errno::Enoent.as_i32() as i64),
            }
        }
        _ if (flags & AT_EMPTY_PATH) != 0 => {
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
            f.inode().clone()
        }
        _ => return -(Errno::Einval.as_i32() as i64),
    };

    let (mode_type, rdev): (u16, u32) = match inode.file_type() {
        FileType::CharDev   => (0o020000, 0x0103),
        FileType::BlockDev  => (0o060000, 0),
        FileType::Directory => (0o040000, 0),
        FileType::Regular   => (0o100000, 0),
        FileType::Symlink   => (0o120000, 0),
        FileType::Fifo      => (0o010000, 0),
        FileType::Socket    => (0o140000, 0),
    };
    // F98+F99: Inode trait first via Option<>; overlay fallback per pseudo-fs.
    let overlay = vfs::inode_times::get(&inode).unwrap_or_default();
    let mode_perm = inode.perm()
        .or_else(|| if overlay.owner_set && overlay.mode_bits != 0 { Some(overlay.mode_bits) } else { None })
        .unwrap_or(0o755);
    let mode = mode_type | mode_perm;
    let stx_uid = inode.uid().unwrap_or(if overlay.owner_set { overlay.uid } else { 0 });
    let stx_gid = inode.gid().unwrap_or(if overlay.owner_set { overlay.gid } else { 0 });
    let (ia, im, ic) = (inode.atime(), inode.mtime(), inode.ctime());
    // statx layout per linux/stat.h. Zero everything then fill the fields we have.
    // SAFETY: buf validated 256-byte 8-aligned range below USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..256u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        // stx_mask = STATX_BASIC_STATS — tell the caller all base
        // fields (type/mode/nlink/uid/gid/atime/mtime/ctime/ino/size/
        // blocks) are valid. Pre-fix mask omitted NLINK/UID/GID/SIZE,
        // which broke ARM musl's stat() wrapper: it returned a struct
        // stat with st_uid/st_gid/st_size synthesised from the
        // unmasked fields, and the shell's perm check rejected the
        // file as \"not executable for caller\" → \"Permission denied\".
        const STATX_BASIC_STATS: u32 = 0x7ff;
        core::ptr::write_volatile(buf as *mut u32, STATX_BASIC_STATS);
        core::ptr::write_volatile((buf +   4)     as *mut u32, 4096);                                // stx_blksize
        core::ptr::write_volatile((buf +  16)     as *mut u32, 1);                                   // stx_nlink
        core::ptr::write_volatile((buf +  20)     as *mut u32, stx_uid);                             // stx_uid
        core::ptr::write_volatile((buf +  24)     as *mut u32, stx_gid);                             // stx_gid
        core::ptr::write_volatile((buf +  28)     as *mut u16, mode);                                // stx_mode
        core::ptr::write_volatile((buf +  32)     as *mut u64, inode.ino());                         // stx_ino
        core::ptr::write_volatile((buf +  40)     as *mut u64, inode.size());                        // stx_size
        core::ptr::write_volatile((buf +  48)     as *mut u64, (inode.size() + 511) / 512);          // stx_blocks (512-byte units)
        // Timestamp slots: each 16 B = (i64 sec, i32 nsec, i32 reserved).
        // Linux statx layout: atime@72, btime@88, ctime@104, mtime@120.
        let write_ts = |off: u64, ns: u64| {
            let sec  = (ns / 1_000_000_000) as i64;
            let nsec = (ns % 1_000_000_000) as i32;
            core::ptr::write_volatile((buf + off)      as *mut i64, sec);
            core::ptr::write_volatile((buf + off + 8)  as *mut i32, nsec);
        };
        write_ts(72,  ia.unwrap_or(overlay.atime_ns));
        write_ts(104, ic.unwrap_or(overlay.ctime_ns));
        write_ts(120, im.unwrap_or(overlay.mtime_ns));
        core::ptr::write_volatile((buf + 128)     as *mut u32, (rdev >> 8)  & 0xfff);                // stx_rdev_major
        core::ptr::write_volatile((buf + 132)     as *mut u32,  rdev        & 0xff);                 // stx_rdev_minor
    }
    0
}
