// Filesystem-shaped syscalls per docs/15§5 + docs/16, split from syscall_glue.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::syscalls::{validate_user_buf, validate_user_buf_writable};

/// `sys_fstat(fd, statbuf)` — slot 5. 144-byte Linux x86_64 struct stat.
/// # C: O(1)
pub fn sys_fstat(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    if let Err(rv) = validate_user_buf(buf, 144, 8) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot per single-mutator-per-active-CPU invariant in `13§5`.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f)  => f,
        Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = file.inode();
    let (mode_type, rdev): (u32, u64) = match inode.file_type() {
        vfs::FileType::CharDev   => (0o020000, 0x0103),
        vfs::FileType::BlockDev  => (0o060000, 0),
        vfs::FileType::Directory => (0o040000, 0),
        vfs::FileType::Regular   => (0o100000, 0),
        vfs::FileType::Symlink   => (0o120000, 0),
        vfs::FileType::Fifo      => (0o010000, 0),
        vfs::FileType::Socket    => (0o140000, 0),
    };
    let mode: u32 = mode_type | 0o600;
    let ino  = inode.ino();
    let size = inode.size() as i64;
    // SAFETY: buf validated 144-byte range below USER_VA_END + 8-byte aligned; CPL=0 writes through user mapping per the active CR3 = caller's AS.
    unsafe {
        core::ptr::write_volatile( buf            as *mut u64, 0);
        core::ptr::write_volatile((buf +   8)     as *mut u64, ino);
        core::ptr::write_volatile((buf +  16)     as *mut u64, 1);
        core::ptr::write_volatile((buf +  24)     as *mut u32, mode);
        core::ptr::write_volatile((buf +  28)     as *mut u32, 0);
        core::ptr::write_volatile((buf +  32)     as *mut u32, 0);
        core::ptr::write_volatile((buf +  36)     as *mut u32, 0);
        core::ptr::write_volatile((buf +  40)     as *mut u64, rdev);
        core::ptr::write_volatile((buf +  48)     as *mut i64, size);
        core::ptr::write_volatile((buf +  56)     as *mut i64, 4096);
        core::ptr::write_volatile((buf +  64)     as *mut i64, 0);
        for off in (72..144).step_by(8) {
            core::ptr::write_volatile((buf + off as u64) as *mut u64, 0);
        }
    }
    0
}

pub use crate::syscalls::ioctl::sys_ioctl;

/// `sys_getcwd(buf, size)` — slot 79. Reads `current.cwd` slot.
/// Returns the path length including the trailing NUL per
/// `man 2 getcwd`; -ERANGE if `size` is too small.
/// # C: O(N_cwd)
pub fn sys_getcwd(args: &SyscallArgs) -> i64 {
    let buf  = args.a0;
    let size = args.a1;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: cwd slot single-mutator per `13§5`; we are the running task on this CPU and the sole writer.
    let cwd_bytes = unsafe { (*cur.cwd.get()).clone() };
    let cwd = cwd_bytes.as_bytes();
    let need = (cwd.len() + 1) as u64;
    if size < need { return -(Errno::Erange.as_i32() as i64); }
    if let Err(rv) = validate_user_buf_writable(buf, need, 1) { return rv; }
    // SAFETY: buf range validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        for (i, &b) in cwd.iter().enumerate() {
            core::ptr::write_volatile((buf + i as u64) as *mut u8, b);
        }
        core::ptr::write_volatile((buf + cwd.len() as u64) as *mut u8, 0);
    }
    need as i64
}

/// `sys_chdir(path)` — slot 80.
/// # C: O(N_devfs_entries)
pub fn sys_chdir(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's user code already executed from this AS); read bounded at 256 B.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let s = match core::str::from_utf8(path) {
        Ok(s)  => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolves = s == "/" || vfs::mount::lookup(s).is_ok();
    if !resolves { return -(Errno::Enoent.as_i32() as i64); }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: single-mutator per `13§5`; current task is sole writer.
    unsafe { *cur.cwd.get() = alloc::string::String::from(s); }
    0
}

/// `sys_fcntl(fd, cmd, arg)` — slot 72. F_DUPFD / F_GETFD / F_SETFD /
/// F_GETFL / F_SETFL / F_GETPIPE_SZ / F_SETPIPE_SZ / F_GETOWN / F_SETOWN.
/// # C: O(N_fds) for F_DUPFD; O(1) otherwise.
/// `sys_fcntl(fd, cmd, arg)` — slot 72. Tier-3 shim per `docs/53§4`.
/// Multi-command dispatch over vfs::FdTable / vfs::File methods
/// (Tier-2). F_GETPIPE_SZ/F_SETPIPE_SZ return the v1 fixed cap.
/// # C: O(1) per command; O(N_fds) for F_DUPFD.
pub fn sys_fcntl(args: &SyscallArgs) -> i64 {
    const F_DUPFD: u64 = 0; const F_GETFD: u64 = 1; const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3; const F_SETFL: u64 = 4;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_GETPIPE_SZ: u64 = 1032; const F_SETPIPE_SZ: u64 = 1031;
    const F_GETOWN: u64 = 9; const F_SETOWN: u64 = 8;
    const SETTABLE_FL: u32 = 0o4_004_000 | 0o0_004_000; // O_APPEND | O_NONBLOCK
    let fd = args.a0 as i32; let cmd = args.a1; let arg = args.a2;
    let ebadf = -(Errno::Ebadf.as_i32() as i64);
    let cur = match sched::live::current() { Some(c) => c, None => return ebadf };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return ebadf };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return ebadf };
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => match fdt.dup_min(fd, arg as i32) {
            Ok(n) => { if cmd == F_DUPFD_CLOEXEC { let _ = fdt.set_cloexec(n, true); } n as i64 }
            Err(e) => -(e as i64),
        },
        F_GETFD => match fdt.cloexec(fd) { Ok(true) => 1, Ok(false) => 0, Err(_) => 0 },
        F_SETFD => { let _ = fdt.set_cloexec(fd, (arg & 1) != 0); 0 }
        F_GETFL => file.flags().bits() as i64,
        F_SETFL => {
            let nb = (file.flags().bits() & !SETTABLE_FL) | ((arg as u32) & SETTABLE_FL);
            file.set_flags(vfs::OpenFlags::from_bits_retain(nb));
            0
        }
        F_GETPIPE_SZ | F_SETPIPE_SZ => 4096,
        F_GETOWN | F_SETOWN => 0,
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

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
    let path_opt = unsafe { crate::devfs::read_user_cstr(path_ptr, 256) };
    let inode = match path_opt {
        Some(p) if !p.is_empty() => {
            let s = match core::str::from_utf8(p) {
                Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
            };
            match vfs::mount::lookup(s) {
                Ok(i) => i,
                Err(_) => match ext4::rootfs::lookup_inode_any(s.as_bytes()) {
                    Some(i) => i,
                    None    => return -(Errno::Enoent.as_i32() as i64),
                }
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
        const STATX_TYPE:  u32 = 1;
        const STATX_MODE:  u32 = 2;
        const STATX_INO:   u32 = 0x100;
        const STATX_ATIME: u32 = 0x20;
        const STATX_MTIME: u32 = 0x40;
        const STATX_CTIME: u32 = 0x80;
        core::ptr::write_volatile( buf            as *mut u32,
            STATX_TYPE | STATX_MODE | STATX_INO | STATX_ATIME | STATX_MTIME | STATX_CTIME);
        core::ptr::write_volatile((buf +   4)     as *mut u32, 4096);                                // stx_blksize
        core::ptr::write_volatile((buf +  16)     as *mut u32, 1);                                   // stx_nlink
        core::ptr::write_volatile((buf +  20)     as *mut u32, stx_uid);                             // stx_uid
        core::ptr::write_volatile((buf +  24)     as *mut u32, stx_gid);                             // stx_gid
        core::ptr::write_volatile((buf +  28)     as *mut u16, mode);                                // stx_mode
        core::ptr::write_volatile((buf +  32)     as *mut u64, inode.ino());                         // stx_ino
        core::ptr::write_volatile((buf +  40)     as *mut u64, inode.size());                        // stx_size
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

/// `sys_stat(path, statbuf)` / `sys_lstat(path, statbuf)` —
/// slots 4/6. Resolves `path` via devfs, writes a 144-byte
/// stat struct (same shape as sys_fstat).
/// # C: O(N_devfs_entries)
pub fn sys_stat(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let buf      = args.a1;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if let Err(rv) = validate_user_buf(buf, 144, 8) { return rv; }
    // SAFETY: path_ptr in user range; user page mapped (caller's AS); bounded read.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let s = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    // Resolve through pseudo-fs first (devfs/procfs/tmpfs) for shadow
    // mounts, fall back to ext4 stat_path which handles any file type
    // (dirs, symlinks, regular). lookup_inode would reject dirs.
    let (ino_num, file_type, size): (u64, vfs::FileType, u64) =
        if let Ok(i) = vfs::mount::lookup(s) {
            (i.ino(), i.file_type(), i.size())
        } else if let Some((ino, ft, sz)) = ext4::rootfs::stat_path(s.as_bytes()) {
            ((0x6E54_0000u64 | ino as u64), ft, sz)
        } else {
            return -(Errno::Enoent.as_i32() as i64);
        };
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

/// `sys_statfs(path, buf)` / `sys_fstatfs(fd, buf)` — slots
/// 137/138. Writes a 120-byte `struct statfs` describing the
/// devfs root: f_type=0x57AC6E9D (TMPFS_MAGIC stand-in),
/// 4096 block size, no usage tracking.
/// # C: O(1)
pub fn sys_statfs(args: &SyscallArgs) -> i64 {
    // Slot 137 takes (path, buf); slot 138 takes (fd, buf). The
    // user-buf is the second arg in both cases.
    let buf = args.a1;
    if let Err(rv) = validate_user_buf(buf, 120, 8) { return rv; }
    // SAFETY: 120-byte user buf validated < USER_VA_END + 8-aligned; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..120u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        core::ptr::write_volatile( buf            as *mut u64, 0x5774_8958_5780_F4B5); // f_type
        core::ptr::write_volatile((buf +   8)     as *mut u64, 4096);                  // f_bsize
        core::ptr::write_volatile((buf +  88)     as *mut u32, 256);                   // f_namelen
    }
    0
}


/// `sys_pread64(fd, buf, cnt, off)` — slot 17.
/// # C: O(cnt)
pub fn sys_pread64(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2;
    let off = args.a3;
    if cnt == 0 { return 0; }
    if let Err(rv) = validate_user_buf(buf, cnt, 1) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: range [buf, buf+cnt) validated < USER_VA_END; user pages mapped via active CR3 (caller's AS); CPL=0 writes through user mapping.
    let user_buf: &mut [u8] = unsafe {
        core::slice::from_raw_parts_mut(buf as *mut u8, cnt as usize)
    };
    match file.inode().read(off, user_buf) {
        Ok(n) => n as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_pwrite64(fd, buf, cnt, off)` — slot 18. Mirrors pread64.
/// # C: O(cnt)
pub fn sys_pwrite64(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2;
    let off = args.a3;
    if cnt == 0 { return 0; }
    if let Err(rv) = validate_user_buf(buf, cnt, 1) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: range [buf, buf+cnt) validated < USER_VA_END; user pages mapped via active CR3; CPL=0 reads through user mapping.
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts(buf as *const u8, cnt as usize)
    };
    match file.inode().write(off, bytes) {
        Ok(n) => n as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_getdents64(fd, dirp, count)` — slot 217. Walks the inode's
/// `readdir`, packs `linux_dirent64` records into the user buffer.
/// Returns bytes written, or 0 at end-of-dir. ENOTDIR for non-dirs.
/// File offset is the readdir cookie — incremented across calls.
/// # C: O(N_dirents)
pub fn sys_getdents64(args: &SyscallArgs) -> i64 {
    use vfs::FileType;
    let fd = args.a0 as i32;
    let dirp = args.a1;
    let count = args.a2 as usize;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    if count == 0 { return 0; }
    if let Err(rv) = validate_user_buf(dirp, args.a2, 1) { return rv; }
    let inode = file.inode().clone();
    if !matches!(inode.file_type(), FileType::Directory) {
        return -(Errno::Enotdir.as_i32() as i64);
    }
    let off = file.pos();
    let mut written: usize = 0;
    let mut new_off = off;
    let r = inode.readdir(off, &mut |cookie, name, ft| {
        let reclen = vfs::dirent64_reclen(name.len());
        if written + reclen > count { return false; }
        let dt: u8 = match ft {
            FileType::Regular   => 8,
            FileType::Directory => 4,
            FileType::CharDev   => 2,
            FileType::BlockDev  => 6,
            FileType::Symlink   => 10,
            FileType::Fifo      => 1,
            FileType::Socket    => 12,
        };
        let mut tmp = [0u8; 320];
        let n = vfs::dirent64_pack(&mut tmp[..reclen], 0, cookie, dt, name.as_bytes())
            .expect("dirent64_pack: tmp buf sized to reclen");
        // SAFETY: validate_user_buf above bounded [dirp, dirp+count) < USER_VA_END; CPL=0; caller's AS active.
        unsafe {
            for i in 0..n {
                core::ptr::write_volatile((dirp + (written + i) as u64) as *mut u8, tmp[i]);
            }
        }
        written += n;
        new_off = cookie;
        true
    });
    match r {
        Ok(_) => { file.set_pos(new_off); written as i64 }
        Err(e) => -(e as i64),
    }
}

/// `sys_dup(oldfd)` — slot 32. Tier-3 shim per `docs/53§4`.
/// Work fn: `vfs::FdTable::dup`. Lowest free fd → same File.
/// # C: O(N_fds)
pub fn sys_dup(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    match fdt.dup(oldfd) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_dup2(oldfd, newfd)` — slot 33. Tier-3 shim per `docs/53§4`.
/// Work fn: `vfs::FdTable::dup2`. oldfd==newfd returns newfd unchanged.
/// # C: O(1) + close
pub fn sys_dup2(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let newfd = args.a1 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    match fdt.dup2(oldfd, newfd) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_dup3(oldfd, newfd, flags)` — slot 292. Tier-3 shim.
/// Like dup2 but rejects oldfd==newfd; accepts O_CLOEXEC (ignored in v1).
/// # C: O(1) + close
pub fn sys_dup3(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let newfd = args.a1 as i32;
    if oldfd == newfd { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    match fdt.dup2(oldfd, newfd) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_close_range(first, last, flags)` — slot 436. Closes the
/// inclusive fd range [first, last]. CLOSE_RANGE_CLOEXEC (bit 2)
/// marks fds cloexec instead of closing. CLOSE_RANGE_UNSHARE (bit 1)
/// is accepted as a no-op (single-process v1 has nothing to unshare).
/// # C: O(last - first)
pub fn sys_close_range(args: &SyscallArgs) -> i64 {
    let first = args.a0 as i32;
    let last  = args.a1 as i32;
    let flags = args.a2 as u32;
    const CLOSE_RANGE_CLOEXEC:  u32 = 0x4;
    if first < 0 || last < 0 || first > last {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let cloexec_only = (flags & CLOSE_RANGE_CLOEXEC) != 0;
    for fd in fdt.live_fds() {
        if fd < first || fd > last { continue; }
        if cloexec_only {
            let _ = fdt.set_cloexec(fd, true);
        } else {
            let _ = fdt.close(fd);
        }
    }
    0
}


/// `sys_access(path, mode)` — slot 21. v1: returns 0 if path
/// resolves in devfs, -ENOENT otherwise. No actual permission
/// check (mode ignored).
/// # C: O(N_devfs_entries)
pub fn sys_access(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); bounded read.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    if path == b"/" { return 0; }
    let s = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    // Try the unified mount-table first (devfs/procfs/tmpfs/ext4), then
    // fall back to the raw-ext4 stat path which handles directories,
    // hardlinks, and symlinks that the mount-table's FileSystem::lookup
    // wrapper rejects. Mirrors sys_statx's resolver chain — without
    // this, ARM busybox's `access(X_OK)` returns ENOENT for /bin/<applet>
    // (a hardlink to /bin/busybox), every PATH-search probe falsely
    // fails, and the shell prints "Permission denied" without ever
    // attempting fork+execve.
    if vfs::mount::lookup(s).is_ok()
        || ext4::rootfs::stat_path(s.as_bytes()).is_some()
    {
        0
    } else {
        -(Errno::Enoent.as_i32() as i64)
    }
}

/// `sys_faccessat(dirfd, path, mode, flags)` — slot 269. v1
/// ignores `dirfd` + `flags`; same semantics as `sys_access`.
/// # C: O(N_devfs_entries)
pub fn sys_faccessat(args: &SyscallArgs) -> i64 {
    let inner = SyscallArgs { a0: args.a1, a1: args.a2, a2: 0, a3: 0, a4: 0, a5: 0 };
    sys_access(&inner)
}

/// `sys_readlink(path, buf, bufsize)` — slot 89. Resolves the
/// procfs symlinks `/proc/self/{exe,cwd,root}` and per-pid
/// `/proc/<tid>/{exe,cwd,root}`. `exe` reports argv[0] from the
/// task's cmdline snapshot (`/init` when unset). All other paths
/// return -EINVAL.
/// # C: O(1) + O(N_tasks) for per-pid lookup
pub fn sys_readlink(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let buf_ptr  = args.a1;
    let bufsize  = args.a2;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    if bufsize == 0 { return -(Errno::Einval.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(buf_ptr, bufsize, 1) { return rv; }
    // SAFETY: ptr in user range; user page mapped (caller already executed user code from this AS); bounded read.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let path_s = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let target: alloc::vec::Vec<u8> = match sched::proclink::resolve_proc_link(path_s) {
        Some(t) => t,
        None    => return -(Errno::Einval.as_i32() as i64),
    };
    let n = (target.len() as u64).min(bufsize) as usize;
    // SAFETY: buf range validated < USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        for i in 0..n {
            core::ptr::write_volatile((buf_ptr + i as u64) as *mut u8, target[i]);
        }
    }
    n as i64
}

// proc-link helpers (exe/cwd/root/fd/ns) moved to syscall_glue_proclink.rs (F112).

/// `sys_readlinkat(dirfd, path, buf, bufsize)` — slot 267.
/// v1 ignores `dirfd` (no real cwd resolution) and routes
/// through `sys_readlink`.
/// # C: O(1)
pub fn sys_readlinkat(args: &SyscallArgs) -> i64 {
    let inner = SyscallArgs { a0: args.a1, a1: args.a2, a2: args.a3, a3: 0, a4: 0, a5: 0 };
    sys_readlink(&inner)
}

/// `sys_poll(fds, nfds, timeout)` — slot 7. v1 non-blocking:
/// reports POLLIN|POLLOUT for CharDev fds (always ready in v1
/// since ConsoleInode reads block at the syscall layer instead
/// of returning EAGAIN); 0 (timeout/no events) for everything
/// else. Returns the number of fds with non-zero revents.
///
/// `pollfd { fd: i32, events: i16, revents: i16 }` = 8 bytes
/// each on Linux x86_64.
/// # C: O(nfds)
pub fn sys_poll(args: &SyscallArgs) -> i64 {
    const POLLIN:  i16 = 0x0001;
    const POLLOUT: i16 = 0x0004;
    const NFDS_MAX: u64 = 4096;
    let fds_ptr = args.a0;
    let nfds    = args.a1;
    let _timeout = args.a2 as i32;
    if nfds == 0 { return 0; }
    if nfds > NFDS_MAX { return -(Errno::Einval.as_i32() as i64); }
    let bytes = match nfds.checked_mul(8) {
        Some(v) => v,
        None    => return -(Errno::Efault.as_i32() as i64),
    };
    if let Err(rv) = validate_user_buf(fds_ptr, bytes, 4) { return rv; }
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    let mut ready: i64 = 0;
    for i in 0..nfds {
        let p = fds_ptr + i * 8;
        // SAFETY: pollfd[i] inside the validated nfds*8-byte range; 4-byte aligned per Linux ABI.
        let fd     = unsafe { core::ptr::read_volatile( p        as *const i32) };
        // SAFETY: same validated range; events at +4 is 2-byte aligned.
        let events = unsafe { core::ptr::read_volatile((p + 4)   as *const i16) };
        let mut revents: i16 = 0;
        if let Ok(file) = fdt.get(fd) {
            if file.inode().file_type() == vfs::FileType::CharDev {
                let ino = file.inode().ino();
                let pty_readable = if (ino & 0xFFFF_0000) == 0x6000_0000 {
                    let is_master = (ino & 0x8000) == 0;
                    crate::dev::pty::pair_for((ino & 0x7FFF) as u32).map(|pair| {
                        pair.with_pair(|p| if is_master { p.master_readable() } else { p.slave_readable() })
                    })
                } else { None };
                let inb = match pty_readable {
                    Some(true)  => POLLIN,
                    Some(false) => 0,
                    None        => POLLIN, // non-pty CharDev — keep prior always-ready
                };
                revents = events & (inb | POLLOUT);
            }
        }
        // SAFETY: revents at p+6 inside validated range; 2-byte aligned.
        unsafe { core::ptr::write_volatile((p + 6) as *mut i16, revents); }
        if revents != 0 { ready += 1; }
    }
    ready
}

/// `sys_ppoll(fds, nfds, ts, sigmask, sigsz)` — slot 271. Same
/// non-blocking shape as poll; signal mask + timespec ignored
/// (real pselect/ppoll wait support rides P3 follow-up).
/// # C: O(nfds)
pub fn sys_ppoll(args: &SyscallArgs) -> i64 {
    let pf = SyscallArgs { a0: args.a0, a1: args.a1, a2: 0, a3: 0, a4: 0, a5: 0 };
    sys_poll(&pf)
}


/// `sys_lseek(fd, offset, whence)` — slot 8. Tier-3 shim.
/// v1 always returns 0 for seekable file types, Espipe otherwise.
/// Work fn `vfs::File::lseek` lands as a follow-up.
/// # C: O(1)
pub fn sys_lseek(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let _off = args.a1 as i64;
    let _whence = args.a2 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    match file.inode().file_type() {
        vfs::FileType::Regular | vfs::FileType::BlockDev => 0,
        _                                                 => -(Errno::Espipe.as_i32() as i64),
    }
}

/// `sys_pwritev(fd, iov, iovcnt, off)` — slot 296. v1 ignores
/// the offset (acts like writev) for non-seekable backends; for
/// regular files this yields posix-correct results when the file
/// position equals `off` (the common stdio case post-fseek).
/// # C: O(iovcnt × iov[i].len)
pub fn sys_pwritev(args: &SyscallArgs) -> i64 { sys_writev(args) }

/// `sys_preadv(fd, iov, iovcnt, off)` — slot 295. Same offset
/// caveat as pwritev.
/// # C: O(1)
pub fn sys_preadv(args: &SyscallArgs) -> i64 { sys_readv(args) }

/// `sys_writev(fd, iov, iovcnt)` — slot 20. fd_table-routed
/// version: looks up the open `File`, walks the iovec array,
/// calls `File::write` for each non-empty buffer. Returns total
/// bytes written or the first negative errno encountered.
/// # C: O(iovcnt × iov[i].len)
pub fn sys_writev(args: &SyscallArgs) -> i64 {
    dtrace!(b"WV_IN", args.a2);
    const IOV_MAX: u64 = 1024;
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2;
    if iovcnt == 0 { return 0; }
    if iovcnt > IOV_MAX { return -(Errno::Einval.as_i32() as i64); }
    let array_bytes = match iovcnt.checked_mul(16) {
        Some(v) => v,
        None    => return -(Errno::Efault.as_i32() as i64),
    };
    if let Err(rv) = validate_user_buf(iov, array_bytes, 8) { return rv; }
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
    let mut total: u64 = 0;
    for i in 0..iovcnt {
        let iov_i = iov + i * 16;
        // SAFETY: iov array validated above; iov_i lies inside; 8-byte aligned per Linux ABI.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: same range as the read above; iov_len at +8 is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        dtrace!(b"WV_IOV", len);
        if len == 0 { continue; }
        if let Err(rv) = validate_user_buf(base, len, 1) { return rv; }
        // SAFETY: range validated < USER_VA_END; CPL=0 reads through caller's user pages.
        let bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(base as *const u8, len as usize)
        };
        dtrace!(b"WV_PRE_W");
        match file.write(bytes) {
            Ok(n)  => { dtrace!(b"WV_OK", n as u64); total = total.saturating_add(n as u64); }
            Err(e) => { dtrace!(b"WV_ERR", e as u64); return -(e as i64); }
        }
    }
    dtrace!(b"WV_OUT", total);
    total as i64
}

/// `sys_readv(fd, iov, iovcnt)` — slot 19. Mirror of writev for
/// reads. Each iov buffer gets one call into `File::read`; a
/// short read terminates the loop early per Linux semantics.
/// # C: O(iovcnt × iov[i].len)
pub fn sys_readv(args: &SyscallArgs) -> i64 {
    const IOV_MAX: u64 = 1024;
    let fd     = args.a0 as i32;
    let iov    = args.a1;
    let iovcnt = args.a2;
    if iovcnt == 0 { return 0; }
    if iovcnt > IOV_MAX { return -(Errno::Einval.as_i32() as i64); }
    let array_bytes = match iovcnt.checked_mul(16) {
        Some(v) => v,
        None    => return -(Errno::Efault.as_i32() as i64),
    };
    if let Err(rv) = validate_user_buf(iov, array_bytes, 8) { return rv; }
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
    let mut total: u64 = 0;
    for i in 0..iovcnt {
        let iov_i = iov + i * 16;
        // SAFETY: iov array validated above; iov_i in range; 8-byte aligned per Linux ABI.
        let base = unsafe { core::ptr::read_volatile(iov_i as *const u64) };
        // SAFETY: same validated range; iov_len at offset +8 is 8-byte aligned.
        let len  = unsafe { core::ptr::read_volatile((iov_i + 8) as *const u64) };
        if len == 0 { continue; }
        if let Err(rv) = validate_user_buf(base, len, 1) { return rv; }
        // SAFETY: range validated < USER_VA_END; CPL=0 writes through caller's AS.
        let buf: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(base as *mut u8, len as usize)
        };
        match file.read(buf) {
            Ok(0)  => break,
            Ok(n)  => {
                total = total.saturating_add(n as u64);
                if (n as u64) < len { break; }
            }
            Err(e) => return -(e as i64),
        }
    }
    total as i64
}

/// `sys_fchdir(fd)` — slot 81. v1 validates `fd` is open in the
/// current task's fd_table; no actual cwd state.
/// # C: O(1)
pub fn sys_fchdir(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match sched::live::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.get(fd) {
        Ok(_)  => 0,
        Err(_) => -(Errno::Ebadf.as_i32() as i64),
    }
}

/// `sys_truncate(path, length)` — slot 76.
/// # C: O(N_devfs_entries)
pub fn sys_truncate(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    let len      = args.a1;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped; bounded read.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let s = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let inode = match vfs::mount::lookup(s) {
        Ok(i)  => i,
        Err(_) => return -(Errno::Enoent.as_i32() as i64),
    };
    match inode.truncate(len) { Ok(_) => 0, Err(e) => -(e as i64) }
}

/// `sys_ftruncate(fd, length)` — slot 77.
/// # C: O(1)
pub fn sys_ftruncate(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let len = args.a1;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    match file.inode().truncate(len) { Ok(_) => 0, Err(e) => -(e as i64) }
}

// `sys_fallocate` lives in `syscall_glue_falloc.rs` (F69).
