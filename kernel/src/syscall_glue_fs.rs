// P3-03 batch: filesystem-shaped syscalls split out of `syscall_glue.rs`
// to keep that file under the 1000-line cap per `08§7`. Routes for
// `fstat`, `ioctl`, `getcwd`, `chdir`, `fchdir` per docs/15§5 +
// docs/16. v1 lacks per-task cwd state and a real on-disk filesystem,
// so most calls synthesise minimal-but-Linux-shaped records.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::syscall_glue::validate_user_buf;

/// `sys_fstat(fd, statbuf)` — slot 5. Writes the 144-byte Linux
/// x86_64 `struct stat` for the open file at `fd`. v1 synthesises
/// a minimal record from the inode's `file_type()` + `ino()`;
/// sufficient for libc's `isatty()` (S_IFCHR check).
/// # C: O(1)
pub fn kernel_sys_fstat(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    if let Err(rv) = validate_user_buf(buf, 144, 8) { return rv; }
    let cur = match crate::sched::current() {
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

/// `sys_ioctl(fd, request, arg)` — slot 16 per docs/15§5 +
/// docs/28§5. v1 honours `TIOCGWINSZ` (fake 80×24 winsize for any
/// CharDev fd) and `TCGETS` (zero termios for libc's `isatty()`
/// probe). Other requests return `-ENOTTY`.
/// # C: O(1)
pub fn kernel_sys_ioctl(args: &SyscallArgs) -> i64 {
    const TCGETS:     u64 = 0x5401;
    const TCSETS:     u64 = 0x5402;
    const TIOCGWINSZ: u64 = 0x5413;
    let fd  = args.a0 as i32;
    let req = args.a1;
    let arg = args.a2;
    let cur = match crate::sched::current() {
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
    if file.inode().file_type() != vfs::FileType::CharDev {
        return -(Errno::Enotty.as_i32() as i64);
    }
    match req {
        TIOCGWINSZ => {
            if let Err(rv) = validate_user_buf(arg, 8, 2) { return rv; }
            // SAFETY: arg validated 8-byte user buffer 2-byte aligned; CPL=0 writes through caller's AS.
            unsafe {
                core::ptr::write_volatile( arg        as *mut u16, 24);
                core::ptr::write_volatile((arg + 2)   as *mut u16, 80);
                core::ptr::write_volatile((arg + 4)   as *mut u16, 0);
                core::ptr::write_volatile((arg + 6)   as *mut u16, 0);
            }
            0
        }
        TCGETS => {
            if let Err(rv) = validate_user_buf(arg, 60, 4) { return rv; }
            // SAFETY: arg validated 60-byte user buffer 4-byte aligned; zero-fill termios suffices for v1 isatty/raw-mode probe.
            unsafe {
                for off in (0..60).step_by(4) {
                    core::ptr::write_volatile((arg + off as u64) as *mut u32, 0);
                }
            }
            0
        }
        TCSETS => 0,
        _      => -(Errno::Enotty.as_i32() as i64),
    }
}

/// `sys_getcwd(buf, size)` — slot 79. v1 has no per-task cwd
/// state; always returns "/". Linux returns the path length
/// including the trailing NUL on success per `man 2 getcwd`.
/// # C: O(1)
pub fn kernel_sys_getcwd(args: &SyscallArgs) -> i64 {
    let buf  = args.a0;
    let size = args.a1;
    if size < 2 { return -(Errno::Erange.as_i32() as i64); }
    if let Err(rv) = validate_user_buf(buf, 2, 1) { return rv; }
    // SAFETY: validated 2-byte user buffer below USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        core::ptr::write_volatile( buf       as *mut u8, b'/');
        core::ptr::write_volatile((buf + 1)  as *mut u8, 0);
    }
    2
}

/// `sys_chdir(path)` — slot 80. v1 has no per-task cwd state;
/// validates the user pointer + accepts any path that resolves
/// in devfs or equals "/". Returns 0 on success, -ENOENT
/// otherwise.
/// # C: O(N_devfs_entries)
pub fn kernel_sys_chdir(args: &SyscallArgs) -> i64 {
    let path_ptr = args.a0;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's user code already executed from this AS); read bounded at 256 B.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    if path == b"/" { return 0; }
    let s = match core::str::from_utf8(path) {
        Ok(s)  => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    if crate::devfs::lookup(s).is_some() { 0 } else { -(Errno::Enoent.as_i32() as i64) }
}

/// `sys_fcntl(fd, cmd, arg)` — slot 72. v1 honours:
/// - F_DUPFD / F_DUPFD_CLOEXEC → fd_table dup starting at `arg`
/// - F_GETFD / F_SETFD → CLOEXEC flag is accepted but not stored
///   (no exec-time fd_table walk yet)
/// - F_GETFL → returns O_RDWR (best-effort)
/// - F_SETFL → accepts O_NONBLOCK / O_APPEND, no-op
/// Other commands return -EINVAL.
/// # C: O(N_fds) for F_DUPFD; O(1) otherwise.
pub fn kernel_sys_fcntl(args: &SyscallArgs) -> i64 {
    const F_DUPFD:         u64 = 0;
    const F_GETFD:         u64 = 1;
    const F_SETFD:         u64 = 2;
    const F_GETFL:         u64 = 3;
    const F_SETFL:         u64 = 4;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    let fd  = args.a0 as i32;
    let cmd = args.a1;
    let arg = args.a2;
    let cur = match crate::sched::current() {
        Some(c) => c,
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(),
        None    => return -(Errno::Ebadf.as_i32() as i64),
    };
    if fdt.get(fd).is_err() {
        return -(Errno::Ebadf.as_i32() as i64);
    }
    match cmd {
        F_DUPFD | F_DUPFD_CLOEXEC => {
            // Walk for the lowest free fd >= arg, then dup.
            let _ = arg; // v1: dup uses lowest free; honouring `arg` lower-bound rides FdTable extension
            match fdt.dup(fd) {
                Ok(new) => new as i64,
                Err(e)  => -(e as i64),
            }
        }
        F_GETFD => 0,
        F_SETFD => 0,
        F_GETFL => 2, // O_RDWR
        F_SETFL => 0,
        _       => -(Errno::Einval.as_i32() as i64),
    }
}

/// `sys_statx(dirfd, path, flags, mask, statxbuf)` — slot 332.
/// v1: writes a minimal `struct statx` (256 B) for the file at
/// `path` resolved through devfs, OR for `dirfd` if `path` is
/// empty + AT_EMPTY_PATH set. Mask reports STATX_TYPE|MODE|INO.
/// # C: O(1)
pub fn kernel_sys_statx(args: &SyscallArgs) -> i64 {
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
            match crate::devfs::lookup(s) {
                Some(i) => i,
                None    => return -(Errno::Enoent.as_i32() as i64),
            }
        }
        _ if (flags & AT_EMPTY_PATH) != 0 => {
            let cur = match crate::sched::current() {
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
    let mode = mode_type | 0o600;
    // statx layout per linux/stat.h. Zero everything then fill the
    // fields we actually have.
    // SAFETY: buf validated 256-byte 8-aligned range below USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..256u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        const STATX_TYPE: u32 = 1;
        const STATX_MODE: u32 = 2;
        const STATX_INO:  u32 = 0x100;
        core::ptr::write_volatile( buf            as *mut u32, STATX_TYPE | STATX_MODE | STATX_INO); // stx_mask
        core::ptr::write_volatile((buf +   4)     as *mut u32, 4096);                                // stx_blksize
        core::ptr::write_volatile((buf +  16)     as *mut u32, 1);                                   // stx_nlink
        core::ptr::write_volatile((buf +  28)     as *mut u16, mode);                                // stx_mode
        core::ptr::write_volatile((buf +  32)     as *mut u64, inode.ino());                         // stx_ino
        core::ptr::write_volatile((buf +  40)     as *mut u64, inode.size());                        // stx_size
        core::ptr::write_volatile((buf + 128)     as *mut u32, (rdev >> 8)  & 0xfff);                // stx_rdev_major
        core::ptr::write_volatile((buf + 132)     as *mut u32,  rdev        & 0xff);                 // stx_rdev_minor
    }
    0
}

/// `sys_stat(path, statbuf)` / `sys_lstat(path, statbuf)` —
/// slots 4/6. Resolves `path` via devfs, writes a 144-byte
/// stat struct (same shape as kernel_sys_fstat).
/// # C: O(N_devfs_entries)
pub fn kernel_sys_stat(args: &SyscallArgs) -> i64 {
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
    let inode = match crate::devfs::lookup(s) {
        Some(i) => i, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let (mode_type, rdev): (u32, u64) = match inode.file_type() {
        vfs::FileType::CharDev   => (0o020000, 0x0103),
        vfs::FileType::BlockDev  => (0o060000, 0),
        vfs::FileType::Directory => (0o040000, 0),
        vfs::FileType::Regular   => (0o100000, 0),
        vfs::FileType::Symlink   => (0o120000, 0),
        vfs::FileType::Fifo      => (0o010000, 0),
        vfs::FileType::Socket    => (0o140000, 0),
    };
    let mode = mode_type | 0o600;
    // SAFETY: buf validated 144-byte 8-aligned range below USER_VA_END; CPL=0 writes through caller's AS.
    unsafe {
        for off in (0..144u64).step_by(8) {
            core::ptr::write_volatile((buf + off) as *mut u64, 0);
        }
        core::ptr::write_volatile((buf +   8)     as *mut u64, inode.ino());
        core::ptr::write_volatile((buf +  16)     as *mut u64, 1);
        core::ptr::write_volatile((buf +  24)     as *mut u32, mode);
        core::ptr::write_volatile((buf +  40)     as *mut u64, rdev);
        core::ptr::write_volatile((buf +  48)     as *mut i64, inode.size() as i64);
        core::ptr::write_volatile((buf +  56)     as *mut i64, 4096);
    }
    0
}

/// `sys_statfs(path, buf)` / `sys_fstatfs(fd, buf)` — slots
/// 137/138. Writes a 120-byte `struct statfs` describing the
/// devfs root: f_type=0x57AC6E9D (TMPFS_MAGIC stand-in),
/// 4096 block size, no usage tracking.
/// # C: O(1)
pub fn kernel_sys_statfs(args: &SyscallArgs) -> i64 {
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

/// `sys_openat(dirfd, path, flags, mode)` — slot 257. v1
/// ignores `dirfd` (devfs is flat); routes `path` through the
/// existing devfs-backed `sys_open` glue.
/// # C: O(N_devfs_entries)
pub fn kernel_sys_openat(args: &SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use alloc::sync::Arc;
    use vfs::{Dentry, File, OpenFlags};
    let path_ptr = args.a1;
    let flags    = args.a2 as u32;
    if path_ptr == 0 || path_ptr >= USER_VA_END {
        return -(Errno::Efault.as_i32() as i64);
    }
    // SAFETY: ptr in user range; user page mapped (caller's AS); bounded read.
    let path = match unsafe { crate::devfs::read_user_cstr(path_ptr, 256) } {
        Some(p) if !p.is_empty() => p,
        _                        => return -(Errno::Einval.as_i32() as i64),
    };
    let s = match core::str::from_utf8(path) {
        Ok(s)  => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let inode = match crate::devfs::lookup(s) {
        Some(i) => i, None => return -(Errno::Enoent.as_i32() as i64),
    };
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let dentry = Dentry::new(None, s.to_string(), Arc::clone(&inode));
    let oflags = OpenFlags::from_bits_truncate(flags);
    let file = File::new(inode, dentry, oflags);
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_pread64(fd, buf, cnt, off)` — slot 17. Routes through
/// fd_table → File::read with the explicit offset honored by
/// the underlying inode (procfs StaticFileInode uses it; pipes
/// + chardevs ignore it).
/// # C: O(cnt)
pub fn kernel_sys_pread64(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2;
    let off = args.a3;
    if cnt == 0 { return 0; }
    if let Err(rv) = validate_user_buf(buf, cnt, 1) { return rv; }
    let cur = match crate::sched::current() {
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
pub fn kernel_sys_pwrite64(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let buf = args.a1;
    let cnt = args.a2;
    let off = args.a3;
    if cnt == 0 { return 0; }
    if let Err(rv) = validate_user_buf(buf, cnt, 1) { return rv; }
    let cur = match crate::sched::current() {
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

/// `sys_getdents64(fd, dirp, count)` — slot 217. v1: every
/// fd we hand out points at a Regular or CharDev file (not a
/// directory), so getdents always returns 0 (= end-of-dir).
/// Real Inode::lookup-driven dirent enumeration rides VFS work
/// per docs/16. Validates `dirp` user range.
/// # C: O(1)
pub fn kernel_sys_getdents64(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let dirp = args.a1;
    let count = args.a2;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    if fdt.get(fd).is_err() { return -(Errno::Ebadf.as_i32() as i64); }
    if count == 0 { return 0; }
    if let Err(rv) = validate_user_buf(dirp, count, 1) { return rv; }
    0
}

/// `sys_dup(oldfd)` — slot 32. Lowest free fd → same File.
/// # C: O(N_fds)
pub fn kernel_sys_dup(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.dup(oldfd) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_dup2(oldfd, newfd)` — slot 33. Closes newfd, clones
/// oldfd. oldfd==newfd returns newfd unchanged.
/// # C: O(1) + close
pub fn kernel_sys_dup2(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let newfd = args.a1 as i32;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.dup2(oldfd, newfd) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_dup3(oldfd, newfd, flags)` — slot 292. Like dup2 but
/// rejects oldfd==newfd; accepts O_CLOEXEC (ignored in v1).
/// # C: O(1) + close
pub fn kernel_sys_dup3(args: &SyscallArgs) -> i64 {
    let oldfd = args.a0 as i32;
    let newfd = args.a1 as i32;
    if oldfd == newfd { return -(Errno::Einval.as_i32() as i64); }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    match fdt.dup2(oldfd, newfd) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_eventfd2(initval, flags)` — slot 290. Allocates a new
/// EventfdInode initialised to `initval`, wraps in a File at the
/// lowest-free fd. flags ignored (EFD_NONBLOCK is the default).
/// `sys_eventfd` (slot 284) routes here with flags=0.
/// # C: O(1)
pub fn kernel_sys_eventfd2(args: &SyscallArgs) -> i64 {
    use alloc::string::ToString;
    use vfs::{Dentry, File, OpenFlags};
    let initval = args.a0;
    let _flags  = args.a1;
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; preempt-off.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let inode = crate::dev_pipe::EventfdInode::new(initval);
    let dentry = Dentry::new(None, "eventfd".to_string(), inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    match fdt.alloc(file) {
        Ok(fd) => fd as i64,
        Err(e) => -(e as i64),
    }
}

/// `sys_access(path, mode)` — slot 21. v1: returns 0 if path
/// resolves in devfs, -ENOENT otherwise. No actual permission
/// check (mode ignored).
/// # C: O(N_devfs_entries)
pub fn kernel_sys_access(args: &SyscallArgs) -> i64 {
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
    if crate::devfs::lookup(s).is_some() { 0 } else { -(Errno::Enoent.as_i32() as i64) }
}

/// `sys_faccessat(dirfd, path, mode, flags)` — slot 269. v1
/// ignores `dirfd` + `flags`; same semantics as `sys_access`.
/// # C: O(N_devfs_entries)
pub fn kernel_sys_faccessat(args: &SyscallArgs) -> i64 {
    let inner = SyscallArgs { a0: args.a1, a1: args.a2, a2: 0, a3: 0, a4: 0, a5: 0 };
    kernel_sys_access(&inner)
}

/// `sys_readlink(path, buf, bufsize)` — slot 89. v1 special-
/// cases the paths libc commonly probes: `/proc/self/exe` →
/// "/init"; `/proc/self/cwd` → "/". All other paths return
/// -EINVAL so glibc falls through to its non-readlink fallback.
/// Returns the byte count written (excluding NUL, per Linux).
/// # C: O(1)
pub fn kernel_sys_readlink(args: &SyscallArgs) -> i64 {
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
    let target: &[u8] = match path {
        b"/proc/self/exe"     => b"/init",
        b"/proc/self/cwd"     => b"/",
        b"/proc/self/root"    => b"/",
        _                     => return -(Errno::Einval.as_i32() as i64),
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

/// `sys_readlinkat(dirfd, path, buf, bufsize)` — slot 267.
/// v1 ignores `dirfd` (no real cwd resolution) and routes
/// through `kernel_sys_readlink`.
/// # C: O(1)
pub fn kernel_sys_readlinkat(args: &SyscallArgs) -> i64 {
    let inner = SyscallArgs { a0: args.a1, a1: args.a2, a2: args.a3, a3: 0, a4: 0, a5: 0 };
    kernel_sys_readlink(&inner)
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
pub fn kernel_sys_poll(args: &SyscallArgs) -> i64 {
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
    let cur = match crate::sched::current() {
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
                revents = events & (POLLIN | POLLOUT);
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
pub fn kernel_sys_ppoll(args: &SyscallArgs) -> i64 {
    let pf = SyscallArgs { a0: args.a0, a1: args.a1, a2: 0, a3: 0, a4: 0, a5: 0 };
    kernel_sys_poll(&pf)
}

/// `sys_lseek(fd, offset, whence)` — slot 8. v1: returns
/// `-ESPIPE` for non-Regular file types (CharDev / Fifo / Socket)
/// per POSIX; returns 0 (start of file) for Regular if such
/// inodes appear later. Real seek state lives on `File` once
/// VFS gains it.
/// # C: O(1)
pub fn kernel_sys_lseek(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let _off = args.a1 as i64;
    let _whence = args.a2 as i32;
    let cur = match crate::sched::current() {
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
    match file.inode().file_type() {
        vfs::FileType::Regular | vfs::FileType::BlockDev => 0,
        _                                                 => -(Errno::Espipe.as_i32() as i64),
    }
}

/// `sys_writev(fd, iov, iovcnt)` — slot 20. fd_table-routed
/// version: looks up the open `File`, walks the iovec array,
/// calls `File::write` for each non-empty buffer. Returns total
/// bytes written or the first negative errno encountered.
/// # C: O(iovcnt × iov[i].len)
pub fn kernel_sys_writev(args: &SyscallArgs) -> i64 {
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
    let cur = match crate::sched::current() {
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
        if len == 0 { continue; }
        if let Err(rv) = validate_user_buf(base, len, 1) { return rv; }
        // SAFETY: range validated < USER_VA_END; CPL=0 reads through caller's user pages.
        let bytes: &[u8] = unsafe {
            core::slice::from_raw_parts(base as *const u8, len as usize)
        };
        match file.write(bytes) {
            Ok(n)  => total = total.saturating_add(n as u64),
            Err(e) => return -(e as i64),
        }
    }
    total as i64
}

/// `sys_readv(fd, iov, iovcnt)` — slot 19. Mirror of writev for
/// reads. Each iov buffer gets one call into `File::read`; a
/// short read terminates the loop early per Linux semantics.
/// # C: O(iovcnt × iov[i].len)
pub fn kernel_sys_readv(args: &SyscallArgs) -> i64 {
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
    let cur = match crate::sched::current() {
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
pub fn kernel_sys_fchdir(args: &SyscallArgs) -> i64 {
    let fd = args.a0 as i32;
    let cur = match crate::sched::current() {
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
