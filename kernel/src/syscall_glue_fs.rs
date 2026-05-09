// Filesystem-shaped syscalls per docs/15§5 + docs/16, split from syscall_glue.rs.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use hal::USER_VA_END;

use crate::syscall_glue::{validate_user_buf, validate_user_buf_writable};

/// `sys_fstat(fd, statbuf)` — slot 5. 144-byte Linux x86_64 struct stat.
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

pub use crate::syscall_glue_ioctl::kernel_sys_ioctl;

/// `sys_getcwd(buf, size)` — slot 79. Reads `current.cwd` slot.
/// Returns the path length including the trailing NUL per
/// `man 2 getcwd`; -ERANGE if `size` is too small.
/// # C: O(N_cwd)
pub fn kernel_sys_getcwd(args: &SyscallArgs) -> i64 {
    let buf  = args.a0;
    let size = args.a1;
    let cur = match crate::sched::current() {
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
    let s = match core::str::from_utf8(path) {
        Ok(s)  => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolves = s == "/"
        || crate::devfs::lookup(s).is_some()
        || crate::procfs::lookup_dynamic(s).is_some()
        || crate::tmpfs::lookup(s).is_some();
    if !resolves { return -(Errno::Enoent.as_i32() as i64); }
    let cur = match crate::sched::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    // SAFETY: single-mutator per `13§5`; current task is sole writer.
    unsafe { *cur.cwd.get() = alloc::string::String::from(s); }
    0
}

/// `sys_fcntl(fd, cmd, arg)` — slot 72. F_DUPFD / F_GETFD / F_SETFD /
/// F_GETFL / F_SETFL / F_GETPIPE_SZ / F_SETPIPE_SZ / F_GETOWN / F_SETOWN.
/// # C: O(N_fds) for F_DUPFD; O(1) otherwise.
pub fn kernel_sys_fcntl(args: &SyscallArgs) -> i64 {
    const F_DUPFD:         u64 = 0;
    const F_GETFD:         u64 = 1;
    const F_SETFD:         u64 = 2;
    const F_GETFL:         u64 = 3;
    const F_SETFL:         u64 = 4;
    const F_DUPFD_CLOEXEC: u64 = 1030;
    const F_GETPIPE_SZ:    u64 = 1032;
    const F_SETPIPE_SZ:    u64 = 1031;
    const F_GETOWN:        u64 = 9;
    const F_SETOWN:        u64 = 8;
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
            match fdt.dup_min(fd, arg as i32) {
                Ok(new) => {
                    if cmd == F_DUPFD_CLOEXEC {
                        let _ = fdt.set_cloexec(new, true);
                    }
                    new as i64
                }
                Err(e)  => -(e as i64),
            }
        }
        F_GETFD => match fdt.cloexec(fd) { Ok(true) => 1, Ok(false) => 0, Err(_) => 0 },
        F_SETFD => {
            let _ = fdt.set_cloexec(fd, (arg & 1) != 0);
            0
        }
        F_GETFL => {
            let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
            file.flags().bits() as i64
        }
        F_SETFL => {
            // POSIX: only O_APPEND/O_NONBLOCK/O_DIRECT/O_NOATIME may
            // be modified. Mask the user value to the settable bits
            // and OR-merge over the existing access mode + creation
            // flags to preserve them.
            const SETTABLE: u32 = 0o4_004_000 | 0o0_004_000; // O_APPEND | O_NONBLOCK
            let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
            let cur_bits = file.flags().bits();
            let new_bits = (cur_bits & !SETTABLE) | ((arg as u32) & SETTABLE);
            file.set_flags(vfs::OpenFlags::from_bits_retain(new_bits));
            0
        }
        F_GETPIPE_SZ => 4096, // matches PipeBuf::PIPE_CAP
        F_SETPIPE_SZ => 4096, // accept but cap at the v1 fixed size
        F_GETOWN     => 0,
        F_SETOWN     => 0,
        _       => -(Errno::Einval.as_i32() as i64),
    }
}

/// `sys_statx(dirfd, path, flags, mask, statxbuf)` — slot 332.
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
    let times = crate::inode_times::get(&inode).unwrap_or_default();
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
        write_ts(72,  times.atime_ns);
        write_ts(104, times.ctime_ns);
        write_ts(120, times.mtime_ns);
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
        Some(i) => i,
        None => match crate::procfs::lookup_dynamic(s) {
            Some(i) => i,
            None => match crate::tmpfs::lookup(s) {
                Some(i) => i,
                None => return -(Errno::Enoent.as_i32() as i64),
            },
        },
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


/// `sys_pread64(fd, buf, cnt, off)` — slot 17.
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

/// `sys_getdents64(fd, dirp, count)` — slot 217. Walks the inode's
/// `readdir`, packs `linux_dirent64` records into the user buffer.
/// Returns bytes written, or 0 at end-of-dir. ENOTDIR for non-dirs.
/// File offset is the readdir cookie — incremented across calls.
/// # C: O(N_dirents)
pub fn kernel_sys_getdents64(args: &SyscallArgs) -> i64 {
    use vfs::FileType;
    let fd = args.a0 as i32;
    let dirp = args.a1;
    let count = args.a2 as usize;
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

/// `sys_close_range(first, last, flags)` — slot 436. Closes the
/// inclusive fd range [first, last]. CLOSE_RANGE_CLOEXEC (bit 2)
/// marks fds cloexec instead of closing. CLOSE_RANGE_UNSHARE (bit 1)
/// is accepted as a no-op (single-process v1 has nothing to unshare).
/// # C: O(last - first)
pub fn kernel_sys_close_range(args: &SyscallArgs) -> i64 {
    let first = args.a0 as i32;
    let last  = args.a1 as i32;
    let flags = args.a2 as u32;
    const CLOSE_RANGE_CLOEXEC:  u32 = 0x4;
    if first < 0 || last < 0 || first > last {
        return -(Errno::Einval.as_i32() as i64);
    }
    let cur = match crate::sched::current() {
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

/// `sys_readlink(path, buf, bufsize)` — slot 89. Resolves the
/// procfs symlinks `/proc/self/{exe,cwd,root}` and per-pid
/// `/proc/<tid>/{exe,cwd,root}`. `exe` reports argv[0] from the
/// task's cmdline snapshot (`/init` when unset). All other paths
/// return -EINVAL.
/// # C: O(1) + O(N_tasks) for per-pid lookup
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
    let path_s = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let target: alloc::vec::Vec<u8> = match resolve_proc_link(path_s) {
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

fn task_exe_path(tid_opt: Option<u32>) -> alloc::vec::Vec<u8> {
    let task = match tid_opt {
        Some(tid) => crate::sched::registry::lookup(tid),
        None      => crate::sched::current().and_then(|c|
            crate::sched::registry::lookup(c.tid)),
    };
    if let Some(t) = task {
        // F62: prefer the recorded exec path (sys_execve's `path`
        // argument). Busybox readlinks /proc/self/exe to discover
        // its own binary; without the real path it falls into
        // dispatcher mode and dumps applet help.
        // SAFETY: exe_path single-mutator per `13§5`; snapshot.
        if let Some(s) = unsafe { (*t.exe_path.get()).clone() } {
            if !s.is_empty() { return s.into_bytes(); }
        }
        // Fallback: argv[0] (legacy path; better than `/init`).
        // SAFETY: cmdline single-mutator per `13§5`.
        if let Some(s) = unsafe { (*t.cmdline.get()).clone() } {
            let bytes = s.as_bytes();
            let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
            if end > 0 { return bytes[..end].to_vec(); }
        }
    }
    b"/init".to_vec()
}

fn task_cwd_path(tid_opt: Option<u32>) -> alloc::vec::Vec<u8> {
    let task = match tid_opt {
        Some(tid) => crate::sched::registry::lookup(tid),
        None      => crate::sched::current().and_then(|c|
            crate::sched::registry::lookup(c.tid)),
    };
    if let Some(t) = task {
        // SAFETY: cwd slot single-mutator per `13§5`.
        let snap = unsafe { (*t.cwd.get()).clone() };
        if !snap.is_empty() { return snap.into_bytes(); }
    }
    b"/".to_vec()
}

fn resolve_proc_link(path: &str) -> Option<alloc::vec::Vec<u8>> {
    let rest = path.strip_prefix("/proc/")?;
    let mut parts = rest.splitn(2, '/');
    let head = parts.next()?;
    let leaf = parts.next()?;
    let tid_opt: Option<u32> = if head == "self" { None } else { head.parse().ok() };
    if head != "self" && tid_opt.is_none() { return None; }
    if let Some(tid) = tid_opt {
        if crate::sched::registry::lookup(tid).is_none() { return None; }
    }
    match leaf {
        "exe"  => Some(task_exe_path(tid_opt)),
        "cwd"  => Some(task_cwd_path(tid_opt)),
        "root" => Some(b"/".to_vec()),
        l if l.starts_with("fd/") => task_fd_path(tid_opt, &l[3..]),
        _      => None,
    }
}

fn task_fd_path(tid_opt: Option<u32>, fd_str: &str) -> Option<alloc::vec::Vec<u8>> {
    let fd: i32 = fd_str.parse().ok()?;
    let task = match tid_opt {
        Some(tid) => crate::sched::registry::lookup(tid)?,
        None      => crate::sched::registry::lookup(crate::sched::current()?.tid)?,
    };
    // SAFETY: fd_table slot single-mutator per `13§5`.
    let fdt = unsafe { (*task.fd_table.get()).as_ref()?.clone() };
    let file = fdt.get(fd).ok()?;
    Some(file.dentry().name().as_bytes().to_vec())
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
                let ino = file.inode().ino();
                let pty_readable = if (ino & 0xFFFF_0000) == 0x6000_0000 {
                    let is_master = (ino & 0x8000) == 0;
                    crate::dev_pty::pair_for((ino & 0x7FFF) as u32).map(|pair| {
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
pub fn kernel_sys_ppoll(args: &SyscallArgs) -> i64 {
    let pf = SyscallArgs { a0: args.a0, a1: args.a1, a2: 0, a3: 0, a4: 0, a5: 0 };
    kernel_sys_poll(&pf)
}


/// `sys_lseek(fd, offset, whence)` — slot 8.
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

/// `sys_pwritev(fd, iov, iovcnt, off)` — slot 296. v1 ignores
/// the offset (acts like writev) for non-seekable backends; for
/// regular files this yields posix-correct results when the file
/// position equals `off` (the common stdio case post-fseek).
/// # C: O(iovcnt × iov[i].len)
pub fn kernel_sys_pwritev(args: &SyscallArgs) -> i64 { kernel_sys_writev(args) }

/// `sys_preadv(fd, iov, iovcnt, off)` — slot 295. Same offset
/// caveat as pwritev.
/// # C: O(1)
pub fn kernel_sys_preadv(args: &SyscallArgs) -> i64 { kernel_sys_readv(args) }

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

/// `sys_truncate(path, length)` — slot 76.
/// # C: O(N_devfs_entries)
pub fn kernel_sys_truncate(args: &SyscallArgs) -> i64 {
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
    let inode = if let Some(i) = crate::devfs::lookup(s) { i }
        else if let Some(i) = crate::tmpfs::lookup(s) { i }
        else { return -(Errno::Enoent.as_i32() as i64); };
    match inode.truncate(len) { Ok(_) => 0, Err(e) => -(e as i64) }
}

/// `sys_ftruncate(fd, length)` — slot 77.
/// # C: O(1)
pub fn kernel_sys_ftruncate(args: &SyscallArgs) -> i64 {
    let fd  = args.a0 as i32;
    let len = args.a1;
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
    match file.inode().truncate(len) { Ok(_) => 0, Err(e) => -(e as i64) }
}

// `sys_fallocate` lives in `syscall_glue_falloc.rs` (F69).
