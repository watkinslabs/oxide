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
    let raw = match core::str::from_utf8(path) {
        Ok(s)  => s,
        Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = crate::syscalls::pathresolve::resolve_cwd(raw);
    let s = resolved.as_str();
    let resolves = s == "/"
        || vfs::mount::lookup(s).is_ok()
        || matches!(ext4::rootfs::stat_path(s.as_bytes()),
                    Some((_, vfs::FileType::Directory, _)));
    if !resolves { return -(Errno::Enoent.as_i32() as i64); }
    // SAFETY: single-mutator per `13§5`; current task is sole writer.
    unsafe { *cur.cwd.get() = alloc::string::String::from(s); }
    0
}

/// `sys_fcntl(fd, cmd, arg)` — slot 72. F_DUPFD / F_DUPFD_CLOEXEC /
/// F_GETFD / F_SETFD / F_GETFL / F_SETFL / F_GETPIPE_SZ /
/// F_SETPIPE_SZ / F_GETOWN / F_SETOWN; F_SETLK / F_SETLKW / F_GETLK
/// + F_OFD_* via `handle_record_lock`.
/// # C: O(1) per cmd; O(N_fds) for F_DUPFD.
pub fn sys_fcntl(args: &SyscallArgs) -> i64 {
    const F_DUPFD: u64 = 0; const F_GETFD: u64 = 1; const F_SETFD: u64 = 2;
    const F_GETFL: u64 = 3; const F_SETFL: u64 = 4;
    const F_GETLK: u64 = 5; const F_SETLK: u64 = 6; const F_SETLKW: u64 = 7;
    const F_OFD_GETLK: u64 = 36; const F_OFD_SETLK: u64 = 37; const F_OFD_SETLKW: u64 = 38;
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
        F_GETOWN => file.owner.load(core::sync::atomic::Ordering::Acquire) as i64,
        F_SETOWN => { file.owner.store(arg as i32, core::sync::atomic::Ordering::Release); 0 }
        F_SETLK | F_SETLKW | F_GETLK |
        F_OFD_SETLK | F_OFD_SETLKW | F_OFD_GETLK => {
            handle_record_lock(&cur, &fdt, &file, cmd, arg)
        }
        _ => -(Errno::Einval.as_i32() as i64),
    }
}

/// F_SETLK / F_SETLKW / F_GETLK + F_OFD_* dispatch via
/// `fs::posix_lock`. SETLKW spins on EAGAIN until success;
/// GETLK probes and writes back.
fn handle_record_lock(
    cur: &sched::Task,
    _fdt: &alloc::sync::Arc<vfs::FdTable>,
    file: &alloc::sync::Arc<vfs::File>,
    cmd: u64,
    arg: u64,
) -> i64 {
    use fs::posix_lock::{decode_flock, encode_flock, probe, try_set_lock, Owner, FLOCK_BYTES};
    const F_GETLK: u64 = 5; const F_SETLK: u64 = 6; const F_SETLKW: u64 = 7;
    const F_OFD_GETLK: u64 = 36; const F_OFD_SETLK: u64 = 37; const F_OFD_SETLKW: u64 = 38;
    if let Err(rv) = validate_user_buf(arg, FLOCK_BYTES as u64, 8) { return rv; }
    let mut bytes = [0u8; FLOCK_BYTES];
    // SAFETY: arg validated FLOCK_BYTES below USER_VA_END; CPL=0 reads through caller's AS.
    unsafe {
        for i in 0..FLOCK_BYTES {
            bytes[i] = core::ptr::read_volatile((arg + i as u64) as *const u8);
        }
    }
    let cur_pos  = file.pos();
    let file_sz  = file.inode().size();
    let mut req  = match decode_flock(&bytes, cur_pos, file_sz) {
        Ok(r) => r, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let is_ofd = matches!(cmd, F_OFD_GETLK | F_OFD_SETLK | F_OFD_SETLKW);
    let owner = if is_ofd {
        Owner::Ofd(alloc::sync::Arc::as_ptr(file) as *const u8 as usize)
    } else {
        Owner::Pid(cur.tid)
    };
    let inode = file.inode();
    match cmd {
        F_GETLK | F_OFD_GETLK => {
            req.pid = match owner { Owner::Pid(p) => p, _ => 0 };
            match probe(inode, &req, owner) {
                Some(blk) => {
                    let mut out = [0u8; FLOCK_BYTES];
                    encode_flock(&mut out, &blk);
                    // SAFETY: arg validated above; CPL=0 writes through caller's AS.
                    unsafe {
                        for i in 0..FLOCK_BYTES {
                            core::ptr::write_volatile((arg + i as u64) as *mut u8, out[i]);
                        }
                    }
                }
                None => {
                    // No conflict — return F_UNLCK in l_type.
                    let mut out = bytes;
                    out[0..2].copy_from_slice(&(fs::posix_lock::F_UNLCK).to_le_bytes());
                    // SAFETY: arg validated above; CPL=0 writes through caller's AS.
                    unsafe {
                        for i in 0..FLOCK_BYTES {
                            core::ptr::write_volatile((arg + i as u64) as *mut u8, out[i]);
                        }
                    }
                }
            }
            0
        }
        F_SETLK | F_OFD_SETLK => {
            match try_set_lock(inode, &req, owner) {
                Ok(()) => 0,
                Err(e) => -(e as i64),
            }
        }
        F_SETLKW | F_OFD_SETLKW => {
            // Spin-yield until peer releases (real wait list rides
            // a follow-up).
            loop {
                match try_set_lock(inode, &req, owner) {
                    Ok(()) => return 0,
                    Err(vfs::VfsError::Eagain) => {
                        // SAFETY: process ctx; preempt-off; runqueue installed; voluntary schedule() yields the CPU; we stay Runnable so the scheduler picks us back up shortly.
                        unsafe { sched::live::schedule::schedule(); }
                    }
                    Err(e) => return -(e as i64),
                }
            }
        }
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
    const AT_FDCWD: i32 = -100;
    let inode = match path_opt {
        Some(p) if !p.is_empty() => {
            let raw = match core::str::from_utf8(p) {
                Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
            };
            // Resolve relative path against cwd (statx semantics for AT_FDCWD).
            let resolved: alloc::string::String = if raw.starts_with('/') {
                raw.into()
            } else if dirfd == AT_FDCWD {
                let cur = match sched::live::current() {
                    Some(c) => c, None => return -(Errno::Einval.as_i32() as i64),
                };
                // SAFETY: cwd slot single-mutator per `13§5`.
                let cwd = unsafe { (*cur.cwd.get()).clone() };
                vfs::path::resolve_against_cwd(&cwd, raw).unwrap_or_else(|| raw.into())
            } else { raw.into() };
            let s = resolved.as_str();
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
        // stx_mask = STATX_BASIC_STATS — tell the caller all base
        // fields (type/mode/nlink/uid/gid/atime/mtime/ctime/ino/size/
        // blocks) are valid. Pre-fix mask omitted NLINK/UID/GID/SIZE,
        // which broke ARM musl's stat() wrapper: it returned a struct
        // stat with st_uid/st_gid/st_size synthesised from the
        // unmasked fields, and busybox-ash's perm check rejected the
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

pub use crate::syscalls::newfstatat::sys_newfstatat;

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
    let raw = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = crate::syscalls::pathresolve::resolve_cwd(raw);
    let s = resolved.as_str();
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
    const O_CLOEXEC: u64 = 0o2_000_000;
    let oldfd = args.a0 as i32;
    let newfd = args.a1 as i32;
    let flags = args.a2;
    if oldfd == newfd { return -(Errno::Einval.as_i32() as i64); }
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    match fdt.dup2(oldfd, newfd) {
        Ok(fd) => {
            if (flags & O_CLOEXEC) != 0 { let _ = fdt.set_cloexec(fd, true); }
            fd as i64
        }
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


/// `sys_access(path, mode)` — slot 21.  returns 0 if path
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
    let raw = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = crate::syscalls::pathresolve::resolve_cwd(raw);
    let s = resolved.as_str();
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
    let raw = match core::str::from_utf8(path) {
        Ok(s) => s, Err(_) => return -(Errno::Einval.as_i32() as i64),
    };
    let resolved = crate::syscalls::pathresolve::resolve_cwd(raw);
    let path_s = resolved.as_str();
    // proc-link family first (/proc/self/exe etc) — not backed by Inode::readlink.
    let target: alloc::vec::Vec<u8> = if let Some(t) = sched::proclink::resolve_proc_link(path_s) { t }
        else if let Some(inode) = ext4::rootfs::lookup_inode_any(path_s.as_bytes()) {
            match inode.readlink() { Ok(v) => v, Err(_) => return -(Errno::Einval.as_i32() as i64) }
        } else if let Ok(inode) = vfs::mount::lookup(path_s) {
            match inode.readlink() { Ok(v) => v, Err(_) => return -(Errno::Einval.as_i32() as i64) }
        } else { return -(Errno::Enoent.as_i32() as i64); };
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
pub use crate::syscalls::poll::{sys_poll, sys_ppoll};


/// `sys_lseek(fd, offset, whence)` — slot 8. Real `vfs::File::seek`
/// for seekable file types (Regular + BlockDev); ESPIPE for the
/// non-seekable kinds (Fifo / Socket / CharDev) per Linux.
/// # C: O(1)
pub fn sys_lseek(args: &SyscallArgs) -> i64 {
    let fd     = args.a0 as i32;
    let off    = args.a1 as i64;
    let whence = args.a2 as i32;
    let cur = match sched::live::current() { Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64) };
    // SAFETY: running task on this CPU; preempt-off; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } { Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64) };
    let file = match fdt.get(fd) { Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64) };
    match file.inode().file_type() {
        vfs::FileType::Regular | vfs::FileType::BlockDev => {}
        _ => return -(Errno::Espipe.as_i32() as i64),
    }
    let from = match whence {
        0 => vfs::SeekFrom::Start,   // SEEK_SET
        1 => vfs::SeekFrom::Current, // SEEK_CUR
        2 => vfs::SeekFrom::End,     // SEEK_END
        _ => return -(Errno::Einval.as_i32() as i64),
    };
    match file.seek(from, off) {
        Ok(pos) => pos as i64,
        Err(e)  => -(e as i64),
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
    if let Err(rv) = crate::syscalls::landlock::check(s,
        ::security::landlock::access::TRUNCATE) { return rv; }
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
