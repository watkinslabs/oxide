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
