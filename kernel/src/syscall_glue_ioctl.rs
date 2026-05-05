// `sys_ioctl` per `15§5` / `28§5`. Split from `syscall_glue_fs.rs`
// to keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::syscall_glue::validate_user_buf;

/// `sys_ioctl(fd, request, arg)` — slot 16.
/// # C: O(1)
pub fn kernel_sys_ioctl(args: &SyscallArgs) -> i64 {
    const TCGETS:     u64 = 0x5401;
    const TCSETS:     u64 = 0x5402;
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCGPTN:   u64 = 0x80045430;
    const TIOCSPTLCK: u64 = 0x40045431;
    const TIOCGPGRP:  u64 = 0x540F;
    const TIOCSPGRP:  u64 = 0x5410;
    let fd  = args.a0 as i32;
    let req = args.a1;
    let arg = args.a2;
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
    if file.inode().file_type() != vfs::FileType::CharDev {
        return -(Errno::Enotty.as_i32() as i64);
    }
    let ino = file.inode().ino();
    let pty_pair = if (ino & 0xFFFF_0000) == 0x6000_0000 {
        crate::dev_pty::pair_for((ino & 0x7FFF) as u32)
    } else { None };

    match req {
        TIOCGWINSZ => {
            if let Err(rv) = validate_user_buf(arg, 8, 2) { return rv; }
            // SAFETY: arg validated 8-byte aligned; CPL=0 writes through caller's AS.
            unsafe {
                core::ptr::write_volatile( arg       as *mut u16, 24);
                core::ptr::write_volatile((arg + 2)  as *mut u16, 80);
                core::ptr::write_volatile((arg + 4)  as *mut u16, 0);
                core::ptr::write_volatile((arg + 6)  as *mut u16, 0);
            }
            0
        }
        TCGETS => {
            if let Err(rv) = validate_user_buf(arg, tty::pty::TERMIOS_BYTES as u64, 4) { return rv; }
            // For pty fds copy the pair's termios image; for non-pty
            // CharDevs zero-fill (matches the prior isatty-probe behaviour).
            let snap = match &pty_pair {
                Some(pair) => pair.with_pair(|p| p.termios),
                None       => [0u8; tty::pty::TERMIOS_BYTES],
            };
            // SAFETY: arg validated 60-byte aligned; CPL=0 writes through caller's AS.
            unsafe {
                for i in 0..tty::pty::TERMIOS_BYTES {
                    core::ptr::write_volatile((arg + i as u64) as *mut u8, snap[i]);
                }
            }
            0
        }
        TCSETS => {
            if let Err(rv) = validate_user_buf(arg, tty::pty::TERMIOS_BYTES as u64, 4) { return rv; }
            if let Some(pair) = &pty_pair {
                let mut buf = [0u8; tty::pty::TERMIOS_BYTES];
                // SAFETY: arg validated 60-byte buffer; CPL=0 reads through caller's AS.
                unsafe {
                    for i in 0..tty::pty::TERMIOS_BYTES {
                        buf[i] = core::ptr::read_volatile((arg + i as u64) as *const u8);
                    }
                }
                pair.with_pair(|p| p.termios = buf);
            }
            0
        }
        TIOCGPTN => {
            if (ino & 0xFFFF_8000) != 0x6000_0000 { return -(Errno::Enotty.as_i32() as i64); }
            if let Err(rv) = validate_user_buf(arg, 4, 4) { return rv; }
            // SAFETY: arg validated 4-byte aligned; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut u32, (ino & 0x7FFF) as u32); }
            0
        }
        TIOCSPTLCK => 0,
        TIOCGPGRP | TIOCSPGRP => {
            let pair = match pty_pair { Some(p) => p, None => return -(Errno::Enotty.as_i32() as i64) };
            if let Err(rv) = validate_user_buf(arg, 4, 4) { return rv; }
            if req == TIOCGPGRP {
                let pgid = pair.with_pair(|p| p.foreground_pgid);
                // SAFETY: arg validated 4-byte aligned; CPL=0 writes.
                unsafe { core::ptr::write_volatile(arg as *mut u32, pgid); }
            } else {
                // SAFETY: arg validated 4-byte aligned; CPL=0 reads.
                let pgid = unsafe { core::ptr::read_volatile(arg as *const u32) };
                pair.with_pair(|p| p.foreground_pgid = pgid);
            }
            0
        }
        _ => -(Errno::Enotty.as_i32() as i64),
    }
}
