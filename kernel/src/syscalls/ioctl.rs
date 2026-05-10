// `sys_ioctl` per `15§5` / `28§5`. Split from `syscall_glue_fs.rs`
// to keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::syscalls::validate_user_buf;

/// `sys_ioctl(fd, request, arg)` — slot 16.
/// # C: O(1)
pub fn kernel_sys_ioctl(args: &SyscallArgs) -> i64 {
    const TCGETS:     u64 = 0x5401;
    const TCSETS:     u64 = 0x5402;
    const TCSETSW:    u64 = 0x5403; // TCSETS after pending output drains; v1 == TCSETS
    const TCSETSF:    u64 = 0x5404; // TCSETS + flush input; v1 == TCSETS
    const TIOCGWINSZ: u64 = 0x5413;
    const TIOCSWINSZ: u64 = 0x5414;
    const TIOCGPTN:   u64 = 0x80045430;
    const TIOCSPTLCK: u64 = 0x40045431;
    const TIOCGPGRP:  u64 = 0x540F;
    const TIOCSPGRP:  u64 = 0x5410;
    const TIOCSCTTY:  u64 = 0x540E;
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
    // userfaultfd / perf ioctls: route through the dedicated handlers
    // before the CharDev gate (those inodes are tagged Regular).
    if (file.inode().ino() & 0xFFFF_FFFF_0000_0000) == 0x5546_4644_0000_0000 {
        return userfaultfd::handle_uffd_ioctl(file.inode(), req, arg);
    }
    if (file.inode().ino() & 0xFFFF_FFFF_0000_0000) == 0x5045_5246_0000_0000 {
        return perf::handle_perf_ioctl(file.inode(), req, arg);
    }
    // evdev ioctls.
    if let Some(rv) = drv_virtio_input::devfs::handle_evdev_ioctl(file.inode(), req, arg) {
        return rv;
    }
    // DRM/render fd ioctls.
    if let Some(rv) = fbdev::devfs::handle_fbdev_ioctl(file.inode(), req, arg) {
        return rv;
    }
    if let Some(rv) = crate::dev_drm::handle_drm_ioctl(file.inode(), req, arg) {
        return rv;
    }
    if file.inode().file_type() != vfs::FileType::CharDev {
        return -(Errno::Enotty.as_i32() as i64);
    }
    // KD_*/VT_* ioctls on /dev/tty<N> + /dev/tty0 + /dev/console
    // route through the vt crate.
    if let Some(rv) = handle_vt_ioctl(file.inode(), req, arg) {
        return rv;
    }
    let ino = file.inode().ino();
    let pty_pair = if (ino & 0xFFFF_0000) == 0x6000_0000 {
        crate::dev_pty::pair_for((ino & 0x7FFF) as u32)
    } else { None };

    match req {
        TIOCGWINSZ => {
            if let Err(rv) = validate_user_buf(arg, 8, 2) { return rv; }
            // PTY fds: read from the pair's stored winsize. Other
            // CharDev fds: report the default 24×80 (matches the
            // prior fixed return).
            let ws = match &pty_pair {
                Some(pair) => pair.with_pair(|p| p.winsize),
                None       => tty::pty::Winsize::default_pty(),
            };
            let bytes = ws.to_le_bytes();
            // SAFETY: arg validated 8-byte aligned; CPL=0 writes through caller's AS.
            unsafe {
                for i in 0..8 {
                    core::ptr::write_volatile((arg + i as u64) as *mut u8, bytes[i]);
                }
            }
            0
        }
        TIOCSWINSZ => {
            if let Err(rv) = validate_user_buf(arg, 8, 2) { return rv; }
            let mut buf = [0u8; 8];
            // SAFETY: arg validated 8-byte buffer; CPL=0 reads through caller's AS.
            unsafe {
                for i in 0..8 {
                    buf[i] = core::ptr::read_volatile((arg + i as u64) as *const u8);
                }
            }
            let ws = tty::pty::Winsize::from_le_bytes(&buf);
            let (changed, fg) = match &pty_pair {
                Some(pair) => pair.with_pair(|p| {
                    p.set_winsize(ws);
                    let fired = p.pending_sigwinch;
                    if fired { p.pending_sigwinch = false; }
                    (fired, p.foreground_pgid)
                }),
                None => (false, 0),
            };
            if changed && fg != 0 {
                // SIGWINCH = 28; bit (28-1) = 27.
                use core::sync::atomic::Ordering;
                for t in crate::sched::registry::tasks_in_pgrp(fg) {
                    t.sigpending.fetch_or(1u64 << 27, Ordering::Release);
                }
            }
            0
        }
        TCGETS => {
            if let Err(rv) = validate_user_buf(arg, tty::pty::TERMIOS_BYTES as u64, 4) { return rv; }
            // For pty fds copy the pair's termios image; for the
            // boot UART /dev/console + /dev/tty<N> read the per-VT
            // termios state. The vt id is the inode number — devfs
            // assigns ino=1 for the foreground alias and ino=N for
            // /dev/ttyN, matching `ConsoleInode::new(vt)` in dev_console.rs.
            let snap = match &pty_pair {
                Some(pair) => pair.with_pair(|p| p.termios),
                None       => {
                    let vt = (ino & 0xff) as u8;
                    crate::tty::termios_get(vt)
                }
            };
            // SAFETY: arg validated 60-byte aligned; CPL=0 writes through caller's AS.
            unsafe {
                for i in 0..tty::pty::TERMIOS_BYTES {
                    core::ptr::write_volatile((arg + i as u64) as *mut u8, snap[i]);
                }
            }
            0
        }
        TCSETS | TCSETSW | TCSETSF => {
            if let Err(rv) = validate_user_buf(arg, tty::pty::TERMIOS_BYTES as u64, 4) { return rv; }
            let mut buf = [0u8; tty::pty::TERMIOS_BYTES];
            // SAFETY: arg validated 60-byte buffer; CPL=0 reads through caller's AS.
            unsafe {
                for i in 0..tty::pty::TERMIOS_BYTES {
                    buf[i] = core::ptr::read_volatile((arg + i as u64) as *const u8);
                }
            }
            if let Some(pair) = &pty_pair {
                pair.with_pair(|p| p.termios = buf);
            } else {
                let vt = (ino & 0xff) as u8;
                crate::tty::termios_set(vt, &buf);
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
            if let Err(rv) = validate_user_buf(arg, 4, 4) { return rv; }
            // PTY fds: read/write the pair's foreground_pgid. Boot
            // UART /dev/console + /dev/tty<N>: use the per-VT slot.
            // Bash + glibc job-control issue these on fd 0 / fd 2
            // at startup; without TIOCGPGRP returning a sensible
            // value bash falls back to "no job control" mode.
            if let Some(pair) = &pty_pair {
                if req == TIOCGPGRP {
                    let pgid = pair.with_pair(|p| p.foreground_pgid);
                    // SAFETY: arg validated 4-byte aligned; CPL=0 writes.
                    unsafe { core::ptr::write_volatile(arg as *mut u32, pgid); }
                } else {
                    // SAFETY: arg validated 4-byte aligned; CPL=0 reads.
                    let pgid = unsafe { core::ptr::read_volatile(arg as *const u32) };
                    pair.with_pair(|p| p.foreground_pgid = pgid);
                }
            } else {
                let vt = (ino & 0xff) as u8;
                if req == TIOCGPGRP {
                    let pgid = crate::tty::foreground_pgid(vt);
                    // SAFETY: arg validated 4-byte aligned; CPL=0 writes.
                    unsafe { core::ptr::write_volatile(arg as *mut u32, pgid); }
                } else {
                    // SAFETY: arg validated 4-byte aligned; CPL=0 reads.
                    let pgid = unsafe { core::ptr::read_volatile(arg as *const u32) };
                    crate::tty::set_foreground_pgid(vt, pgid);
                }
            }
            0
        }
        TIOCSCTTY => {
            // Make this fd's tty the controlling terminal for the
            // caller's session. v1 records sid on the VT but doesn't
            // enforce session-match checks on subsequent TIOCSPGRP.
            if pty_pair.is_some() {
                // PTY controlling-tty already tracked via pair's
                // session field — pre-existing semantics, no-op
                // here for the v1 path.
                return 0;
            }
            let vt = (ino & 0xff) as u8;
            let cur = match crate::sched::current() {
                Some(c) => c, None => return -(Errno::Eperm.as_i32() as i64),
            };
            use core::sync::atomic::Ordering;
            crate::tty::set_session(vt, cur.sid.load(Ordering::Acquire));
            0
        }
        _ => -(Errno::Enotty.as_i32() as i64),
    }
}

/// KD_*/VT_* ioctls on /dev/tty<N> via the vt crate. Returns
/// `Some(rv)` when the ioctl is recognised; `None` to fall back to
/// the existing tty-line-discipline path.
/// # C: O(1)
fn handle_vt_ioctl(inode: &vfs::InodeRef, req: u64, arg: u64) -> Option<i64> {
    if inode.file_type() != vfs::FileType::CharDev { return None; }
    // /dev/tty<N> + /dev/tty0 + /dev/console all use ConsoleInode
    // whose ino == max(vt, 1); 0 means foreground alias.
    let ino_low = (inode.ino() & 0xFF) as u8;
    let vt_target = if ino_low == 1 { vt::active() } else { ino_low };
    if !(1..=63).contains(&vt_target) { return None; }
    use syscall::errno::Errno;
    let errno = |e: Errno| -(e.as_i32() as i64);
    match req {
        vt::KDGETMODE => {
            let v = vt::slot(vt_target).map(|s| s.kd_mode).unwrap_or(vt::KD_TEXT);
            if arg != 0 && arg < hal::USER_VA_END {
                // SAFETY: arg validated < USER_VA_END; aligned u32 store of mode value into caller's AS.
                unsafe { core::ptr::write_volatile(arg as *mut u32, v); }
            }
            Some(0)
        }
        vt::KDSETMODE => {
            let mode = arg as u32;
            match vt::set_kd_mode(vt_target, mode) {
                Ok(()) => Some(0),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::KDGKBMODE => {
            let v = vt::slot(vt_target).map(|s| s.kb_mode).unwrap_or(vt::K_XLATE);
            if arg != 0 && arg < hal::USER_VA_END {
                // SAFETY: arg validated < USER_VA_END; aligned u32 store.
                unsafe { core::ptr::write_volatile(arg as *mut u32, v); }
            }
            Some(0)
        }
        vt::KDSKBMODE => {
            let mode = arg as u32;
            match vt::set_kb_mode(vt_target, mode) {
                Ok(()) => Some(0),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::KDGKBTYPE => {
            // KB_101 = 2; arg is u8 user pointer.
            if arg != 0 && arg < hal::USER_VA_END {
                // SAFETY: arg validated < USER_VA_END; single-byte store.
                unsafe { core::ptr::write_volatile(arg as *mut u8, 2u8); }
            }
            Some(0)
        }
        vt::VT_OPENQRY => {
            let id = match vt::openqry() { Ok(n) => n as u32, Err(_) => return Some(errno(Errno::Ebusy)) };
            if arg != 0 && arg < hal::USER_VA_END {
                // SAFETY: arg validated < USER_VA_END; aligned u32 store.
                unsafe { core::ptr::write_volatile(arg as *mut u32, id); }
            }
            Some(0)
        }
        vt::VT_GETSTATE => {
            let st = vt::get_state();
            if arg == 0 || arg + 6 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 6; struct vt_stat is 6 bytes.
            unsafe {
                core::ptr::write_volatile(arg as *mut u16, st.v_active);
                core::ptr::write_volatile((arg + 2) as *mut u16, st.v_signal);
                core::ptr::write_volatile((arg + 4) as *mut u16, st.v_state);
            }
            Some(0)
        }
        vt::VT_ACTIVATE => {
            let n = arg as u8;
            match vt::activate(n) {
                Ok(()) => Some(0),
                Err(vt::Error::Busy) => Some(errno(Errno::Ebusy)),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::VT_WAITACTIVE => {
            // Synchronous (current single-CPU model): switch already
            // happened by the time VT_ACTIVATE returned, so this is
            // a no-op when n matches current; otherwise EINVAL.
            if (arg as u8) == vt::active() { Some(0) }
            else { Some(errno(Errno::Einval)) }
        }
        vt::VT_DISALLOCATE => {
            match vt::disallocate(arg as u8) {
                Ok(()) => Some(0),
                Err(vt::Error::Busy) => Some(errno(Errno::Ebusy)),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::VT_LOCKSWITCH | vt::VT_UNLOCKSWITCH => {
            let lock = req == vt::VT_LOCKSWITCH;
            match vt::lock_switch(vt_target, lock) {
                Ok(()) => Some(0),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        // KIOCSOUND / KDMKTONE / KDADDIO — accept silently or EPERM.
        vt::KIOCSOUND | vt::KDMKTONE => Some(0),
        vt::KDADDIO => Some(errno(Errno::Eperm)),
        _ => None,
    }
}
