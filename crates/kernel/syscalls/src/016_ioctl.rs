// `sys_ioctl` per `15§5` / `28§5`. Split from `syscall_glue_fs.rs`
// to keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;

/// `sys_ioctl(fd, request, arg)` — slot 16.
/// # C: O(1)
pub fn sys_ioctl(args: &SyscallArgs) -> i64 {
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
    const TIOCNOTTY:  u64 = 0x5422;
    const TIOCGSID:   u64 = 0x5429;
    // Modem-control bits (DTR/RTS/CD/RI/DSR/CTS). For our v1 console
    // alias these are nominal — report all signals asserted on GET,
    // accept and ignore SETs / BISs / BICs. getty issues a
    // TIOCMGET to confirm carrier-detect before the login banner.
    const TIOCMGET:   u64 = 0x5415;
    const TIOCMBIS:   u64 = 0x5416;
    const TIOCMBIC:   u64 = 0x5417;
    const TIOCMSET:   u64 = 0x5418;
    let fd  = args.a0 as i32;
    // ioctl request numbers are conventionally 32-bit (Linux's
    // `_IO*` macros encode them in 32 bits). musl's userspace stub
    // passes them as `int`, so on x86_64 the upper 32 bits of rsi
    // can carry sign-extended garbage (e.g. TIOCGPTN = 0x80045430
    // sign-extends to 0xFFFFFFFF80045430). Mask to 32 bits so our
    // match arms compare correctly.
    let req = args.a1 & 0xFFFF_FFFF;
    let arg = args.a2;
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
    // pidfd ioctls (PIDFD_GET_INFO): route before the CharDev gate.
    // systemd verifies a forked service is its child via this ioctl;
    // ENOTTY makes it SIGKILL the child (console-getty respawn).
    if let Some(id) = crate::pidfd::tid_from_ino(file.inode().ino()) {
        return crate::pidfd::handle_pidfd_ioctl(id, req, arg);
    }
    // userfaultfd / perf ioctls: route through the dedicated handlers
    // before the CharDev gate (those inodes are tagged Regular).
    if (file.inode().ino() & 0xFFFF_FFFF_0000_0000) == 0x5546_4644_0000_0000 {
        return ::fs::userfaultfd::handle_uffd_ioctl(file.inode(), req, arg);
    }
    if (file.inode().ino() & 0xFFFF_FFFF_0000_0000) == 0x5045_5246_0000_0000 {
        return ::fs::perf::handle_perf_ioctl(file.inode(), req, arg);
    }
    // evdev ioctls.
    if let Some(rv) = drv_virtio_input::devfs::handle_evdev_ioctl(file.inode(), req, arg) {
        return rv;
    }
    // DRM/render fd ioctls.
    if let Some(rv) = fbdev::devfs::handle_fbdev_ioctl(file.inode(), req, arg) {
        return rv;
    }
    if let Some(rv) = drm::node::handle_drm_ioctl(file.inode(), req, arg) {
        return rv;
    }
    // B48: SIOC* network-iface ioctls on AF_INET / AF_INET6 sockets.
    // dhcpcd's whole bring-up dance uses SIOCGIFFLAGS / SIOCSIFFLAGS
    // / SIOCGIFADDR / SIOCSIFADDR / SIOCGIFINDEX / SIOCGIFHWADDR
    // / SIOCGIFMTU / SIOCGIFNETMASK / SIOCADDRT to probe + configure
    // eth0 before sending the DHCPDISCOVER.
    if (req & 0xFFFFFF00) == 0x00008900 {
        if let Some(rv) = crate::siocgif::handle_sioc(req, arg) {
            return rv;
        }
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
        devpts::pair_for((ino & 0x7FFF) as u32)
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
                for t in sched::live::registry::tasks_in_pgrp(fg) {
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
                    tty::live::termios_get(vt)
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
                tty::live::termios_set(vt, &buf);
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
                    let pgid = tty::live::foreground_pgid(vt);
                    // SAFETY: arg validated 4-byte aligned; CPL=0 writes.
                    unsafe { core::ptr::write_volatile(arg as *mut u32, pgid); }
                } else {
                    // SAFETY: arg validated 4-byte aligned; CPL=0 reads.
                    let pgid = unsafe { core::ptr::read_volatile(arg as *const u32) };
                    tty::live::set_foreground_pgid(vt, pgid);
                }
            }
            0
        }
        TIOCSCTTY => {
            // Make this fd's tty the controlling terminal for the
            // caller's session. v1 records sid on the VT but doesn't
            // enforce session-match checks on subsequent TIOCSPGRP.
            let cur = match sched::live::current() {
                Some(c) => c, None => return -(Errno::Eperm.as_i32() as i64),
            };
            // F200: store the inode on the calling task so /dev/tty
            // open can redirect to it.
            // SAFETY: single-mutator per `13§5` — running task on this CPU is the sole writer to ctty.
            unsafe { *cur.ctty.get() = Some(file.inode().clone()); }
            if let Some(pair) = &pty_pair {
                // F215: TIOCSCTTY must seed the slave's foreground
                // pgid with the calling session leader's pgid — Linux
                // POSIX: when a session leader acquires a controlling
                // terminal, the foreground process group is set to
                // the leader's process group. Without this,
                // tcgetpgrp(slave) returns 0 on the very first call
                // and any job-control shell (bash, dash)
                // kills itself with SIGTTIN before reading any input.
                use core::sync::atomic::Ordering;
                let pgid = cur.pgid.load(Ordering::Acquire);
                let sid  = cur.sid.load(Ordering::Acquire);
                pair.with_pair(|p| {
                    p.foreground_pgid = pgid;
                    p.session_pid = sid;
                });
                return 0;
            }
            let vt = (ino & 0xff) as u8;
            use core::sync::atomic::Ordering;
            tty::live::set_session(vt, cur.sid.load(Ordering::Acquire));
            // B18: mirror the PTY branch above — when a session
            // leader acquires a VT as its controlling terminal,
            // the foreground process group MUST be seeded with
            // the leader's pgrp. Without this, tcgetpgrp(0) on
            // the freshly-controlled VT returns 0, the shell's
            // job-control logic decides it's running in the
            // background, every read of stdin trips SIGTTIN,
            // and the shell stops itself the moment login's
            // post-fork_session execvp hands off. Symptom:
            // console login passes PAM and immediately respawns
            // getty — never reaches a usable shell prompt.
            tty::live::set_foreground_pgid(vt, cur.pgid.load(Ordering::Acquire));
            0
        }
        TIOCGSID => {
            // B40: getty calls `tcgetsid(STDIN_FILENO)` to
            // decide whether to TIOCSCTTY-steal. Linux returns the
            // session id that owns the tty, or ENOTTY when none does.
            // We track sid per VT (set on TIOCSCTTY); pty pairs track
            // it on the pair. Return 0/ENOTTY (rather than -EFAULT)
            // when no session has claimed yet so getty falls through
            // to the TIOCSCTTY path.
            if let Err(rv) = validate_user_buf(arg, 4, 4) { return rv; }
            let sid: u32 = if let Some(pair) = &pty_pair {
                pair.with_pair(|p| p.session_pid)
            } else {
                tty::live::session((ino & 0xff) as u8)
            };
            if sid == 0 { return -(Errno::Enotty.as_i32() as i64); }
            // SAFETY: arg validated 4-byte aligned; CPL=0 write through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut u32, sid); }
            0
        }
        TIOCNOTTY => {
            // B40: detach controlling tty for the calling session.
            // v1 clears the per-VT sid slot when the calling task
            // matches; ignored otherwise. getty issues this
            // to drop inherited ctty before its TIOCSCTTY-steal so a
            // real session leader doesn't already own the line.
            if pty_pair.is_some() { return 0; }
            let vt = (ino & 0xff) as u8;
            let cur = match sched::live::current() {
                Some(c) => c, None => return -(Errno::Eperm.as_i32() as i64),
            };
            use core::sync::atomic::Ordering;
            let my_sid = cur.sid.load(Ordering::Acquire);
            if my_sid != 0 && tty::live::session(vt) == my_sid {
                tty::live::set_session(vt, 0);
            }
            0
        }
        TIOCMGET => {
            // Nominal modem-status: DTR | RTS | CD | DSR | CTS all
            // asserted (matches a healthy serial console). Bits from
            // linux/include/uapi/asm-generic/termios.h.
            if let Err(rv) = validate_user_buf(arg, 4, 4) { return rv; }
            const TIOCM_LE:  u32 = 0x001;
            const TIOCM_DTR: u32 = 0x002;
            const TIOCM_RTS: u32 = 0x004;
            const TIOCM_CTS: u32 = 0x020;
            const TIOCM_CAR: u32 = 0x040;
            const TIOCM_DSR: u32 = 0x100;
            let bits = TIOCM_LE | TIOCM_DTR | TIOCM_RTS | TIOCM_CTS | TIOCM_CAR | TIOCM_DSR;
            // SAFETY: arg validated 4-byte aligned; CPL=0 write through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut u32, bits); }
            0
        }
        TIOCMSET | TIOCMBIS | TIOCMBIC => 0,
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
        vt::KDSIGACCEPT => {
            // systemd (manager.c) asks the kernel to deliver a signal on the
            // VT secure-attention keypress. We have no kbd-signal path; accept
            // as a no-op so PID1 doesn't warn "Failed to enable kbrequest".
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
