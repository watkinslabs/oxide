// `sys_ioctl` per `15§5` / `28§5`. Split from `syscall_glue_fs.rs`
// to keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf;

/// VT_WAITACTIVE sleep queue: a task blocks here until a VT switch completes
/// (Linux `vt_event` / `vt_waitactive`). Woken by `vt_switch_wake`, which the
/// vt crate's switch-completion hook drives from `do_switch`.
static VT_SWITCH_WAIT: sched::live::WaitList = sched::live::WaitList::new();

/// Wake every task blocked in VT_WAITACTIVE. Registered (via
/// `vt::set_switch_hook`) as the vt switch-completion hook in kmain, so each
/// completed `do_switch` rouses the blocked waiters to re-check the active VT.
/// # C: O(N_waiters)
pub fn vt_switch_wake() { VT_SWITCH_WAIT.wake_all(); }

/// `sys_ioctl(fd, request, arg)` — slot 16.
/// # C: O(1)
pub fn sys_ioctl(args: &SyscallArgs) -> i64 {
    const TCGETS:     u64 = 0x5401;
    const TCSETS:     u64 = 0x5402;
    const TCSETSW:    u64 = 0x5403; // TCSETS after pending output drains; v1 == TCSETS
    const TCSETSF:    u64 = 0x5404; // TCSETS + flush unread input
    const TCXONC:     u64 = 0x540A; // tcflow(): 0=TCOOFF 1=TCOON 2=TCIOFF 3=TCION
    const TCFLSH:     u64 = 0x540B; // tcflush(): arg 0=TCIFLUSH 1=TCOFLUSH 2=TCIOFLUSH
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
            // PTY fds: read from the pair's stored winsize. The serial
            // system console (vt<=1) owns its winsize on the TtyStruct
            // (T8 — was the dead fixed default). Numbered VTs report the
            // 24×80 default until the per-VT screen buffers land.
            let ws = match &pty_pair {
                Some(pair) => pair.with_pair(|p| p.winsize),
                None => match console::route(ino) {
                    // Serial line: its own winsize (80×24 until the remote
                    // resizes). Video VT: the framebuffer cell grid.
                    console::TtyTarget::Serial => console::static_console::winsize_get(),
                    console::TtyTarget::Vt(vt) => console::vt_tty::vt_tty(vt).winsize(),
                },
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
                // Store on the resolved tty + raise SIGWINCH on its live fg
                // pgrp when it changed. Serial and video VT are independent.
                None => match console::route(ino) {
                    console::TtyTarget::Serial => {
                        let ch = console::static_console::winsize_set(ws);
                        (ch, console::static_console::foreground_pgid())
                    }
                    console::TtyTarget::Vt(vt) => {
                        let tty = console::vt_tty::vt_tty(vt);
                        (tty.set_winsize(ws), tty.fg_pgrp())
                    }
                },
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
                None => match console::route(ino) {
                    console::TtyTarget::Serial => console::static_console::termios_get(),
                    console::TtyTarget::Vt(vt) => console::vt_tty::vt_tty(vt).termios(),
                },
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
                // TCSETSF also discards unread input (Linux `tcsetattr`
                // TCSAFLUSH). agetty sets the line params with TCSETSF to
                // drop any type-ahead/answerback before the login prompt.
                if req == TCSETSF { pair.with_pair(|p| p.flush_slave(true, false)); }
            } else {
                // login ECHO-off + bash raw mode must reach the resolved
                // tty's N_TTY ldisc. TCSETSF also flushes input.
                match console::route(ino) {
                    console::TtyTarget::Serial => {
                        console::static_console::termios_set(&buf);
                        if req == TCSETSF { console::static_console::flush(tty::TtyFlush::Input); }
                    }
                    console::TtyTarget::Vt(vt) => {
                        console::vt_tty::vt_tty(vt).set_termios(&buf);
                        if req == TCSETSF { console::vt_tty::vt_tty(vt).flush(tty::TtyFlush::Input); }
                    }
                }
            }
            0
        }
        TCFLSH => {
            // tcflush(): discard queued I/O per the arg selector. agetty/
            // login/bash drop stale type-ahead + terminal-query answerback
            // (`ESC[r;cR`) before reading; without it the bytes contaminate
            // the username line → login fails → getty respawns (`28§4`).
            let sel = tty::TtyFlush::from_arg(arg);
            if let Some(pair) = &pty_pair {
                pair.with_pair(|p| p.flush_slave(sel.input(), sel.output()));
            } else {
                match console::route(ino) {
                    console::TtyTarget::Serial => console::static_console::flush(sel),
                    console::TtyTarget::Vt(vt) => console::vt_tty::vt_tty(vt).flush(sel),
                }
            }
            0
        }
        TCXONC => 0,
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
                let tgt = console::route(ino);
                if req == TIOCGPGRP {
                    let pgid = match tgt {
                        console::TtyTarget::Serial => console::static_console::foreground_pgid(),
                        console::TtyTarget::Vt(vt) => console::vt_tty::vt_tty(vt).fg_pgrp(),
                    };
                    // SAFETY: arg validated 4-byte aligned; CPL=0 writes.
                    unsafe { core::ptr::write_volatile(arg as *mut u32, pgid); }
                } else {
                    // SAFETY: arg validated 4-byte aligned; CPL=0 reads.
                    let pgid = unsafe { core::ptr::read_volatile(arg as *const u32) };
                    // Set the fg pgrp on the TtyStruct (+ driver shadow) so
                    // ISIG (^C) targets the live fg.
                    match tgt {
                        console::TtyTarget::Serial => console::static_console::set_foreground_pgid(pgid),
                        console::TtyTarget::Vt(vt) => console::vt_tty::set_fg_pgrp(vt, pgid),
                    }
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
            use core::sync::atomic::Ordering;
            let sid  = cur.sid.load(Ordering::Acquire);
            let pgid = cur.pgid.load(Ordering::Acquire);
            // B18: when a session leader acquires its controlling
            // terminal, the foreground process group MUST be seeded with
            // the leader's pgrp. Without this, tcgetpgrp(0) returns 0, the
            // shell decides it's a background job, every stdin read trips
            // SIGTTIN, and the shell stops itself right after login's
            // execvp — login passes PAM then respawns getty forever.
            match console::route(ino) {
                console::TtyTarget::Serial => console::static_console::set_session_and_fg(sid, pgid),
                console::TtyTarget::Vt(vt) => console::vt_tty::set_session_and_fg(vt, sid, pgid),
            }
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
                match console::route(ino) {
                    console::TtyTarget::Serial => console::static_console::session(),
                    console::TtyTarget::Vt(vt) => console::vt_tty::vt_tty(vt).sid(),
                }
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
            let cur = match sched::live::current() {
                Some(c) => c, None => return -(Errno::Eperm.as_i32() as i64),
            };
            use core::sync::atomic::Ordering;
            let my_sid = cur.sid.load(Ordering::Acquire);
            match console::route(ino) {
                console::TtyTarget::Serial => {
                    if my_sid != 0 && console::static_console::session() == my_sid {
                        console::static_console::notty();
                    }
                }
                console::TtyTarget::Vt(vt) => {
                    if my_sid != 0 && console::vt_tty::vt_tty(vt).sid() == my_sid {
                        console::vt_tty::notty(vt);
                    }
                }
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
            // Block until the active VT == n (Linux `vt_waitactive`): the
            // requested switch may be DEFERRED behind a VT_PROCESS owner's
            // VT_RELDISP, so this must sleep rather than EINVAL on a not-yet-
            // current target. Signal-interruptible (EINTR): the owner that
            // must field relsig + call VT_RELDISP is frequently the SAME task
            // blocked here, so the wait MUST yield to signal delivery or the
            // switch deadlocks.
            let n = arg as u8;
            if !(1..=63).contains(&n) { return Some(errno(Errno::Einval)); }
            use core::sync::atomic::Ordering;
            loop {
                if vt::active() == n { return Some(0); }
                let cur = match sched::live::current() {
                    Some(c) => c, None => return Some(errno(Errno::Einval)),
                };
                // Any unblocked pending signal interrupts the wait (mirrors the
                // poll/pselect6 EINTR check) so the dispatch tail can deliver it
                // — including the relsig the owner must answer with VT_RELDISP.
                let pending = cur.sigpending.load(Ordering::Acquire);
                let mask    = cur.sigmask.load(Ordering::Acquire);
                if pending & !mask != 0 { return Some(-(Errno::Eintr.as_i32() as i64)); }
                // park WITH a re-check deadline (not a bare park): the
                // active() check and the park are NOT under a shared lock, so a
                // do_switch completing in that window would wake an empty list
                // and the park would then miss it. The deadline bounds a missed
                // wake to RESCAN_NS of latency (the re-loop re-reads active())
                // instead of a hang — the same safety net poll/select use.
                const RESCAN_NS: u64 = 20_000_000; // 20ms
                let dl = crate::poll::poll_common::monotonic_ns().saturating_add(RESCAN_NS);
                // SAFETY: process ctx; preempt-off across the syscall; park_with_deadline marks the running task Sleeping on VT_SWITCH_WAIT + stamps the wake deadline; schedule yields; the re-loop re-reads active() on wake — woken by vt_switch_wake (do_switch) or the deadline scanner.
                unsafe {
                    VT_SWITCH_WAIT.park_with_deadline(dl);
                    sched::live::schedule();
                }
            }
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
        vt::VT_GETMODE => {
            let m = vt::slot(vt_target).map(|s| s.vt_mode).unwrap_or_default();
            if arg == 0 || arg + 8 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 8; struct vt_mode is 8 bytes (u8,u8,u16,u16,u16) written field-by-field into the caller's AS.
            unsafe {
                core::ptr::write_volatile(arg as *mut u8, m.mode);
                core::ptr::write_volatile((arg + 1) as *mut u8, m.waitv);
                core::ptr::write_volatile((arg + 2) as *mut u16, m.relsig);
                core::ptr::write_volatile((arg + 4) as *mut u16, m.acqsig);
                core::ptr::write_volatile((arg + 6) as *mut u16, m.frsig);
            }
            Some(0)
        }
        vt::VT_SETMODE => {
            if arg == 0 || arg + 8 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 8; reading the 8-byte struct vt_mode from the caller's AS field-by-field.
            let m = unsafe {
                vt::VtMode {
                    mode:   core::ptr::read_volatile(arg as *const u8),
                    waitv:  core::ptr::read_volatile((arg + 1) as *const u8),
                    relsig: core::ptr::read_volatile((arg + 2) as *const u16),
                    acqsig: core::ptr::read_volatile((arg + 4) as *const u16),
                    frsig:  core::ptr::read_volatile((arg + 6) as *const u16),
                }
            };
            // Record the calling process as the VT's controlling owner (Linux
            // vc->vt_pid): BOTH its namespace vpid (to signal) and its internal
            // tid (monotonic, never reused) so the handshake's liveness test is
            // immune to vpid reuse.
            let (vpid, tid) = sched::live::current()
                .map(|t| (t.vtgid.load(core::sync::atomic::Ordering::Acquire), t.tid))
                .unwrap_or((0, 0));
            match vt::set_vt_mode(vt_target, m, vpid, tid) {
                Ok(()) => Some(0),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::VT_RELDISP => {
            // The foreground VT_PROCESS owner answers a release request: arg>=1
            // allows a pending switch to complete, arg==0 refuses it. The vt
            // layer validates the caller IS that VT's recorded owner (vpid+tid)
            // — a non-owner that tries to ack/cancel another's switch gets
            // EPERM (Linux `vt_reldisp` ownership check).
            let (vpid, tid) = sched::live::current()
                .map(|t| (t.vtgid.load(core::sync::atomic::Ordering::Acquire), t.tid))
                .unwrap_or((0, 0));
            match vt::reldisp(arg as i32, vpid, tid) {
                Ok(()) => Some(0),
                Err(vt::Error::Perm) => Some(errno(Errno::Eperm)),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::KDGETLED | vt::KDGKBLED => {
            let leds = vt::slot(vt_target).map(|s| s.leds).unwrap_or(0) as u8;
            if arg != 0 && arg < hal::USER_VA_END {
                // SAFETY: arg validated < USER_VA_END; single-byte LED state store into caller's AS.
                unsafe { core::ptr::write_volatile(arg as *mut u8, leds); }
            }
            Some(0)
        }
        vt::KDSETLED | vt::KDSKBLED => {
            // arg = LED bitmask by value (Scroll=1,Num=2,Caps=4); 0xff means
            // "revert to the default kbd-driven state" — no LED hardware, so
            // store the bits (0 on revert).
            let leds = if (arg as u32) == 0xff { 0 } else { (arg as u32) & 0x7 };
            match vt::set_leds(vt_target, leds) {
                Ok(()) => Some(0),
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::VT_RESIZE | vt::VT_RESIZEX => {
            // vt_sizes { u16 v_rows, v_cols, ... } / vt_consize { u16 v_rows,
            // v_cols, ... } — both lead with rows then cols.
            if arg == 0 || arg + 4 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 4; reading the leading 2×u16 (rows, cols) of the resize struct from the caller's AS.
            let (rows, cols) = unsafe {
                (core::ptr::read_volatile(arg as *const u16),
                 core::ptr::read_volatile((arg + 2) as *const u16))
            };
            match vt::resize(vt_target, rows, cols) {
                Ok(()) => { vt_apply_winsize(rows, cols); Some(0) }
                Err(_) => Some(errno(Errno::Einval)),
            }
        }
        vt::TIOCLINUX => Some(handle_tioclinux(arg)),
        // Linux's vt_ioctl() has NO case for VT_SENDSIG: it falls through to
        // ENOIOCTLCMD → the tty layer maps that to ENOTTY/EINVAL. Mirror that
        // deliberately (parity decision, not a silent gap) — do not invent a
        // behaviour Linux itself does not implement.
        vt::VT_SENDSIG => Some(errno(Errno::Einval)),
        // Font + unicode-map (setfont): own handler.
        vt::KDFONTOP | vt::PIO_UNIMAP | vt::GIO_UNIMAP | vt::PIO_UNIMAPCLR => {
            handle_font_ioctl(req, arg)
        }
        // KIOCSOUND / KDMKTONE / KDADDIO — accept silently or EPERM.
        vt::KIOCSOUND | vt::KDMKTONE => Some(0),
        vt::KDADDIO => Some(errno(Errno::Eperm)),
        _ => None,
    }
}

/// True if `[ptr, ptr+len)` lies wholly in the userspace VA window. Mirrors the
/// `arg==0 || arg>=USER_VA_END` guard used across this file but for a multi-byte
/// span (used by the TIOCLINUX struct reads/writes). # C: O(1)
fn user_ok(ptr: u64, len: u64) -> bool {
    ptr != 0 && len != 0 && ptr.checked_add(len).map_or(false, |end| end <= hal::USER_VA_END)
}

/// TIOCLINUX (Linux `tty_io.c` → `vt.c tioclinux`): `*arg[0]` is the
/// subfunction selector; the rest of the layout depends on it. Operates on the
/// FOREGROUND console (Linux uses `fg_console` for the screen subfunctions).
/// Returns the syscall result (0 / -errno / a value for GET subfunctions).
/// Unknown subfunction → EINVAL (never a faked success). # C: O(rows*cols) on
/// SETSEL, else O(1).
fn handle_tioclinux(arg: u64) -> i64 {
    use syscall::errno::Errno;
    let errno = |e: Errno| -(e.as_i32() as i64);
    if !user_ok(arg, 1) { return errno(Errno::Efault); }
    // SAFETY: arg validated in-userspace for 1 byte; CPL=0 read of the subfunction selector from the caller's AS.
    let sub = unsafe { core::ptr::read_volatile(arg as *const u8) };
    match sub {
        vt::tiocl::TIOCL_SETSEL => {
            // struct tiocl_selection { u16 xs, ys, xe, ye, sel_mode; } at arg+2.
            if !user_ok(arg, 2 + 10) { return errno(Errno::Efault); }
            // SAFETY: arg validated in-userspace for 12 bytes; read the 5×u16 selection rectangle from the caller's AS.
            let (xs, ys, xe, ye, mode) = unsafe {(
                core::ptr::read_volatile((arg + 2) as *const u16),
                core::ptr::read_volatile((arg + 4) as *const u16),
                core::ptr::read_volatile((arg + 6) as *const u16),
                core::ptr::read_volatile((arg + 8) as *const u16),
                core::ptr::read_volatile((arg + 10) as *const u16),
            )};
            // Linux SETSEL coords are 1-based (xs/ys start at 1); normalise to
            // 0-based grid cells. A 0 stays 0 (clamped by resolve_selection).
            let z = |v: u16| v.saturating_sub(1);
            let (rows, cols) = match fbcon::kernel::console_dims() {
                Some(d) => d, None => return errno(Errno::Einval),
            };
            let (start, end) = match vt::tiocl::resolve_selection(z(xs), z(ys), z(xe), z(ye), mode, rows, cols) {
                Some(r) => r, None => return errno(Errno::Einval),
            };
            // Glyph dump of the fg screen (rows*cols Latin-1 bytes).
            let screen = fbcon::kernel::screen_dump(false);
            if screen.is_empty() { vt::tiocl::set_selection(alloc::vec::Vec::new()); return 0; }
            let lut = vt::tiocl::sel_lut();
            let (s, e) = if mode == vt::tiocl::TIOCL_SELWORD {
                vt::tiocl::widen_to_words(&screen, &lut, cols, start, end)
            } else { (start, end) };
            // Extract the cells [s, e] inclusive, inserting a newline at each
            // row boundary (Linux `sel_buffer` appends '\r' at EOL of a
            // multi-line char/line selection; we emit '\n' so a paste reads as
            // typed lines). Trailing blanks per row are trimmed (Linux does the
            // same via `clear_selection` / the `set_selection` space-trim).
            let e = e.min(screen.len().saturating_sub(1));
            let s = s.min(e);
            let mut out: alloc::vec::Vec<u8> = alloc::vec::Vec::new();
            let cols_u = cols as usize;
            let mut i = s;
            while i <= e {
                let row_end = (i / cols_u) * cols_u + (cols_u - 1);
                let line_end = row_end.min(e);
                // trim trailing spaces on this row's slice
                let mut j = line_end;
                while j >= i && screen[j] == b' ' { if j == i { break; } j -= 1; }
                let upto = if screen[j] == b' ' { i } else { j + 1 };
                out.extend_from_slice(&screen[i..upto]);
                if line_end < e { out.push(b'\n'); }
                i = row_end + 1;
            }
            vt::tiocl::set_selection(out);
            0
        }
        vt::tiocl::TIOCL_PASTESEL => {
            // Inject the stored selection into the fg console's tty INPUT,
            // byte-by-byte through the same path the keyboard uses (Linux
            // `paste_selection` → `tty_insert_flip_*`).
            let sel = vt::tiocl::selection();
            for &b in sel.iter() { tty::live::input_push_byte(b); }
            0
        }
        vt::tiocl::TIOCL_UNBLANKSCREEN => { vt::unblank(); 0 }
        vt::tiocl::TIOCL_SELLOADLUT => {
            // arg+4 holds 32 bytes (256 bits) of word-select char-class LUT.
            if !user_ok(arg, 4 + 32) { return errno(Errno::Efault); }
            let mut lut = [0u8; 32];
            // SAFETY: arg validated in-userspace for 36 bytes; read the 32-byte word-select LUT from the caller's AS.
            unsafe { for i in 0..32 { lut[i] = core::ptr::read_volatile((arg + 4 + i as u64) as *const u8); } }
            vt::tiocl::set_sel_lut(lut);
            0
        }
        vt::tiocl::TIOCL_GETSHIFTSTATE => {
            // Linux writes the shift-state byte to ((char*)arg)[1].
            if !user_ok(arg, 2) { return errno(Errno::Efault); }
            let bits = vt::tiocl::linux_shift_state(drv_virtio_input::keymap::mods().bits());
            // SAFETY: arg validated in-userspace for 2 bytes; CPL=0 write of the shift-state byte into ((char*)arg)[1].
            unsafe { core::ptr::write_volatile((arg + 1) as *mut u8, bits); }
            0
        }
        vt::tiocl::TIOCL_SETVESABLANK => {
            // arg+1 = blank interval (minutes). No hw blank timer; store it.
            if !user_ok(arg, 2) { return errno(Errno::Efault); }
            // SAFETY: arg validated in-userspace for 2 bytes; read the VESA blank-interval byte from the caller's AS.
            let mins = unsafe { core::ptr::read_volatile((arg + 1) as *const u8) } as u32;
            vt::tiocl::set_blank_interval(mins);
            0
        }
        vt::tiocl::TIOCL_SETKMSGREDIRECT => {
            // arg+1 = target VT for kernel printk redirect. Store it.
            if !user_ok(arg, 2) { return errno(Errno::Efault); }
            // SAFETY: arg validated in-userspace for 2 bytes; read the kmsg-redirect target VT byte from the caller's AS.
            let vt = unsafe { core::ptr::read_volatile((arg + 1) as *const u8) };
            vt::tiocl::set_kmsg_redirect(vt);
            0
        }
        vt::tiocl::TIOCL_GETFGCONSOLE => {
            // 0-based fg console index, returned as the syscall value (Linux
            // tioclinux returns `fg_console`).
            vt::active().saturating_sub(1) as i64
        }
        vt::tiocl::TIOCL_SCROLLCONSOLE => {
            // arg+1 = s32 lines delta (Linux `scrollfront`/`scrollback`).
            if !user_ok(arg, 1 + 4) { return errno(Errno::Efault); }
            // SAFETY: arg validated in-userspace for 5 bytes; read the s32 scroll-lines delta from the caller's AS.
            let lines = unsafe { core::ptr::read_volatile((arg + 1) as *const i32) };
            vt::scrolldelta(lines as isize);
            0
        }
        vt::tiocl::TIOCL_BLANKSCREEN => { vt::blank(); 0 }
        vt::tiocl::TIOCL_BLANKEDSCREEN => {
            // Return the blank-flag state as the syscall value (Linux returns
            // `console_blanked`).
            if vt::tiocl::blanked() { 1 } else { 0 }
        }
        vt::tiocl::TIOCL_GETKMSGREDIRECT => {
            // Return the stored kmsg-redirect target VT as the syscall value.
            vt::tiocl::kmsg_redirect() as i64
        }
        _ => errno(Errno::Einval),
    }
}

/// KDFONTOP + PIO/GIO_UNIMAP — the `setfont` font + unicode-map path
/// (Linux `con_font_op` / `con_set_unimap`). KDFONTOP loads/reads the glyph
/// bitmaps (32 bytes/glyph buffer); the unicode map is set separately by
/// PIO_UNIMAP (codepoint→glyph-index), so `conv_uni_to_pc` follows a custom
/// font. # C: O(charcount*height) on a font load.
fn handle_font_ioctl(req: u64, arg: u64) -> Option<i64> {
    use syscall::errno::Errno;
    let errno = |e: Errno| -(e.as_i32() as i64);
    const STRIDE: usize = 32;       // KDFONTOP: 32 bytes per glyph
    const MAX_GLYPHS: u32 = 512;
    const MAX_UNI: usize = 8192;    // unimap entry cap (sanity bound)
    match req {
        vt::KDFONTOP => {
            // struct console_font_op { u32 op,flags,width,height,charcount;
            // u8 *data; } — `data` is 8-byte aligned → offset 24 (4 bytes pad
            // after charcount@16); struct size 32.
            if arg == 0 || arg + 32 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 32; read the console_font_op fields from the caller's AS at their padded offsets.
            let (op, width, height, charcount, data_ptr) = unsafe {(
                core::ptr::read_volatile(arg as *const u32),
                core::ptr::read_volatile((arg + 8) as *const u32),
                core::ptr::read_volatile((arg + 12) as *const u32),
                core::ptr::read_volatile((arg + 16) as *const u32),
                core::ptr::read_volatile((arg + 24) as *const u64),
            )};
            match op {
                vt::KD_FONT_OP_SET => {
                    if charcount == 0 || charcount > MAX_GLYPHS { return Some(errno(Errno::Einval)); }
                    let bytes = charcount as usize * STRIDE;
                    if data_ptr == 0 || data_ptr + bytes as u64 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
                    let mut buf = alloc::vec![0u8; bytes];
                    // SAFETY: data_ptr validated for `bytes`; copy the glyph bitmaps from the caller's AS.
                    unsafe { for i in 0..bytes { buf[i] = core::ptr::read_volatile((data_ptr + i as u64) as *const u8); } }
                    match fbcon::font::set_font(width, height, charcount, STRIDE, &buf) {
                        Ok(()) => Some(0),
                        Err(()) => Some(errno(Errno::Einval)),
                    }
                }
                vt::KD_FONT_OP_GET => {
                    let (w, h, c, data) = fbcon::font::get_font(STRIDE);
                    // The caller's charcount is its buffer capacity (in glyphs).
                    if charcount < c {
                        // SAFETY: arg validated above; report the needed count.
                        unsafe { core::ptr::write_volatile((arg + 16) as *mut u32, c); }
                        return Some(errno(Errno::Enospc));
                    }
                    // SAFETY: arg validated; write back the real width/height/charcount.
                    unsafe {
                        core::ptr::write_volatile((arg + 8) as *mut u32, w);
                        core::ptr::write_volatile((arg + 12) as *mut u32, h);
                        core::ptr::write_volatile((arg + 16) as *mut u32, c);
                    }
                    let bytes = c as usize * STRIDE;
                    if data_ptr == 0 || data_ptr + bytes as u64 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
                    // SAFETY: data_ptr validated for `bytes`; copy glyph bitmaps out to the caller's AS.
                    unsafe { for i in 0..bytes.min(data.len()) { core::ptr::write_volatile((data_ptr + i as u64) as *mut u8, data[i]); } }
                    Some(0)
                }
                vt::KD_FONT_OP_SET_DEFAULT => { fbcon::font::set_default(); Some(0) }
                _ => Some(errno(Errno::Einval)), // KD_FONT_OP_COPY unsupported
            }
        }
        vt::PIO_UNIMAP => {
            // struct unimapdesc { u16 entry_ct; struct unipair *entries; } —
            // entries at offset 8 (64-bit alignment). unipair = {u16 unicode, u16 fontpos}.
            if arg == 0 || arg + 16 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 16; read entry_ct (u16) + entries ptr (u64) from the caller's AS.
            let (ct, entries) = unsafe {(
                core::ptr::read_volatile(arg as *const u16) as usize,
                core::ptr::read_volatile((arg + 8) as *const u64),
            )};
            if ct > MAX_UNI { return Some(errno(Errno::Einval)); }
            let span = ct as u64 * 4;
            if ct > 0 && (entries == 0 || entries + span >= hal::USER_VA_END) { return Some(errno(Errno::Efault)); }
            let mut pairs = alloc::vec::Vec::with_capacity(ct);
            for i in 0..ct {
                let p = entries + (i as u64) * 4;
                // SAFETY: entries validated for `span`; read each 4-byte unipair (unicode, fontpos) from the caller's AS.
                let (uni, pos) = unsafe {(
                    core::ptr::read_volatile(p as *const u16) as u32,
                    core::ptr::read_volatile((p + 2) as *const u16),
                )};
                pairs.push((uni, pos));
            }
            fbcon::font::set_unimap(&pairs);
            Some(0)
        }
        vt::GIO_UNIMAP => {
            if arg == 0 || arg + 16 >= hal::USER_VA_END { return Some(errno(Errno::Efault)); }
            // SAFETY: arg validated < USER_VA_END - 16; read the caller's buffer capacity (entry_ct) + dest ptr.
            let (cap, entries) = unsafe {(
                core::ptr::read_volatile(arg as *const u16) as usize,
                core::ptr::read_volatile((arg + 8) as *const u64),
            )};
            let map = fbcon::font::unimap();
            if cap < map.len() {
                // SAFETY: arg validated; report the needed entry count.
                unsafe { core::ptr::write_volatile(arg as *mut u16, map.len() as u16); }
                return Some(errno(Errno::Enomem));
            }
            let span = map.len() as u64 * 4;
            if !map.is_empty() && (entries == 0 || entries + span >= hal::USER_VA_END) { return Some(errno(Errno::Efault)); }
            for (i, &(uni, pos)) in map.iter().enumerate() {
                let p = entries + (i as u64) * 4;
                // SAFETY: entries validated for `span`; write each 4-byte unipair out to the caller's AS.
                unsafe {
                    core::ptr::write_volatile(p as *mut u16, uni as u16);
                    core::ptr::write_volatile((p + 2) as *mut u16, pos);
                }
            }
            // SAFETY: arg validated; write back the actual entry count.
            unsafe { core::ptr::write_volatile(arg as *mut u16, map.len() as u16); }
            Some(0)
        }
        vt::PIO_UNIMAPCLR => { fbcon::font::clear_unimap(); Some(0) }
        _ => None,
    }
}

/// VT_RESIZE/VT_RESIZEX side effect: push the new grid into the system
/// console winsize and raise SIGWINCH on its fg pgrp (Linux `vt_resize` →
/// tty winsize update + signal), so a full-screen app reflows.
/// # C: O(P) tasks in the fg pgrp.
fn vt_apply_winsize(rows: u16, cols: u16) {
    let ws = tty::pty::Winsize { rows, cols, xpixel: 0, ypixel: 0 };
    // VT_RESIZE targets the foreground VIDEO console, not the serial line.
    let fgvt = console::foreground_vt();
    let tty = console::vt_tty::vt_tty(fgvt);
    let changed = tty.set_winsize(ws);
    let fg = tty.fg_pgrp();
    if changed && fg != 0 {
        use core::sync::atomic::Ordering;
        // SIGWINCH = 28; bit (28-1) = 27.
        for t in sched::live::registry::tasks_in_pgrp(fg) {
            t.sigpending.fetch_or(1u64 << 27, Ordering::Release);
        }
    }
}
