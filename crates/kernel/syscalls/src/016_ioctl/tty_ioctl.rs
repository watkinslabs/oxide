#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

use super::vt::handle_vt_ioctl;

const TCGETS:     u64 = 0x5401;
const TCSETS:     u64 = 0x5402;
const TCSETSW:    u64 = 0x5403; // TCSETS after pending output drains; v1 == TCSETS
const TCSETSF:    u64 = 0x5404; // TCSETS + flush unread input
const TCXONC:     u64 = 0x540A; // tcflow(): 0=TCOOFF 1=TCOON 2=TCIOFF 3=TCION
const TCFLSH:     u64 = 0x540B; // tcflush(): arg 0=TCIFLUSH 1=TCOFLUSH 2=TCIOFLUSH
const TIOCEXCL:   u64 = 0x540C;
const TIOCNXCL:   u64 = 0x540D;
const TIOCGEXCL:  u64 = 0x80045440;
const TIOCGWINSZ: u64 = 0x5413;
const TIOCSWINSZ: u64 = 0x5414;
const TIOCGPTN:   u64 = 0x80045430;
const TIOCSPTLCK: u64 = 0x40045431;
const TIOCGPTLCK: u64 = 0x80045439;
const TIOCGPGRP:  u64 = 0x540F;
const TIOCSPGRP:  u64 = 0x5410;
const TIOCSCTTY:  u64 = 0x540E;
const TIOCNOTTY:  u64 = 0x5422;
const TIOCGSID:   u64 = 0x5429;
// Modem-control bits (DTR/RTS/CD/RI/DSR/CTS). The serial/VT console
// models a software modem register (TIOCMGET reflects prior
// TIOCMSET/BIS/BIC; carrier strapped active). A pty has no modem
// lines → ENOTTY (Linux `pty` has no `tiocmget`/`tiocmset`). getty
// issues TIOCMGET to confirm carrier-detect before the login banner.
const TIOCMGET:   u64 = 0x5415;
const TIOCMBIS:   u64 = 0x5416;
const TIOCMBIC:   u64 = 0x5417;
const TIOCMSET:   u64 = 0x5418;
// Linux TCGETS/TCSETS use the kernel UAPI `struct termios`, not glibc's
// public 60-byte `struct termios`. On x86_64 the ioctl payload is:
// c_iflag/c_oflag/c_cflag/c_lflag (4*4), c_line (1), c_cc[19] = 36 B.
const KERNEL_TERMIOS_BYTES: usize = tty::pty::TERMIOS_OFF_CC + tty::pty::NCCS;

pub(super) fn handle_tty_ioctl(file: &vfs::File, _fd: i32, req: u64, arg: u64) -> i64 {
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
                // SIGWINCH is the canonical window-size notification signal.
                use core::sync::atomic::Ordering;
                for t in sched::live::registry::tasks_in_pgrp(fg) {
                    t.sigpending.fetch_or(sched::Signum::Sigwinch.bit(), Ordering::Release);
                    sched::live::signal_wake_up(&t);
                }
            }
            0
        }
        TCGETS => {
            if let Err(rv) = validate_user_buf_writable(arg, KERNEL_TERMIOS_BYTES as u64, 4) { return rv; }
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
            // SAFETY: arg validated kernel-termios-sized and aligned; CPL=0
            // writes through caller's AS. glibc converts this 36-byte kernel
            // UAPI image to its public 60-byte struct termios in userspace.
            unsafe {
                for i in 0..KERNEL_TERMIOS_BYTES {
                    core::ptr::write_volatile((arg + i as u64) as *mut u8, snap[i]);
                }
            }
            0
        }
        TCSETS | TCSETSW | TCSETSF => {
            if let Err(rv) = validate_user_buf(arg, KERNEL_TERMIOS_BYTES as u64, 4) { return rv; }
            let mut buf = [0u8; tty::pty::TERMIOS_BYTES];
            // SAFETY: arg validated kernel-termios-sized; CPL=0 reads through
            // caller's AS. Preserve the internal speed/padding tail.
            unsafe {
                for i in 0..KERNEL_TERMIOS_BYTES {
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
        TIOCEXCL | TIOCNXCL => {
            let on = req == TIOCEXCL;
            if let Some(pair) = &pty_pair {
                pair.set_exclusive((ino & 0x8000) == 0, on);
            } else {
                match console::route(ino) {
                    console::TtyTarget::Serial => console::static_console::set_exclusive(on),
                    console::TtyTarget::Vt(vt) => console::vt_tty::vt_tty(vt).set_exclusive(on),
                }
            }
            0
        }
        TIOCGEXCL => {
            if let Err(rv) = validate_user_buf_writable(arg, 4, 4) { return rv; }
            let excl = if let Some(pair) = &pty_pair {
                pair.exclusive((ino & 0x8000) == 0)
            } else {
                match console::route(ino) {
                    console::TtyTarget::Serial => console::static_console::exclusive(),
                    console::TtyTarget::Vt(vt) => console::vt_tty::vt_tty(vt).exclusive(),
                }
            };
            // SAFETY: arg validated 4-byte aligned; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut i32, excl as i32); }
            0
        }
        TCXONC => {
            // tcflow(): software flow control. TCOOFF(0) suspends output,
            // TCOON(1) resumes it, TCIOFF(2)/TCION(3) transmit a STOP/START
            // char to the input source. The output pair (TCOOFF/TCOON) is
            // the must-have: a suspended tty's WRITE path parks until
            // resumed (bash job-control / ^S). An out-of-range action is
            // EINVAL — never a fake success.
            let action = match tty::TtyFlow::from_arg(arg) {
                Some(a) => a,
                None => return -(Errno::Einval.as_i32() as i64),
            };
            if let Some(pair) = &pty_pair {
                // Slave-side pts: output-suspend withholds slave_write bytes
                // in the pair's out_hold (the same buffer ^S/^Q drive).
                // TCIOFF/TCION have no upstream to flow-control on a pts.
                match action {
                    tty::TtyFlow::OutputOff => { pair.with_pair(|p| p.flow_output(true)); }
                    tty::TtyFlow::OutputOn  => { pair.with_pair(|p| p.flow_output(false)); }
                    tty::TtyFlow::InputOff | tty::TtyFlow::InputOn => {}
                }
            } else {
                match console::route(ino) {
                    console::TtyTarget::Serial => console::static_console::flow(action),
                    console::TtyTarget::Vt(vt) => { console::vt_tty::vt_tty(vt).flow(action); }
                }
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
        TIOCSPTLCK => {
            // Master-side pts lock toggle (glibc/musl unlockpt = arg 0).
            if (ino & 0xFFFF_8000) != 0x6000_0000 { return -(Errno::Enotty.as_i32() as i64); }
            if let Err(rv) = validate_user_buf(arg, 4, 4) { return rv; }
            // SAFETY: arg validated 4-byte aligned; CPL=0 read through caller's AS.
            let v = unsafe { core::ptr::read_volatile(arg as *const i32) };
            match &pty_pair {
                Some(pair) => { pair.set_locked(v != 0); 0 }
                None => -(Errno::Enotty.as_i32() as i64),
            }
        }
        TIOCGPTLCK => {
            if (ino & 0xFFFF_8000) != 0x6000_0000 { return -(Errno::Enotty.as_i32() as i64); }
            if let Err(rv) = validate_user_buf(arg, 4, 4) { return rv; }
            let locked = match &pty_pair {
                Some(pair) => pair.is_locked(),
                None => return -(Errno::Enotty.as_i32() as i64),
            };
            // SAFETY: arg validated 4-byte aligned; CPL=0 write through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut i32, locked as i32); }
            0
        }
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
            // Linux: only a driver with `tiocmget` answers. Serial console
            // has one (software MCR); VT (vt.c) + pty have none → ENOTTY.
            if let Err(rv) = validate_user_buf(arg, 4, 4) { return rv; }
            if pty_pair.is_some() { return -(Errno::Enotty.as_i32() as i64); }
            let bits = match console::route(ino) {
                console::TtyTarget::Serial => console::static_console::modem_get(),
                console::TtyTarget::Vt(_)  => return -(Errno::Enotty.as_i32() as i64),
            };
            // SAFETY: arg validated 4-byte aligned; CPL=0 write through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut u32, bits); }
            0
        }
        TIOCMSET | TIOCMBIS | TIOCMBIC => {
            if let Err(rv) = validate_user_buf(arg, 4, 4) { return rv; }
            if pty_pair.is_some() { return -(Errno::Enotty.as_i32() as i64); }
            match console::route(ino) {
                console::TtyTarget::Serial => {
                    // SAFETY: arg validated 4-byte aligned; CPL=0 read through caller's AS.
                    let v = unsafe { core::ptr::read_volatile(arg as *const u32) };
                    match req {
                        TIOCMSET => console::static_console::modem_set(v),
                        TIOCMBIS => console::static_console::modem_bis(v),
                        _        => console::static_console::modem_bic(v),
                    }
                    0
                }
                console::TtyTarget::Vt(_) => -(Errno::Enotty.as_i32() as i64),
            }
        }
        _ => {
            #[cfg(feature = "debug-syscall")]
            {
                klog::write_raw(b"[ioctl] char ENOTTY fd=");
                klog::write_dec_u64(_fd as u64);
                klog::write_raw(b" req=");
                klog::write_hex_u64(req);
                klog::write_raw(b" ino=");
                klog::write_dec_u64(file.inode().ino());
                klog::write_raw(b" path=");
                let p = file.dentry().absolute_path();
                klog::write_raw(&p);
                klog::write_raw(b"\n");
            }
            -(Errno::Enotty.as_i32() as i64)
        },
    }
}
