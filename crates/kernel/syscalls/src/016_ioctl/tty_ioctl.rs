#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};
use tty::ioctl::req as tty_req;

use super::vt::handle_vt_ioctl;

// Module manifest:
// - `session`: TIOCSCTTY / TIOCGSID / TIOCNOTTY + the modem-control family.
#[path = "tty_ioctl/session.rs"]
mod session;

const TCGETS: u64 = tty_req::TCGETS as u64;
const TCSETS: u64 = tty_req::TCSETS as u64;
const TCSETSW: u64 = tty_req::TCSETSW as u64;
const TCSETSF: u64 = tty_req::TCSETSF as u64;
const TCXONC: u64 = tty_req::TCXONC as u64;
const TCFLSH: u64 = tty_req::TCFLSH as u64;
const TIOCEXCL: u64 = tty_req::TIOCEXCL as u64;
const TIOCNXCL: u64 = tty_req::TIOCNXCL as u64;
const TIOCGEXCL: u64 = tty_req::TIOCGEXCL as u64;
const TIOCGWINSZ: u64 = tty_req::TIOCGWINSZ as u64;
const TIOCSWINSZ: u64 = tty_req::TIOCSWINSZ as u64;
const TIOCGPTN: u64 = tty_req::TIOCGPTN as u64;
const TIOCSPTLCK: u64 = tty_req::TIOCSPTLCK as u64;
const TIOCPKT: u64 = tty_req::TIOCPKT as u64;
const TIOCGPKT: u64 = tty_req::TIOCGPKT as u64;
const TIOCGPTLCK: u64 = tty_req::TIOCGPTLCK as u64;
const TIOCGPTPEER: u64 = tty_req::TIOCGPTPEER as u64;
const TIOCSIG: u64 = tty_req::TIOCSIG as u64;
const TIOCOUTQ: u64 = tty_req::TIOCOUTQ as u64;
const FIONREAD: u64 = tty_req::FIONREAD as u64;
const TIOCSETD: u64 = tty_req::TIOCSETD as u64;
const TIOCGETD: u64 = tty_req::TIOCGETD as u64;
const TIOCGPGRP: u64 = tty_req::TIOCGPGRP as u64;
const TIOCSPGRP: u64 = tty_req::TIOCSPGRP as u64;
const TIOCSCTTY: u64 = tty_req::TIOCSCTTY as u64;
const TIOCNOTTY: u64 = tty_req::TIOCNOTTY as u64;
const TIOCGSID: u64 = tty_req::TIOCGSID as u64;
// Modem-control bits (DTR/RTS/CD/RI/DSR/CTS). The serial/VT console
// models a software modem register (TIOCMGET reflects prior
// TIOCMSET/BIS/BIC; carrier strapped active). A pty has no modem
// lines → ENOTTY (Linux `pty` has no `tiocmget`/`tiocmset`). getty
// issues TIOCMGET to confirm carrier-detect before the login banner.
const TIOCMGET: u64 = tty_req::TIOCMGET as u64;
const TIOCMBIS: u64 = tty_req::TIOCMBIS as u64;
const TIOCMBIC: u64 = tty_req::TIOCMBIC as u64;
const TIOCMSET: u64 = tty_req::TIOCMSET as u64;
// Linux TCGETS/TCSETS use the kernel UAPI `struct termios`, not glibc's
// public 60-byte `struct termios`. On x86_64 the ioctl payload is:
// c_iflag/c_oflag/c_cflag/c_lflag (4*4), c_line (1), c_cc[19] = 36 B.
const KERNEL_TERMIOS_BYTES: usize = tty::pty::TERMIOS_OFF_CC + tty::pty::NCCS;

/// The resolved console tty, or an immediate ENOTTY return. Re-checks rather
/// than unwrapping so no branch can fall back to a fabricated VT.
macro_rules! con_tty {
    ($con:expr) => {
        match $con { Some(t) => t, None => return -(Errno::Enotty.as_i32() as i64) }
    };
}

pub(super) fn handle_tty_ioctl(
    cur: &sched::Task,
    file: &vfs::File,
    fdt: &vfs::FdTable,
    _fd: i32,
    req: u64,
    arg: u64,
) -> i64 {
    // KD_*/VT_* ioctls on /dev/tty<N> + /dev/tty0 + /dev/console
    // route through the vt crate.
    if let Some(rv) = handle_vt_ioctl(file.inode(), req, arg) {
        return rv;
    }
    let inode = file.inode();
    let pty_pair = devpts::pair_for_inode(inode);
    let pty_master = devpts::is_master_inode(inode);
    // Linux reaches `tty_ioctl` only through `tty_fops`; a description whose
    // `f_op` has no `->unlocked_ioctl` gets `-ENOTTY` from `vfs_ioctl`, and
    // `signalfd`/`eventfd` declare none while `timerfd`/`inotify` return
    // `-ENOTTY` from their handler's default arm. This handler is the ioctl
    // dispatcher's unclaimed-CharDev fallback, so it must apply that rule
    // itself: an inode that is neither a pty endpoint nor a console tty is not
    // a terminal, whatever its number. It used to be answered from a video VT
    // derived from the inode's low byte.
    let con = console::route(inode);
    if pty_pair.is_none() && con.is_none() { return -(Errno::Enotty.as_i32() as i64); }

    match req {
        TIOCGWINSZ => {
            if let Err(rv) = validate_user_buf(arg, 8, 2) { return rv; }
            // PTY fds: read from the pair's stored winsize. The serial
            // system console (vt<=1) owns its winsize on the TtyStruct
            // (T8 — was the dead fixed default). Numbered VTs report the
            // 24×80 default until the per-VT screen buffers land.
            let ws = match &pty_pair {
                Some(pair) => pair.with_pair(|p| p.winsize),
                None => match con_tty!(con) {
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
                None => match con_tty!(con) {
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
                // Linux `tty_do_resize` -> `kill_pgrp(pgrp, SIGWINCH, 1)`:
                // kernel-generated, PROCESS-directed.
                for t in sched::live::registry::tasks_in_pgrp(fg) {
                    sched::live::send_sig_priv_group(&t, sched::Signum::Sigwinch as u32);
                }
            }
            0
        }
        TCGETS => {
            if let Err(rv) = validate_user_buf_writable(arg, KERNEL_TERMIOS_BYTES as u64, 4) { return rv; }
            // For pty fds copy the pair's termios image; for the serial line
            // and /dev/tty<N> read the resolved tty's own termios state.
            let snap = match &pty_pair {
                Some(pair) => pair.with_pair(|p| p.termios),
                None => match con_tty!(con) {
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
                pair.with_pair(|p| p.set_termios(buf));
                // TCSETSF also discards unread input (Linux `tcsetattr`
                // TCSAFLUSH). agetty sets the line params with TCSETSF to
                // drop any type-ahead/answerback before the login prompt.
                if req == TCSETSF { pair.with_pair(|p| p.flush_slave(true, false)); }
            } else {
                // login ECHO-off + bash raw mode must reach the resolved
                // tty's N_TTY ldisc. TCSETSF also flushes input.
                match con_tty!(con) {
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
                match con_tty!(con) {
                    console::TtyTarget::Serial => console::static_console::flush(sel),
                    console::TtyTarget::Vt(vt) => console::vt_tty::vt_tty(vt).flush(sel),
                }
            }
            0
        }
        TIOCEXCL | TIOCNXCL => {
            let on = req == TIOCEXCL;
            if let Some(pair) = &pty_pair {
                pair.set_exclusive(pty_master, on);
            } else {
                match con_tty!(con) {
                    console::TtyTarget::Serial => console::static_console::set_exclusive(on),
                    console::TtyTarget::Vt(vt) => console::vt_tty::vt_tty(vt).set_exclusive(on),
                }
            }
            0
        }
        TIOCGEXCL => {
            if let Err(rv) = validate_user_buf_writable(arg, 4, 4) { return rv; }
            let excl = if let Some(pair) = &pty_pair {
                pair.exclusive(pty_master)
            } else {
                match con_tty!(con) {
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
                match con_tty!(con) {
                    console::TtyTarget::Serial => console::static_console::flow(action),
                    console::TtyTarget::Vt(vt) => { console::vt_tty::vt_tty(vt).flow(action); }
                }
            }
            0
        }
        TIOCGPTN => {
            if !pty_master { return -(Errno::Enotty.as_i32() as i64); }
            if let Err(rv) = validate_user_buf_writable(arg, tty_req::INT_BYTES, tty_req::INT_BYTES) { return rv; }
            // SAFETY: arg validated 4-byte aligned; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut u32, pty_pair.as_ref().map(|p| p.pts_num()).unwrap_or_default()); }
            0
        }
        TIOCSPTLCK => {
            // Master-side pts lock toggle (glibc/musl unlockpt = arg 0).
            if !pty_master { return -(Errno::Enotty.as_i32() as i64); }
            if let Err(rv) = validate_user_buf(arg, tty_req::INT_BYTES, tty_req::INT_BYTES) { return rv; }
            // SAFETY: arg validated 4-byte aligned; CPL=0 read through caller's AS.
            let v = unsafe { core::ptr::read_volatile(arg as *const i32) };
            match &pty_pair {
                Some(pair) => { pair.set_locked(v != 0); 0 }
                None => -(Errno::Enotty.as_i32() as i64),
            }
        }
        TIOCGPTLCK => {
            if !pty_master { return -(Errno::Enotty.as_i32() as i64); }
            if let Err(rv) = validate_user_buf_writable(arg, tty_req::INT_BYTES, tty_req::INT_BYTES) { return rv; }
            let locked = match &pty_pair {
                Some(pair) => pair.is_locked(),
                None => return -(Errno::Enotty.as_i32() as i64),
            };
            // SAFETY: arg validated 4-byte aligned; CPL=0 write through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut i32, locked as i32); }
            0
        }
        TIOCPKT => {
            // Packet mode is a Unix98 MASTER-only ioctl. VTE enables it
            // before creating the child so control events and ordinary
            // terminal bytes share one race-free read stream.
            if !pty_master { return -(Errno::Enotty.as_i32() as i64); }
            if let Err(rv) = validate_user_buf(arg, tty_req::INT_BYTES, tty_req::INT_BYTES) { return rv; }
            // SAFETY: arg validated readable for one Linux int input.
            let enabled = unsafe { core::ptr::read_volatile(arg as *const i32) } != 0;
            match &pty_pair {
                Some(pair) => { pair.with_pair(|p| p.set_master_packet(enabled)); 0 }
                None => -(Errno::Eio.as_i32() as i64),
            }
        }
        TIOCGPKT => {
            if !pty_master { return -(Errno::Enotty.as_i32() as i64); }
            if let Err(rv) = validate_user_buf_writable(arg, tty_req::INT_BYTES, tty_req::INT_BYTES) { return rv; }
            let enabled = match &pty_pair {
                Some(pair) => pair.with_pair(|p| p.master_packet_enabled()),
                None => return -(Errno::Eio.as_i32() as i64),
            };
            // SAFETY: arg is a validated writable Linux int buffer.
            unsafe { core::ptr::write_volatile(arg as *mut i32, enabled as i32); }
            0
        }
        TIOCSIG => {
            if !pty_master { return -(Errno::Enotty.as_i32() as i64); }
            let sig = match arg as u8 {
                v if v == sched::Signum::Sigint as u8 => sched::Signum::Sigint,
                v if v == sched::Signum::Sigquit as u8 => sched::Signum::Sigquit,
                v if v == sched::Signum::Sigtstp as u8 => sched::Signum::Sigtstp,
                _ => return -(Errno::Einval.as_i32() as i64),
            };
            let fg = match &pty_pair {
                Some(pair) => pair.with_pair(|p| p.foreground_pgid),
                None => return -(Errno::Eio.as_i32() as i64),
            };
            if fg != 0 {
                // Linux `n_tty_ioctl_helper`'s TIOCSTI/flush signal arms ->
                // `kill_pgrp(..., 1)`.
                for task in sched::live::registry::tasks_in_pgrp(fg) {
                    sched::live::send_sig_priv_group(&task, sig.as_u8() as u32);
                }
            }
            0
        }
        FIONREAD | TIOCOUTQ => {
            if let Err(rv) = validate_user_buf_writable(arg, tty_req::INT_BYTES, tty_req::INT_BYTES) { return rv; }
            let count = match &pty_pair {
                Some(pair) if req == FIONREAD => pair.with_pair(|p| p.readable_bytes(pty_master)),
                Some(pair) => pair.with_pair(|p| p.output_bytes(pty_master)),
                None => return -(Errno::Enotty.as_i32() as i64),
            };
            // SAFETY: arg is a validated writable Linux int buffer.
            unsafe { core::ptr::write_volatile(arg as *mut i32, count as i32); }
            0
        }
        TIOCGETD => {
            if let Err(rv) = validate_user_buf_writable(arg, tty_req::INT_BYTES, tty_req::INT_BYTES) { return rv; }
            // SAFETY: arg is a validated writable Linux int buffer.
            unsafe { core::ptr::write_volatile(arg as *mut u32, tty_req::N_TTY); }
            0
        }
        TIOCSETD => {
            if let Err(rv) = validate_user_buf(arg, tty_req::INT_BYTES, tty_req::INT_BYTES) { return rv; }
            // SAFETY: arg is a validated readable Linux int buffer.
            let ldisc = unsafe { core::ptr::read_volatile(arg as *const u32) };
            if ldisc != tty_req::N_TTY { return -(Errno::Einval.as_i32() as i64); }
            0
        }
        TIOCGPTPEER => {
            // `TIOCGPTPEER` opens the slave belonging to THIS Unix98 master
            // without resolving `/dev/pts/<n>` in the caller's mount namespace.
            // Terminal emulators use it to create a pty safely before the
            // child changes namespaces; returning ENOTTY here aborts terminal
            // launch before the shell is ever spawned.
            if !pty_master { return -(Errno::Enotty.as_i32() as i64); }
            let pair = match &pty_pair {
                Some(pair) => pair,
                None => return -(Errno::Eio.as_i32() as i64),
            };
            if pair.is_locked() { return -(Errno::Eio.as_i32() as i64); }
            let flags = vfs::OpenFlags::from_bits_truncate(arg as u32);
            let (slave, dentry, peer_mnt_id) = match pair.slave_path() {
                Some(path) => path, None => return -(Errno::Eio.as_i32() as i64),
            };
            devpts::acquire_ctty_on_open(&slave, flags.bits());
            let cred = match crate::pathresolve::file_cred_for(cur) {
                Some(cred) => cred,
                None => return -(Errno::Esrch.as_i32() as i64),
            };
            let file = vfs::File::new_at(slave, dentry, flags - vfs::OpenFlags::O_CLOEXEC,
                peer_mnt_id, cred);
            if let Err(error) = file.open_hook() { return -(error as i64); }
            match fdt.alloc_limit(file, cur.nofile_soft()) {
                Ok(fd) => {
                    if flags.contains(vfs::OpenFlags::O_CLOEXEC) { let _ = fdt.set_cloexec(fd, true); }
                    fd as i64
                }
                Err(error) => -(error as i64),
            }
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
                let tgt = con_tty!(con);
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
        TIOCSCTTY | TIOCGSID | TIOCNOTTY | TIOCMGET | TIOCMSET | TIOCMBIS | TIOCMBIC =>
            session::handle(file, con, &pty_pair, req, arg),
        _ => {
            #[cfg(feature = "debug-boot")]
            {
                klog::write_raw(b"[pty ENOTTY] fd=");
                klog::write_dec_u64(_fd as u64);
                klog::write_raw(b" req=");
                klog::write_hex_u64(req);
                klog::write_raw(b" ino=");
                klog::write_dec_u64(file.inode().ino());
                if let Some(cur) = sched::live::current() {
                    klog::write_raw(b" comm=");
                    let comm = cur.comm_bytes();
                    klog::write_raw(sched::Task::comm_trim(&comm).as_bytes());
                }
                klog::write_raw(b"\n");
            }
            -(Errno::Enotty.as_i32() as i64)
        },
    }
}
