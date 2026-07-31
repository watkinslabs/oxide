#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};
use tty::ioctl::req as tty_req;

use super::vt::handle_vt_ioctl;

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
    let ino = file.inode().ino();
    let pty_pair = devpts::pair_for_inode(ino);
    let pty_master = devpts::is_master_inode(ino);

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
                pair.with_pair(|p| p.set_termios(buf));
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
                pair.set_exclusive(pty_master, on);
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
                pair.exclusive(pty_master)
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
                use core::sync::atomic::Ordering;
                for task in sched::live::registry::tasks_in_pgrp(fg) {
                    task.sigpending.fetch_or(sig.bit(), Ordering::Release);
                    sched::live::signal_wake_up(&task);
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
            let slave = devpts::make_slave_inode(alloc::sync::Arc::clone(pair));
            devpts::acquire_ctty_on_open(&slave, flags.bits());
            let cred = match crate::pathresolve::file_cred_for(cur) {
                Some(cred) => cred,
                None => return -(Errno::Esrch.as_i32() as i64),
            };
            let dentry = vfs::dcache::d_alloc_pseudo("[pts]", slave.clone(), &crate::anon_dname::ANON_INODE_OPS);
            let file = vfs::File::new_at(slave, dentry, flags - vfs::OpenFlags::O_CLOEXEC, file.mnt_id(), cred);
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
            // F200: store the inode on the calling PROCESS so /dev/tty
            // open can redirect to it from any of its threads.
            cur.set_ctty(Some(file.inode().clone()));
            if let Some(pair) = &pty_pair {
                // F215: TIOCSCTTY must seed the slave's foreground
                // pgid with the calling session leader's pgid — Linux
                // POSIX: when a session leader acquires a controlling
                // terminal, the foreground process group is set to
                // the leader's process group. Without this,
                // tcgetpgrp(slave) returns 0 on the very first call
                // and any job-control shell (bash, dash)
                // kills itself with SIGTTIN before reading any input.
                let pgid = cur.pgid();
                let sid  = cur.sid();
                pair.with_pair(|p| {
                    p.foreground_pgid = pgid;
                    p.session_pid = sid;
                });
                return 0;
            }
            let sid  = cur.sid();
            let pgid = cur.pgid();
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
            // Linux `tty_jobctrl_ioctl` TIOCNOTTY (`drivers/tty/tty_jobctrl.c:578-582`):
            //     if (current->signal->tty != tty) return -ENOTTY;
            //     no_tty();   /* = disassociate_ctty(0) + proc_clear_tty(current) */
            //
            // The `proc_clear_tty(current)` half is what agetty depends on: it
            // runs TIOCNOTTY, closes every fd, then calls vhangup(2), and
            // expects the vhangup to be a NO-OP because it no longer holds a
            // controlling terminal. Clearing only the tty's sid slot — as this
            // handler used to — left `task.ctty` populated, so the following
            // vhangup revoked a console nobody asked it to touch.
            let cur = match sched::live::current() {
                Some(c) => c, None => return -(Errno::Enotty.as_i32() as i64),
            };
            use core::sync::atomic::Ordering;
            let ctty_ino = cur.ctty_ino();
            if ctty_ino != Some(ino) { return -(Errno::Enotty.as_i32() as i64); }
            let target = crate::tty_hangup::resolve(ino);
            // `disassociate_ctty(0)` returns immediately for a non-leader
            // (`tty_jobctrl.c:269-270`); only `proc_clear_tty` runs for it.
            let my_pid = { let v = cur.vtgid.load(Ordering::Acquire);
                if v != 0 { v } else { cur.tgid.load(Ordering::Acquire) } };
            let my_sid = cur.sid();
            if my_sid != 0 && my_sid == my_pid {
                if let Some(t) = &target {
                    // (1) SIGHUP + SIGCONT to the tty's foreground process group
                    // (`tty_jobctrl.c:277-286`, `on_exit == 0` so both go out).
                    let fg = crate::tty_hangup::foreground_pgrp(t);
                    if fg != 0 {
                        let bits = sched::Signum::Sighup.bit() | sched::Signum::Sigcont.bit();
                        for task in sched::live::registry::tasks_in_pgrp(fg) {
                            task.sigpending.fetch_or(bits, Ordering::Release);
                            sched::live::signal_wake_up(&task);
                        }
                    }
                    // (2) clear tty->ctrl.session / tty->ctrl.pgrp — detach, do
                    // NOT revoke: TIOCNOTTY is not a hangup.
                    crate::tty_hangup::clear_linkage(t);
                }
                // (3) `session_clear_tty(task_session(current))`: every member
                // of the session loses this terminal.
                tty::hangup::clear_session_ctty(ino, my_sid);
            }
            // `proc_clear_tty(tsk)` — unconditional, leader or not.
            cur.set_ctty(None);
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
