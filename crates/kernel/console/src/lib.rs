#![cfg(target_os = "oxide-kernel")]  // kernel-only crate (uses static_console/sched::live)
#![no_std]
#[macro_use] extern crate kmacros;
extern crate alloc;

// `/dev/console` + `/dev/tty<N>` char-devices per docs/16 + docs/28.
//
// `/dev/console`, `/dev/tty`, and `/dev/tty0` resolve to the foreground
// video VT by default. `/dev/ttyS0` is a separate serial tty. This mirrors
// Linux's device split: a machine can run a framebuffer console login and
// an independent serial login at the same time without mirroring user I/O.
//
// printk stays SEPARATE: kernel logs reach the UART via klog's serial
// sink (and mirror to fbcon); a tty write here goes TtyStruct → UART, NOT
// into the kmsg ring — the dmesg/shell-output split.
//
// init's fd 0/1/2 install a vt=0 (system console) ConsoleInode.

pub mod jobctl;
pub mod static_console;
pub mod vt_tty;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;

use tty::ReadOutcome;
use vfs::{Dentry, FdTable, File, FileType, Ino, Inode, InodeBuilder, InodeRef, KResult, OpenFlags, VfsError};
use vfs::{FileOps, default_inode_ops, mk_mode};

// --- device routing (Linux serial-vs-VT split) -------------------------
//
// Linux keeps the serial line and the video VTs as SEPARATE tty devices —
// they are NOT one console mirrored to two sinks. The char-device inode's
// low byte selects the backing tty:
//   0xFE  → the serial tty (`/dev/ttyS0`) — serial UART only.
//   0xFD  → the FOREGROUND video VT (`/dev/console`,`/dev/tty`,`/dev/tty0`).
//   1..63 → that numbered VT (`/dev/ttyN`).
// High bits 0x7400 keep these clear of the pty (0x6000_0000), vcs
// (0x7600/0x7700), fbdev (0xFB00) and pidfd (0xFF00_0000) ino ranges.

/// Console char-device ino base (low byte = device selector).
pub const TTY_INO_BASE: Ino = 0x7400;
/// Low-byte selector for the serial tty (`/dev/ttyS0`).
pub const SERIAL_INO_LB: u8 = 0xFE;
/// Low-byte selector for the foreground video VT (`/dev/console`/tty0).
pub const FG_VT_INO_LB: u8 = 0xFD;

/// Which backing tty a console char-device ino maps to.
pub enum TtyTarget {
    /// The serial UART tty (`static_console`).
    Serial,
    /// Video VT `n` (1-based) — `vt_tty(n)`.
    Vt(u8),
}

/// Resolve a console char-device ino to its backing tty (the Linux device
/// split). `0xFE` → serial; `0xFD` → foreground video VT; `1..63` → VT n.
/// # C: O(1)
pub fn route(ino: u64) -> TtyTarget {
    match (ino & 0xff) as u8 {
        SERIAL_INO_LB => TtyTarget::Serial,
        FG_VT_INO_LB  => TtyTarget::Vt(tty::live::foreground().max(1)),
        n             => TtyTarget::Vt(n),
    }
}

/// The current foreground video VT (1-based). `/dev/console` + the keyboard
/// follow this. # C: O(1)
pub fn foreground_vt() -> u8 { tty::live::foreground().max(1) }

/// True when `ino` is a console / serial / numbered-VT tty char-device inode
/// (the `0x7400..=0x74FF` band — `/dev/console`, `/dev/tty`, `/dev/tty0`,
/// `/dev/tty1..63`, `/dev/ttyS0`). Excludes vcs (`0x7600`/`0x7700`), pts
/// (`0x6000_0000`), fbdev, vcsa, and pidfd ranges. # C: O(1)
pub fn is_console_tty_ino(ino: Ino) -> bool {
    (ino & !0xFF) == TTY_INO_BASE
}

/// Linux `tty_open` controlling-terminal acquisition (`drivers/tty/tty_io.c`
/// `tty_open` → `__proc_set_tty`, POSIX §11.1.3). Called from the open(2)
/// path after a console/serial/VT tty char-device inode has been resolved.
///
/// When the caller is a session leader with NO controlling terminal, the
/// open flags do NOT carry `O_NOCTTY`, and the tty has no owning session,
/// make this tty the session's controlling terminal: record the inode on the
/// calling task (`task.ctty`) so `/dev/tty` resolves to it, claim the tty for
/// the leader's session (`tty->session`), and seed the tty's foreground
/// process group with the leader's pgrp (without which a job-control shell
/// trips SIGTTIN on its first read). No-op when O_NOCTTY is set, the inode is
/// not a console tty, the caller is not a session leader, the caller already
/// owns a ctty, or the tty already belongs to a session (a plain open never
/// steals — that needs TIOCSCTTY).
/// # C: O(1)
pub fn acquire_ctty_on_open(inode: &InodeRef, flags: u32) {
    use core::sync::atomic::Ordering;
    let ino = inode.ino();
    if !is_console_tty_ino(ino) { return; }
    let o_noctty = flags & OpenFlags::O_NOCTTY.bits() != 0;
    let cur = match sched::live::current() { Some(c) => c, None => return };
    // Session leader iff its session id equals its own (v)pid.
    let vpid = cur.vtgid.load(Ordering::Acquire);
    let my_pid = if vpid != 0 { vpid } else { cur.tid };
    let sid = cur.sid.load(Ordering::Acquire);
    let is_leader = sid != 0 && sid == my_pid;
    // SAFETY: single-mutator per `13§5` — running task on this CPU is the sole writer of ctty.
    let has_ctty = unsafe { (*cur.ctty.get()).is_some() };
    let tty_sid = match route(ino) {
        TtyTarget::Serial => static_console::session(),
        TtyTarget::Vt(vt) => vt_tty::vt_tty(vt).sid(),
    };
    if !tty::ctty::should_acquire_ctty(true, o_noctty, is_leader, has_ctty, tty_sid != 0) {
        return;
    }
    // Acquire: record on the task + claim the tty for this session, seeding
    // the fg pgrp with the leader's pgrp.
    let pgid = cur.pgid.load(Ordering::Acquire);
    // SAFETY: single-mutator per `13§5` — running task on this CPU is the sole writer of ctty.
    unsafe { *cur.ctty.get() = Some(inode.clone()); }
    match route(ino) {
        TtyTarget::Serial => static_console::set_session_and_fg(sid, pgid),
        TtyTarget::Vt(vt) => vt_tty::set_session_and_fg(vt, sid, pgid),
    }
}

// ---- VT console device: per-inode `vt` in `i_private`, shared `i_fop` ----

/// Backend-private state (`i_private`) for a VT console inode: which VT it
/// pins. `vt == 0` = foreground video VT (`/dev/console`/`/dev/tty`/
/// `/dev/tty0`), resolved at I/O time; `vt 1..=N_VT` pin a specific VT.
pub struct ConsoleData { vt: u8 }

/// Distinct inode numbers per VT so VFS-level introspection (`stat`/
/// `getdents` ino fields) reflects the underlying device. vt=0 = the
/// foreground-VT alias (low byte 0xFD); vt N = that VT (low byte N). # C: O(1)
fn console_ino(vt: u8) -> Ino {
    if vt == 0 { TTY_INO_BASE | FG_VT_INO_LB as Ino } else { TTY_INO_BASE | vt as Ino }
}
fn console_rdev(vt: u8) -> u32 { if vt == 0 { 0x0500 } else { 0x0400 | vt as u32 } }
fn console_perm(vt: u8) -> u16 { if vt == 0 { 0o666 } else { 0o620 } }

/// Build a VT console inode pinned to `vt`. Use 0 for the foreground-alias
/// (`/dev/console`, `/dev/tty`, `/dev/tty0`); 1..=N_VT for the per-VT slots.
/// # C: O(1)
pub fn make_console_inode(vt: u8) -> InodeRef {
    InodeBuilder::new(console_ino(vt), mk_mode(FileType::CharDev, console_perm(vt)),
        default_inode_ops(), Arc::new(ConsoleFileOps))
        .fsid(devfs::DEVFS_FSID).rdev(console_rdev(vt))
        .private(Arc::new(ConsoleData { vt }))
        .build()
}

/// Blocking read of VT `vt` (vt 0 → foreground VT). `ino` is the device's own
/// inode number (job-control gate). # C: backend-dependent
fn vt_read(vt: u8, ino: Ino, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() { return Ok(0); }
    // TtyStruct::read parks lost-wakeup-free and returns a cooked line
    // (Bytes), 0 on ^D (Eof), or Interrupted when an unblocked signal lands
    // during the blocking wait → -EINTR (Linux n_tty_read).
    let v = if vt == 0 { foreground_vt() } else { vt };
    let tty = vt_tty::vt_tty(v);
    jobctl::check(tty.fg_pgrp(), tty.sid(), ino,
        tty::pty::read_lflag(&tty.termios()), jobctl::Access::Read)?;
    match tty.read(buf) {
        ReadOutcome::Bytes(n) => Ok(n),
        ReadOutcome::Eof => Ok(0),
        ReadOutcome::Interrupted => Err(VfsError::Eintr),
    }
}

/// Non-blocking read of VT `vt` (empty ⇒ `Eagain`). # C: O(buf.len())
fn vt_read_nonblock(vt: u8, ino: Ino, buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() { return Ok(0); }
    let v = if vt == 0 { foreground_vt() } else { vt };
    let tty = vt_tty::vt_tty(v);
    jobctl::check(tty.fg_pgrp(), tty.sid(), ino,
        tty::pty::read_lflag(&tty.termios()), jobctl::Access::Read)?;
    let n = tty.read_nonblock(buf);
    if n == 0 { return Err(VfsError::Eagain); }
    Ok(n)
}

/// Readiness for poll/ppoll/select on VT `vt`. POLLIN only when input is
/// actually queued; always writable. # C: O(1)
fn vt_poll(vt: u8) -> u32 {
    let v = if vt == 0 { foreground_vt() } else { vt };
    vt_tty::vt_tty(v).poll()
}

/// Write `buf` to VT `vt`. The per-VT `TtyStruct` owns OPOST (ONLCR), then
/// `VtConsoleDriver::write` feeds the post-OPOST bytes to the fbcon emulator.
/// Does NOT touch the serial UART. # C: backend-dependent
fn vt_write(vt: u8, ino: Ino, buf: &[u8]) -> KResult<usize> {
    dtrace!(b"CW_IN", buf.len() as u64);
    let v = if vt == 0 { foreground_vt() } else { vt };
    let tty = vt_tty::vt_tty(v);
    jobctl::check(tty.fg_pgrp(), tty.sid(), ino,
        tty::pty::read_lflag(&tty.termios()), jobctl::Access::Write)?;
    let n = tty.write(buf);
    dtrace!(b"CW_OUT", n as u64);
    Ok(n)
}

/// `file_operations` for a VT console inode — recovers `vt` off `i_private`.
/// NOTE(kp2): the per-VT tty's `PollSubscribers` is NOT exposed (the struct
/// `Inode` only carries an OWNED `Option<PollSubscribers>`; there is no
/// FileOps hook to return a borrowed external list). epoll/poll targeted
/// wakes therefore fall back to the poll-loop's bounded 20 ms rescan net
/// (`007_poll.rs`) rather than instant `notify()`. Restoring the old
/// targeted wake needs a vfs follow-up: a `FileOps::poll_subscribers` hook
/// or an `Arc<PollSubscribers>`-shared inode field.
struct ConsoleFileOps;
impl FileOps for ConsoleFileOps {
    fn read(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let vt = console_data(inode)?.vt;
        vt_read(vt, inode.ino(), buf)
    }
    fn read_nonblock(&self, inode: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        let vt = console_data(inode)?.vt;
        vt_read_nonblock(vt, inode.ino(), buf)
    }
    fn poll(&self, inode: &Inode) -> u32 {
        match console_data(inode) { Ok(d) => vt_poll(d.vt), Err(_) => vfs::POLL_ERR }
    }
    fn write(&self, inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        let vt = console_data(inode)?.vt;
        vt_write(vt, inode.ino(), buf)
    }
}

/// Recover the VT console state from an inode's `i_private`. # C: O(1)
fn console_data(inode: &Inode) -> KResult<&ConsoleData> {
    inode.private::<ConsoleData>().ok_or(VfsError::Einval)
}

// ---- system console (`/dev/console` = the preferred `console=`) ----

/// `file_operations` for `/dev/console` — dispatches each op to the serial
/// tty or the foreground VT (vt 0) per the last `console=` on the cmdline.
struct SystemConsoleFileOps;
impl FileOps for SystemConsoleFileOps {
    fn read(&self, _i: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial_read(buf),
            cmdline::ConsoleKind::Vt(_)  => vt_read(0, console_ino(0), buf),
        }
    }
    fn read_nonblock(&self, _i: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial_read_nonblock(buf),
            cmdline::ConsoleKind::Vt(_)  => vt_read_nonblock(0, console_ino(0), buf),
        }
    }
    fn write(&self, _i: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => serial_write(buf),
            cmdline::ConsoleKind::Vt(_)  => vt_write(0, console_ino(0), buf),
        }
    }
    fn write_nonblock(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        // Default FileOps::write_nonblock forwards to write; keep that, but
        // serial write must still pass the job-control gate it owns.
        self.write(inode, off, buf)
    }
    fn poll(&self, _i: &Inode) -> u32 {
        match cmdline::preferred_console() {
            cmdline::ConsoleKind::Serial => static_console::poll(),
            cmdline::ConsoleKind::Vt(_)  => vt_poll(0),
        }
    }
}

/// Build the `/dev/console` (preferred-console, 5:1) inode. # C: O(1)
pub fn make_system_console_inode() -> InodeRef {
    InodeBuilder::new(TTY_INO_BASE | 0x01, mk_mode(FileType::CharDev, 0o600),
        default_inode_ops(), Arc::new(SystemConsoleFileOps))
        .fsid(devfs::DEVFS_FSID).rdev(0x0501)
        .build()
}

/// `/dev/ttyS0` — the serial UART tty, a SEPARATE device from the video
/// console. Serial-only: never renders to the framebuffer. Its winsize is
/// the serial-terminal default (80×24 until the remote sends SIGWINCH),
/// independent of the framebuffer geometry.
/// `/dev/ttyS0` inode number. # C: O(1)
fn serial_ino() -> Ino { TTY_INO_BASE | SERIAL_INO_LB as Ino }

#[cfg(target_arch = "x86_64")]
const SERIAL_RDEV: u32 = 0x0440;
#[cfg(target_arch = "aarch64")]
const SERIAL_RDEV: u32 = 0xcc40;

/// Job-control gate for ttyS0 (background-pgrp read/write of the controlling
/// serial tty). # C: O(pgrp size).
fn serial_jobctl(access: jobctl::Access) -> KResult<()> {
    jobctl::check(
        static_console::foreground_pgid(),
        static_console::session(),
        serial_ino(),
        tty::pty::read_lflag(&static_console::termios_get()),
        access,
    )
}

/// Blocking read of the serial tty. # C: backend-dependent
fn serial_read(buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() { return Ok(0); }
    serial_jobctl(jobctl::Access::Read)?;
    match static_console::read(buf) {
        ReadOutcome::Bytes(n) => Ok(n),
        ReadOutcome::Eof => Ok(0),
        ReadOutcome::Interrupted => Err(VfsError::Eintr),
    }
}
/// Non-blocking read of the serial tty (empty ⇒ `Eagain`). # C: backend-dependent
fn serial_read_nonblock(buf: &mut [u8]) -> KResult<usize> {
    if buf.is_empty() { return Ok(0); }
    serial_jobctl(jobctl::Access::Read)?;
    let n = static_console::read_nonblock(buf);
    if n == 0 { return Err(VfsError::Eagain); }
    Ok(n)
}
/// Write to the serial tty (job-control gated). # C: backend-dependent
fn serial_write(buf: &[u8]) -> KResult<usize> {
    serial_jobctl(jobctl::Access::Write)?;
    Ok(static_console::write(buf))
}

/// `file_operations` for `/dev/ttyS0` — the serial UART tty. NOTE(kp2): the
/// serial tty's `PollSubscribers` is not exposed (same vfs gap as the VT
/// console — see [`ConsoleFileOps`]); targeted epoll wakes degrade to the
/// poll-loop rescan net.
struct SerialFileOps;
impl FileOps for SerialFileOps {
    fn read(&self, _i: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { serial_read(buf) }
    fn read_nonblock(&self, _i: &Inode, _off: u64, buf: &mut [u8]) -> KResult<usize> { serial_read_nonblock(buf) }
    fn poll(&self, _i: &Inode) -> u32 { static_console::poll() }
    fn write(&self, _i: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { serial_write(buf) }
}

/// Build the `/dev/ttyS0` serial UART inode (`0o660`, arch-specific rdev).
/// A SEPARATE device from the video console (serial-only, own winsize).
/// # C: O(1)
pub fn make_serial_inode() -> InodeRef {
    InodeBuilder::new(serial_ino(), mk_mode(FileType::CharDev, 0o660), default_inode_ops(), Arc::new(SerialFileOps))
        .fsid(devfs::DEVFS_FSID).rdev(SERIAL_RDEV)
        .build()
}

/// Keyboard input sink: deliver one byte to the FOREGROUND video VT's tty
/// (Linux `kbd_keycode` → the fg console's `tty_port`). Routes to
/// `vt_tty(foreground())`, NOT the serial tty — the keyboard belongs to the
/// video console, the serial line gets its own RX (`drv_serial` → ttyS0).
/// Registered as the kbd sink at boot. # C: O(1) + waiter wake
pub fn kbd_input(b: u8) {
    vt_tty::vt_tty(foreground_vt()).receive_from_driver(&[b]);
}

/// Route a VT emulator's terminal answerback (DSR/CPR reply per `CSI n`)
/// into VT `vt`'s tty INPUT ring so the program that issued the query reads
/// its reply back — the Linux `respond_string` → `tty_insert_flip_string`
/// counterpart. Every VT (incl. the fg console) is a `vt_tty`; the serial
/// line answers via its remote terminal, not here. Registered with
/// `fbcon::kernel::set_reply_sink` at boot. # C: O(N) bytes + waiter wake
pub fn vt_reply_sink(vt: u8, bytes: &[u8]) {
    vt_tty::vt_tty(vt.max(1)).receive_from_driver(bytes);
}

/// Build the `init`-process fd table with fd 0/1/2 all pointing at
/// `/dev/console` — the *preferred console* per `console=`
/// ([`system_console_inode`]), so a kernel-spawned PID1 inherits the same
/// console device that userspace opens at `/dev/console`. Returns an
/// `Arc<FdTable>` ready to install on the spawned user task. # C: O(1)
pub fn init_console_fd_table() -> Arc<FdTable> {
    let table = Arc::new(FdTable::new());
    let inode: InodeRef = system_console_inode();
    // Full path so /proc/self/fd/{0,1,2} readlink to /dev/console
    // (the Linux contract) and symlink follow (/dev/stdout → fd/1 →
    // /dev/console) reopens the real node.
    let dentry = Dentry::new(None, "/dev/console".to_string(), inode.clone());
    let file = File::new(inode, dentry, OpenFlags::O_RDWR);
    // alloc returns the lowest-free fd; first three calls give
    // 0, 1, 2 in order.
    let _fd0 = table.alloc(file.clone());
    let _fd1 = table.alloc(file.clone());
    let _fd2 = table.alloc(file);
    table
}

/// `/dev/vcs` (text) + `/dev/vcsa` (text+attr) — the VT screen-dump devices
/// (Linux `drivers/tty/vt/vc_screen.c`). A read snapshots the FOREGROUND VT's
/// screen: `vcs` = `rows*cols` glyph bytes; `vcsa` = a 4-byte header
/// `[rows, cols, cursor_x, cursor_y]` then `[glyph, attr]` pairs. Read-only
/// here (writing the screen via vcs is not supported → EINVAL).
/// Backend-private state (`i_private`) for a vcs inode: `with_attr` selects
/// `/dev/vcsa` (text+attr) over `/dev/vcs` (text). # C: O(1)
pub struct VcsData { with_attr: bool }

/// `file_operations` for `/dev/vcs{,a}` — read snapshots the foreground VT's
/// screen; write is unsupported (`EINVAL`).
struct VcsFileOps;
impl FileOps for VcsFileOps {
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let with_attr = inode.private::<VcsData>().ok_or(VfsError::Einval)?.with_attr;
        let data = fbcon::kernel::screen_dump(with_attr);
        let off = off as usize;
        if off >= data.len() { return Ok(0); }
        let n = (data.len() - off).min(buf.len());
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }
    fn write(&self, _i: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> { Err(VfsError::Einval) }
}

/// Build a vcs screen-dump inode. `attr=false` → `/dev/vcs(0)`; `attr=true`
/// → `/dev/vcsa(0)`. Distinct, collision-free inos (low byte 0 ⇒ the VT/fbdev
/// ioctl routers skip these): 0x7600 = vcs, 0x7700 = vcsa. # C: O(1)
pub fn make_vcs_inode(attr: bool) -> InodeRef {
    let ino: Ino = if attr { 0x7700 } else { 0x7600 };
    let rdev: u32 = if attr { 0x0780 } else { 0x0700 };
    InodeBuilder::new(ino, mk_mode(FileType::CharDev, 0o644), default_inode_ops(), Arc::new(VcsFileOps))
        .fsid(devfs::DEVFS_FSID).rdev(rdev)
        .private(Arc::new(VcsData { with_attr: attr }))
        .build()
}

/// The backing inode for `/dev/console` — the *preferred console* named by
/// the LAST `console=` on the boot cmdline (Linux: `/dev/console` (5:1) is the
/// kernel's preferred console device, NOT a fixed alias of the video VT).
/// `console=ttyS0`/`ttyAMA0` as the preferred console ⇒ the serial tty;
/// `console=tty<n>`/none ⇒ the foreground video VT. # C: O(cmdline length)
pub fn system_console_inode() -> InodeRef {
    make_system_console_inode()
}

/// Fallibly register the console/tty char-device nodes into devfs
/// (self-registration per docs/56). `/dev/console` follows the preferred
/// `console=` ([`system_console_inode`]); `/dev/tty`+`/dev/tty0` are the
/// foreground VT; /dev/tty1..N each carry their own VT id; /dev/vcs{,0,a,a0}
/// dump the screen. Matching existing model devices are idempotent; conflicts
/// roll back nodes published by this call and return the driver-model error.
/// # C: O(N_VT)
pub fn try_register_devnodes() -> drv::KResult<()> {
    use alloc::sync::Arc;
    let mut published = Vec::new();
    // device-model Stage C (D27): the console/tty char devices self-register
    // through `drv::try_device_add` (dev_class "tty"). Each `node_factory` mints the
    // EXACT bespoke inode (per-VT `i_private`, routing tag, rdev) the direct
    // register used, so every /dev node is byte-identical (shared instances —
    // tty/tty0, vcs/vcs0, vcsa/vcsa0 — are preserved by cloning a captured Arc).
    // bus "tty" is ignored by the pci/virtio /sys synthesis (no spurious /sys
    // entry); dev_t metadata is decoded from each inode's real rdev.
    // /dev/console = the preferred console (serial when a serial console is
    // the preferred console, else the fg VT) — the Linux 5:1 kernel-console
    // device.
    push_tty_node(&mut published, "console", 0x0501, Arc::new(|| system_console_inode()))?;
    // /dev/tty, /dev/tty0 = the foreground video VT (always video; distinct
    // from /dev/console, which the console= cmdline may point at serial). Both
    // share ONE inode instance (rdev 5:0), as before.
    let fg: vfs::InodeRef = make_console_inode(0);
    let fg2 = Arc::clone(&fg);
    push_tty_node(&mut published, "tty",  console_rdev(0), Arc::new(move || Arc::clone(&fg)))?;
    push_tty_node(&mut published, "tty0", console_rdev(0), Arc::new(move || Arc::clone(&fg2)))?;
    // Serial line — a SEPARATE device (its own tty, serial-only, own winsize).
    push_tty_node(&mut published, "ttyS0", SERIAL_RDEV, Arc::new(|| make_serial_inode()))?;
    for vt in 1..=tty::live::N_VT as u8 {
        let mut name = String::with_capacity(6);
        name.push_str("tty");
        if vt >= 10 { name.push((b'0' + (vt / 10)) as char); }
        name.push((b'0' + (vt % 10)) as char);
        push_tty_node(&mut published, &name, console_rdev(vt), Arc::new(move || make_console_inode(vt)))?;
    }
    // VT screen-dump devices (vc_screen.c). 0 = current foreground VT.
    let vcs: vfs::InodeRef = make_vcs_inode(false);
    let vcs2 = Arc::clone(&vcs);
    push_tty_node(&mut published, "vcs",  0x0700, Arc::new(move || Arc::clone(&vcs)))?;
    push_tty_node(&mut published, "vcs0", 0x0700, Arc::new(move || Arc::clone(&vcs2)))?;
    let vcsa: vfs::InodeRef = make_vcs_inode(true);
    let vcsa2 = Arc::clone(&vcsa);
    push_tty_node(&mut published, "vcsa",  0x0780, Arc::new(move || Arc::clone(&vcsa)))?;
    push_tty_node(&mut published, "vcsa0", 0x0780, Arc::new(move || Arc::clone(&vcsa2)))?;
    Ok(())
}

/// Register console/tty nodes for the boot path. A model conflict here means
/// the kernel cannot publish the canonical tty namespace, so fail immediately.
/// # C: O(N_VT)
pub fn register_devnodes() {
    if let Err(e) = try_register_devnodes() {
        panic!("console tty device registration failed: {:?}", e);
    }
}

fn push_tty_node(
    published: &mut Vec<Arc<drv::Device>>,
    name: &str,
    rdev: u32,
    factory: drv::NodeFactory,
) -> drv::KResult<()> {
    match add_tty_node(name, rdev, factory) {
        Ok(Some(dev)) => {
            published.push(dev);
            Ok(())
        }
        Ok(None) => Ok(()),
        Err(e) => {
            for dev in published.iter().rev() {
                drv::device_del(dev);
            }
            Err(e)
        }
    }
}

/// Self-register a tty-class `/dev/<name>` node through `drv::try_device_add`
/// (D27).
/// `rdev` is the inode's packed `(major<<8)|minor`; the device-model carries the
/// decoded `(major,minor)` metadata and the `factory` mints the exact inode.
/// Returns `Ok(Some(_))` when this call published a fresh model device and
/// `Ok(None)` when an identical model device already existed.
/// # C: O(N_devices)
fn add_tty_node(name: &str, rdev: u32, factory: drv::NodeFactory) -> drv::KResult<Option<Arc<drv::Device>>> {
    let dev_t = (rdev >> 8, rdev & 0xff);
    match drv::try_device_add(Arc::new(
        drv::Device::new("tty", String::from(name), 0, 0, 0)
            .with_devnode("tty", String::from(name), Some(dev_t))
            .with_node_factory(factory)))
    {
        Ok(dev) => Ok(Some(dev)),
        Err(drv::Error::Busy) => {
            if drv::devices().iter().any(|d| {
                d.bus == "tty"
                    && d.addr == name
                    && d.dev_class == "tty"
                    && d.devname.as_deref() == Some(name)
                    && d.dev_t == Some(dev_t)
                    && d.node_factory.is_some()
            }) {
                Ok(None)
            } else {
                Err(drv::Error::Busy)
            }
        }
        Err(e) => Err(e),
    }
}
