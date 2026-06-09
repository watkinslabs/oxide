// Global serial system console (tty-rebuild-plan §3-T7 core cutover).
//
// The boot serial line (`/dev/console`, `/dev/tty`, `/dev/tty0`,
// `/dev/ttyS0`) is one `TtyStruct` built around `serialtty`'s
// `SerialTtyDriver` over the real UART (`KernelUart` → `drv_serial::emit`)
// with N_TTY (ICANON|ECHO|ISIG, OPOST|ONLCR). This REPLACES the old
// input-only `tty::live` VT-ring + the racy `ConsoleInode::read` park
// loop: reads use the lost-wakeup-free `TtyStruct::read`, writes use
// N_TTY OPOST → UART. Position in the stack (tty-rebuild-plan §0):
//
//   /dev/console inode ─▶ TtyStruct ─▶ N_TTY ─▶ SerialTtyDriver ─▶ UART
//                            │ block/wake (KernelWait, lost-wakeup-free)
//                            └ fg_pgrp / sid / termios = SOURCE OF TRUTH
//
// The `016_ioctl` handler routes the non-pty console branch
// (TCGETS/TCSETS/TIOCSPGRP/TIOCSCTTY/...) here so the tty itself owns
// termios + fg_pgrp + sid — login's password ECHO-off (TCSETS clearing
// ECHO) and bash's raw mode (TCSETS) actually reach the ldisc, and ISIG
// (^C) targets the live fg pgrp.
//
// printk stays SEPARATE: `klog` still emits kernel logs to the UART via
// `drv_serial::emit` (and mirrors to fbcon). A tty write here goes
// TtyStruct → UART directly, NOT into the kmsg ring — the dmesg/shell
// split (tty-rebuild-plan §0 fact (a)).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicU64, Ordering};

use serialtty::{KernelUart, SerialOut, SerialTtyDriver};
use tty::ldisc::Sig;
use tty::pty::{default_termios, TERMIOS_BYTES};
use tty::wait::kernel::KernelWait;
use tty::{TtyDriver, TtyStruct};

/// `FgSignal` raising a real signal on the fg pgrp (Linux `isig` →
/// `kill_pgrp`). Mirrors `tty::live::deliver_signal_to_waiters`: OR the
/// signal bit into every task in `pgrp` via the scheduler registry. The
/// blocking-read wakeup is the tty core's `receive_from_driver` →
/// `wait.wake_all()` (it already wakes after the ldisc receive that
/// produced the signal), so the parked reader rouses and the syscall
/// boundary observes the pending signal.
#[derive(Default)]
pub struct KernelFgSignal;

impl serialtty::FgSignal for KernelFgSignal {
    /// # C: O(P) tasks in the fg pgrp
    fn raise(&mut self, pgrp: u32, sig: Sig) {
        let signo = sig.signo() as u32;
        if pgrp == 0 || signo == 0 || signo > 64 {
            return;
        }
        let bit = 1u64 << (signo - 1);
        for t in sched::live::registry::tasks_in_pgrp(pgrp) {
            t.sigpending.fetch_or(bit, Ordering::Release);
        }
    }
}

/// The concrete kernel serial console tty type: serial driver over the
/// real UART with a real fg-pgrp signal sink, parked on `KernelWait`.
pub type KernelConsoleTty = TtyStruct<SerialTtyDriver<KernelUart, KernelFgSignal>, KernelWait>;

/// Boot-installed `Arc<KernelConsoleTty>` as a raw `Arc::into_raw`
/// pointer (kept alive for the kernel lifetime — the system console never
/// goes away). 0 = not yet installed.
static CONSOLE_PTR: AtomicU64 = AtomicU64::new(0);

/// Borrow the installed console tty, or `None` before `install`.
/// # C: O(1)
fn console() -> Option<&'static KernelConsoleTty> {
    let p = CONSOLE_PTR.load(Ordering::Acquire);
    if p == 0 {
        return None;
    }
    // SAFETY: p came from Arc::into_raw in install() over a valid
    // Arc<KernelConsoleTty> deliberately leaked for the kernel lifetime
    // (the system console never closes); &* gives a shared ref valid for
    // this call, and every TtyStruct method takes &self (aliasing-safe).
    let tty = unsafe { &*(p as *const KernelConsoleTty) };
    Some(tty)
}

/// Assemble the global serial console tty and wire the UART RX sink to
/// feed it. Call once at boot, before RX starts (replaces the old
/// `drv_serial::set_rx_sink(tty::live::push_and_wake_fg)`). Leaks the
/// `Arc` intentionally: the serial line lives for the whole kernel
/// lifetime, so the RX sink + device nodes may dereference it freely.
/// # C: O(1)
pub fn install() {
    let tty: Arc<KernelConsoleTty> = Arc::new(TtyStruct::with_termios(
        SerialTtyDriver::with_signal(KernelUart, KernelFgSignal),
        KernelWait::new(),
        default_termios(),
    ));
    let raw = Arc::into_raw(tty) as u64;
    CONSOLE_PTR.store(raw, Ordering::Release);
    drv_serial::set_rx_sink(rx_byte);
}

/// UART RX byte sink (`fn(u8)` for `drv_serial::set_rx_sink`). Pushes the
/// byte into the console tty's flip path → N_TTY → cooks/echoes/ISIG →
/// wakes parked readers. Mirrors Linux `uart_insert_char` →
/// `tty_flip_buffer_push`. Dropped silently before `install`.
/// # C: O(1) + O(waiters) wake
pub fn rx_byte(b: u8) {
    if let Some(tty) = console() {
        tty.receive_from_driver(&[b]);
    }
}

// ------------------------------------------------------------- inode ops
//
// The `ConsoleInode` read/write/poll delegate here. Before `install`
// (should never happen for real opens) reads/writes degrade safely.

/// Blocking read — the lost-wakeup-free `TtyStruct::read`. Returns the
/// cooked bytes (whole line in ICANON) into `buf`.
/// # C: O(N) bytes + sleeps until input
pub fn read(buf: &mut [u8]) -> usize {
    match console() {
        Some(tty) => tty.read(buf),
        None => 0,
    }
}

/// Non-blocking read: drain ready bytes, never park. Returns 0 when the
/// input queue is empty (caller maps that to EAGAIN for O_NONBLOCK fds —
/// systemd PID1's `ppoll`+`read` loop relies on this).
/// # C: O(N) bytes
pub fn read_nonblock(buf: &mut [u8]) -> usize {
    match console() {
        Some(tty) => tty.read_nonblock(buf),
        None => 0,
    }
}

/// Write `buf` through N_TTY output processing (OPOST/ONLCR) → UART. Does
/// NOT touch the kmsg ring. Returns bytes consumed.
/// # C: O(N) bytes
pub fn write(buf: &[u8]) -> usize {
    match console() {
        Some(tty) => tty.write(buf),
        // Pre-install fallback: emit raw so early /dev/console writes are
        // not silently lost. Cooked output is the tty's job once up.
        None => {
            KernelUart.emit(buf);
            buf.len()
        }
    }
}

/// Poll mask (POLLIN when a read would return; POLLOUT always).
/// # C: O(1)
pub fn poll() -> u32 {
    match console() {
        Some(tty) => tty.poll(),
        // Writable but never readable before install.
        None => tty::ldisc::pollmask::POLLOUT,
    }
}

// --------------------------------------------------- ioctl source-of-truth
//
// `016_ioctl` routes the non-pty console branch here so the tty owns
// termios / fg_pgrp / sid (the Linux contract: the tty_struct is the
// source of truth, not a side table). `serialtty::set_fg_pgrp` keeps the
// driver's ISIG-target shadow in sync with the core.

/// TCGETS: snapshot the console termios image.
/// # C: O(1)
pub fn termios_get() -> [u8; TERMIOS_BYTES] {
    match console() {
        Some(tty) => tty.termios(),
        None => default_termios(),
    }
}

/// TCSETS{,W,F}: install a new termios image (login ECHO-off, bash raw).
/// # C: O(1)
pub fn termios_set(t: &[u8; TERMIOS_BYTES]) {
    if let Some(tty) = console() {
        tty.set_termios(t);
    }
}

/// TIOCGPGRP: foreground pgrp (0 = unset).
/// # C: O(1)
pub fn foreground_pgid() -> u32 {
    console().map(|t| t.fg_pgrp()).unwrap_or(0)
}

/// TIOCSPGRP / tcsetpgrp: set the fg pgrp on BOTH the core and the
/// driver's ISIG-target shadow (keeps ^C → SIGINT aimed at the live fg).
/// # C: O(1)
pub fn set_foreground_pgid(pgid: u32) {
    if let Some(tty) = console() {
        serialtty::set_fg_pgrp(tty, pgid);
    }
}

/// TIOCGSID: controlling session id (0 = unset).
/// # C: O(1)
pub fn session() -> u32 {
    console().map(|t| t.sid()).unwrap_or(0)
}

/// TIOCSCTTY: claim the console as controlling tty of `sid` and seed the
/// fg pgrp with `pgid` (POSIX: session leader acquiring a ctty sets the
/// fg pgrp to its own pgrp — without it bash trips SIGTTIN and stops).
/// # C: O(1)
pub fn set_session_and_fg(sid: u32, pgid: u32) {
    if let Some(tty) = console() {
        tty.set_ctty(sid);
        serialtty::set_fg_pgrp(tty, pgid);
    }
}

/// TIOCNOTTY: release the controlling tty (clear sid + fg pgrp).
/// # C: O(1)
pub fn notty() {
    if let Some(tty) = console() {
        tty.notty();
        tty.with_driver(|d| d.set_fg_pgrp(0));
    }
}
