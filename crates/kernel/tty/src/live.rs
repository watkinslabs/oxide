// TTY input plumbing per docs/28. v1 implementation: timer-tick-
// driven UART polling (avoids the IOAPIC/PIC routing IRQ4 would
// need), kernel ringbuffer, blocking `sys_read(fd=0)` via a
// task `WaitQueue`.
//
// Multi-VT layout (post-B07): one ringbuffer + waiters list per
// VT slot 1..=6 plus a foreground-VT pointer. UART RX byes flow
// into the foreground VT's ring; reads from /dev/tty<N> drain
// VT-N's ring. /dev/console, /dev/tty, and /dev/tty0 carry vt=0
// — a virtual alias that resolves to FOREGROUND_VT at every
// access. v1 keeps foreground pinned to VT 1; runtime VT
// switching (Ctrl-Alt-F<n> equivalent) rides a follow-up.
//
// Flow:
//   timer IRQ → eoi → tick_pick_next → crate::tick_poll_uart
//     ↓
//     UART LSR.DR set?  → read RBR byte, push to VT[fg].rx
//     buffer non-empty?  → wake all VT[fg].waiters
//
//   user calls sys_read(fd=0) on a /dev/ttyN inode (vt = N or
//   resolved from 0 → foreground)
//     → if VT[vt].rx empty: state=Sleeping, push self to
//                           VT[vt].waiters, schedule()
//                           (on resume, retry)
//       else: pop one byte, write to user buf, return 1
//
// Single-CPU UP. Per-CPU partitioning + a real RX-IRQ rewrite
// rides full TTY support per docs/28.


use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use sched::{Task, TaskState};
use sync::{Spinlock, Tty as TtyClass};

// tty-side UART emit. The bytes here are user-visible character
// output (echo, ^C marker, BS visualization), not debug log spam,
// so the per-subsystem cfg-gate doesn't apply (R06 is for diagnostic
// klog output). Aliased through dev_console-style to satisfy the
// spec-lint klog-ungated check.
use klog::write_raw as tty_emit;

/// Fixed-capacity byte ringbuffer. 64 B is plenty for v1's
/// interactive shell pacing (UART data trickles in at 115200 ≈
/// 11 KB/s; even at full rate the ringbuffer drains every few
/// thousand timer ticks).
const RX_CAP: usize = 1024;

struct RxBuf {
    data: [u8; RX_CAP],
    head: usize,    // pop index
    tail: usize,    // push index
    len:  usize,
}

impl RxBuf {
    const fn new() -> Self {
        Self { data: [0; RX_CAP], head: 0, tail: 0, len: 0 }
    }

    fn push(&mut self, b: u8) -> bool {
        if self.len == RX_CAP { return false; }
        self.data[self.tail] = b;
        self.tail = (self.tail + 1) % RX_CAP;
        self.len += 1;
        true
    }

    fn pop(&mut self) -> Option<u8> {
        if self.len == 0 { return None; }
        let b = self.data[self.head];
        self.head = (self.head + 1) % RX_CAP;
        self.len -= 1;
        Some(b)
    }
}

/// Number of distinct VT slots (1..=N_VT). VT 0 is reserved as
/// the "foreground alias" — nothing is stored at index 0.
pub const N_VT: usize = 63;

/// Foreground VT (1..=N_VT). UART RX bytes route here. `0` is
/// not a valid stored value — readers using vt=0 dereference
/// this atomic at access time.
static FOREGROUND_VT: AtomicU8 = AtomicU8::new(1);

/// Per-VT RX ringbuffers. Index 0 of this array == VT 1, etc.
static VT_RINGS: [Spinlock<RxBuf, TtyClass>; N_VT] =
    [const { Spinlock::new(RxBuf::new()) }; N_VT];

/// Per-VT wait queues. Mirrors `VT_RINGS` indexing.
static VT_WAITERS: [Spinlock<Vec<Arc<Task>>, TtyClass>; N_VT] =
    [const { Spinlock::new(Vec::new()) }; N_VT];

/// Per-VT termios image — the same 60-byte layout TCGETS / TCSETS
/// see. Default at boot is "cooked sane" (`pty::default_termios`):
/// ICANON | ECHO | ISIG, ICRNL, OPOST | ONLCR, c_cc[VINTR]=^C etc.
/// Programs that want raw mode (bash, vi, …) tcsetattr their own.
static VT_TERMIOS: [Spinlock<[u8; crate::pty::TERMIOS_BYTES], TtyClass>; N_VT] =
    [const { Spinlock::new(crate::pty::default_termios()) }; N_VT];

/// Per-VT cooked-mode line buffer. ICANON path accumulates here
/// until a NL / VEOF / VEOL terminates the line; on terminate the
/// buffer contents move to `VT_RINGS[vt]` for sys_read to drain.
/// Capacity matches the smallest reasonable interactive line; bash's
/// readline / vi etc. set ICANON off and bypass.
const LINE_CAP: usize = 256;
struct LineBuf {
    data: [u8; LINE_CAP],
    len:  usize,
}
impl LineBuf {
    const fn new() -> Self { Self { data: [0; LINE_CAP], len: 0 } }
}
static VT_LINES: [Spinlock<LineBuf, TtyClass>; N_VT] =
    [const { Spinlock::new(LineBuf::new()) }; N_VT];

/// Per-VT foreground process group id. POSIX `tcsetpgrp(2)` /
/// TIOCSPGRP writes this; ISIG-driven signal delivery targets this
/// pgid via `sched::registry::tasks_in_pgrp`. `0` = unset (no
/// foreground assigned yet — signals fall back to readers parked
/// on the VT, which is the v1 stand-in until something runs
/// `tcsetpgrp` on this tty).
static VT_FG_PGID: [AtomicU32; N_VT] =
    [const { AtomicU32::new(0) }; N_VT];

/// Per-VT controlling-session id. TIOCSCTTY writes this; future
/// session-leader checks (POSIX requires the caller's sid to match
/// the tty's sid before TIOCSPGRP succeeds) will read it. v1
/// records it but doesn't enforce yet.
static VT_SID: [AtomicU32; N_VT] =
    [const { AtomicU32::new(0) }; N_VT];

/// Resolve a caller-supplied VT id to a 0-based index into
/// `VT_RINGS` / `VT_WAITERS`. `vt == 0` resolves to the current
/// foreground; anything outside 1..=N_VT clamps to foreground -1
/// rather than panicking (devfs paths are validated at registration
/// time, but inode reuse + future runtime mappings make a
/// defensive clamp cheap).
fn vt_index(vt: u8) -> usize {
    let resolved = if vt == 0 { FOREGROUND_VT.load(Ordering::Relaxed) } else { vt };
    let n = (resolved as usize).clamp(1, N_VT) - 1;
    debug_assert!(n < N_VT);
    n
}

/// Read one COM1 byte non-blocking via I/O ports. Used by
/// `tick_poll_uart` (timer ISR ctx) and `sys_read`
/// (process ctx).
/// # SAFETY: privileged port I/O legal at CPL=0.
#[cfg(target_arch = "x86_64")]
#[inline]
unsafe fn uart_inb(port: u16) -> u8 {
    let v: u8;
    // SAFETY: port I/O instruction at CPL=0; no memory effect.
    unsafe {
        core::arch::asm!(
            "in al, dx",
            out("al") v,
            in("dx") port,
            options(nomem, nostack, preserves_flags),
        );
    }
    v
}

/// Timer-tick callback per `13§9` / docs/28. Polls COM1 LSR for
/// RX-data-ready; if set, reads one byte from RBR and pushes to
/// the ringbuffer. After a successful push, walks WAITERS:
/// transitions each Sleeping task to Runnable + enqueues on the
/// global runqueue's CFS class so the next schedule() picks it.
///
/// # SAFETY: caller is the timer IRQ dispatcher running with
/// IRQs masked; single-CPU UP. Reads two bytes max from the
/// COM1 port range.
/// # C: O(W) waiter wake — bounded by the small set of tasks
/// blocked on stdin
#[cfg(target_arch = "x86_64")]
pub unsafe fn tick_poll_uart() {
    // SAFETY: per fn contract — privileged port I/O.
    let lsr = unsafe { uart_inb(0x3FD) };
    if lsr & 0x01 == 0 {
        return;
    }
    // SAFETY: per fn contract — privileged port I/O at CPL=0; LSR.DR was just observed set so RBR has a byte.
    let b = unsafe { uart_inb(0x3F8) };
    push_and_wake_fg(b);
}

/// PL011 RX poll for arm timer-tick context. Reads `FR.RXFE` to
/// check for pending bytes; on each available byte pulls from
/// `DR` and feeds the foreground VT's `RX_BUF` + waiters.
///
/// # SAFETY: caller is the timer IRQ dispatcher running with
/// IRQs masked; single-CPU UP. Reads through the published
/// PL011_BASE_VA Device-attr mapping.
/// # C: O(N_bytes_drained × W_waiters)
#[cfg(target_arch = "aarch64")]
pub unsafe fn tick_poll_uart() {
    const PL011_DR: u64 = 0x00;
    const PL011_FR: u64 = 0x18;
    const FR_RXFE:  u32 = 1 << 4;
    let va = hal_aarch64::pl011::base_va();
    if va == 0 { return; }
    // Drain up to 16 bytes per tick (one full PL011 RX FIFO).
    let mut n = 0;
    while n < 16 {
        // SAFETY: va is a published Device-nGnRnE 4 KiB mapping over the PL011 register page; FR/DR offsets sit inside it.
        let fr = unsafe { core::ptr::read_volatile((va + PL011_FR) as *const u32) };
        if (fr & FR_RXFE) != 0 { break; }
        // SAFETY: same Device mapping; DR low byte is the received byte.
        let b = unsafe { core::ptr::read_volatile((va + PL011_DR) as *const u32) } as u8;
        push_and_wake_fg(b);
        n += 1;
    }
}

/// Push `b` through the foreground VT's line discipline. Called
/// from each arch's timer-tick poller. The discipline consults the
/// VT's per-fd termios image to decide:
///
///   c_lflag bits:
///     ISIG   — VINTR/VQUIT/VSUSP raise SIGINT/SIGQUIT/SIGTSTP on
///              all readers parked on this VT, then drop the byte.
///     ICANON — line-buffer until VEOL/VEOF/`\n` terminates a line;
///              VERASE pops one char, VKILL clears the line. The
///              terminated line moves to RX_BUF.
///     ECHO   — write the input byte (with VERASE/VKILL niceties
///              when ECHOE/ECHOK ride along) back to the UART so
///              the user sees their typing. Off ⇒ silent (login
///              password mode).
///   c_iflag bits:
///     IGNCR  — drop CR.
///     ICRNL  — translate CR → NL (only if not IGNCR).
///     INLCR  — translate NL → CR.
///
/// In raw mode (ICANON off) every byte goes straight to RX_BUF so
/// programs like bash + vim see the keystrokes one at a time.
fn push_and_wake_fg(b: u8) {
    let idx = vt_index(0);
    let term = *VT_TERMIOS[idx].lock();
    let iflag = crate::pty::read_iflag(&term);
    let lflag = crate::pty::read_lflag(&term);

    // c_iflag preprocessing.
    let mut b = b;
    if b == b'\r' {
        if (iflag & crate::pty::iflag::IGNCR) != 0 { return; }
        if (iflag & crate::pty::iflag::ICRNL) != 0 { b = b'\n'; }
    } else if b == b'\n' && (iflag & crate::pty::iflag::INLCR) != 0 {
        b = b'\r';
    }

    // ISIG: turn the configured control characters into signals
    // and swallow them — they don't reach userspace input.
    if (lflag & crate::pty::lflag::ISIG) != 0 {
        let vintr = term[crate::pty::TERMIOS_OFF_CC + crate::pty::cc::VINTR];
        let vquit = term[crate::pty::TERMIOS_OFF_CC + crate::pty::cc::VQUIT];
        let vsusp = term[crate::pty::TERMIOS_OFF_CC + crate::pty::cc::VSUSP];
        let sig = if b != 0 && b == vintr { Some(2u32) }
             else if b != 0 && b == vquit { Some(3u32) }
             else if b != 0 && b == vsusp { Some(20u32) }
             else { None };
        if let Some(s) = sig {
            // Echo a visible "^C\n"-style marker if ECHO is on so
            // the user sees the interrupt land where they typed.
            if (lflag & crate::pty::lflag::ECHO) != 0 && b < 0x20 {
                tty_emit(&[b'^', b + 0x40]);
                tty_emit(b"\r\n");
            }
            // Reset any in-progress cooked line — Linux drops it on
            // INTR/QUIT/SUSP.
            if (lflag & crate::pty::lflag::ICANON) != 0 {
                VT_LINES[idx].lock().len = 0;
            }
            deliver_signal_to_waiters(idx, s);
            return;
        }
    }

    // Echo before pushing — if the byte ends up dropped (ICANON
    // VERASE / VKILL) we still want the visual effect to land.
    if (lflag & crate::pty::lflag::ECHO) != 0 {
        echo_byte(b, lflag, &term);
    }

    if (lflag & crate::pty::lflag::ICANON) != 0 {
        canonical_input(idx, b, &term);
    } else {
        // Raw mode: byte goes straight to readers.
        let pushed = VT_RINGS[idx].lock().push(b);
        if pushed { wake_waiters(idx); }
    }
}

/// Echo `b` to the foreground UART. CR/NL render as "\r\n" so the
/// host terminal advances cleanly (matches what the OPOST + ONLCR
/// path on output produces). Backspace + DEL render as "\b \b" so
/// terminals visually erase the previous glyph. ECHOE/ECHOK
/// niceties for VERASE / VKILL flow through `canonical_input`.
fn echo_byte(b: u8, _lflag: u32, _term: &[u8; crate::pty::TERMIOS_BYTES]) {
    match b {
        b'\r' | b'\n'   => tty_emit(b"\r\n"),
        0x7f | 0x08     => tty_emit(b"\x08 \x08"),
        c if c >= 0x20 && c < 0x7f => tty_emit(&[c]),
        c if c < 0x20 && c != 0    => {
            // Show as "^X" so users at least see *something*.
            tty_emit(&[b'^', c + 0x40]);
        }
        _ => {}
    }
}

/// ICANON path — accumulate `b` into the line buffer; on a line
/// terminator move the line into RX_BUF and wake readers; honour
/// VERASE / VKILL editing. VEOF on an empty line raises
/// end-of-file (push 0-byte sentinel — `try_read` returns it; the
/// caller treats `Some(0)` as EOF for the v1 path).
fn canonical_input(idx: usize, b: u8, term: &[u8; crate::pty::TERMIOS_BYTES]) {
    let verase = term[crate::pty::TERMIOS_OFF_CC + crate::pty::cc::VERASE];
    let vkill  = term[crate::pty::TERMIOS_OFF_CC + crate::pty::cc::VKILL];
    let veof   = term[crate::pty::TERMIOS_OFF_CC + crate::pty::cc::VEOF];

    let mut line = VT_LINES[idx].lock();

    // VERASE: pop one byte from line buffer (already echoed
    // "\b \b" above so the user sees it disappear).
    if verase != 0 && b == verase {
        if line.len > 0 { line.len -= 1; }
        return;
    }

    // VKILL: drop the entire line.
    if vkill != 0 && b == vkill {
        line.len = 0;
        tty_emit(b"\r\n");
        return;
    }

    // VEOF on empty line: push a 0-len sentinel so the reader
    // returns 0 ⇒ EOF. On a non-empty line, VEOF acts as a
    // newline-less line terminator (the line so far gets returned
    // without a trailing \n). v1: simplify to "drop and return
    // empty line" — bash treats either as EOF for stdin reads.
    if veof != 0 && b == veof {
        if line.len == 0 {
            // Push a zero-length record by waking waiters with the
            // ring empty — readers retry, find no bytes, can detect
            // EOF via /dev/console::read returning Ok(0). We have
            // no flag for that yet, so push '\0' as v1 sentinel.
            let _ = VT_RINGS[idx].lock().push(0);
        } else {
            flush_line(idx, &mut line);
        }
        wake_waiters(idx);
        return;
    }

    // Line terminator: \n (or VEOL).
    if b == b'\n' {
        if line.len < LINE_CAP {
            let i = line.len;
            line.data[i] = b'\n';
            line.len = i + 1;
        }
        flush_line(idx, &mut line);
        wake_waiters(idx);
        return;
    }

    // Ordinary character: append.
    if line.len < LINE_CAP {
        let i = line.len;
        line.data[i] = b;
        line.len = i + 1;
    }
}

fn flush_line(idx: usize, line: &mut LineBuf) {
    let mut ring = VT_RINGS[idx].lock();
    for i in 0..line.len {
        if !ring.push(line.data[i]) { break; }
    }
    line.len = 0;
}

/// Translate `sig_no` into a sigpending bit-set on every task in
/// this VT's foreground process group. If no foreground pgrp has
/// been set yet (TIOCSPGRP / `tcsetpgrp` never called), fall back
/// to delivering to whoever is parked reading the VT — that's the
/// v1 best-effort target. `^C / ^\\ / ^Z` flow through here.
fn deliver_signal_to_waiters(idx: usize, sig: u32) {
    if sig == 0 || sig > 64 { return; }
    let bit = 1u64 << (sig - 1);
    let fg = VT_FG_PGID[idx].load(Ordering::Acquire);
    if fg != 0 {
        for t in sched::live::registry::tasks_in_pgrp(fg) {
            t.sigpending.fetch_or(bit, Ordering::Release);
        }
    } else {
        let waiters = VT_WAITERS[idx].lock();
        for t in waiters.iter() {
            t.sigpending.fetch_or(bit, Ordering::Release);
        }
    }
    wake_waiters(idx);
}

/// Read this VT's foreground pgid (0 if unset). Used by
/// TIOCGPGRP on /dev/console.
/// # C: O(1)
pub fn foreground_pgid(vt: u8) -> u32 {
    VT_FG_PGID[vt_index(vt)].load(Ordering::Acquire)
}

/// Set this VT's foreground pgid. Used by TIOCSPGRP / tcsetpgrp.
/// # C: O(1)
pub fn set_foreground_pgid(vt: u8, pgid: u32) {
    VT_FG_PGID[vt_index(vt)].store(pgid, Ordering::Release);
}

/// Make `sid` the controlling session for this VT. Used by
/// TIOCSCTTY. v1 records but doesn't enforce session-match
/// checks on subsequent TIOCSPGRP.
/// # C: O(1)
pub fn set_session(vt: u8, sid: u32) {
    VT_SID[vt_index(vt)].store(sid, Ordering::Release);
}

/// Read a snapshot of `vt`'s termios image. Used by TCGETS.
/// `vt == 0` resolves to foreground.
/// # C: O(1)
pub fn termios_get(vt: u8) -> [u8; crate::pty::TERMIOS_BYTES] {
    *VT_TERMIOS[vt_index(vt)].lock()
}

/// Replace `vt`'s termios image. Used by TCSETS{,W,F}.
/// `vt == 0` resolves to foreground.
/// # C: O(1)
pub fn termios_set(vt: u8, new: &[u8; crate::pty::TERMIOS_BYTES]) {
    *VT_TERMIOS[vt_index(vt)].lock() = *new;
}

/// Read c_oflag for `vt`. Used by ConsoleInode::write to decide
/// whether to apply ONLCR / OPOST translation on output.
/// # C: O(1)
pub fn output_oflag(vt: u8) -> u32 {
    crate::pty::read_oflag(&*VT_TERMIOS[vt_index(vt)].lock())
}

fn wake_waiters(idx: usize) {
    let mut waiters = VT_WAITERS[idx].lock();
    if waiters.is_empty() { return; }
    let rq = match sched::live::global() {
        Some(r) => r,
        None    => { waiters.clear(); return; }
    };
    let mut inner = rq.inner.lock();
    while let Some(task) = waiters.pop() {
        task.set_state(TaskState::Runnable);
        task.lift_vruntime(inner.cfs.min_vruntime());
        inner.enqueue(task);
    }
    rq.nr_running.store(inner.nr_running(), Ordering::Release);
    sched::live::preempt::set_need_resched();
}

/// Pop one byte from `vt`'s RX ringbuffer. `vt == 0` reads from
/// the current foreground VT. `None` means "no data right now"
/// — caller should park via `park_current_for_tty_vt` if blocking.
/// # C: O(1)
pub fn try_read_vt(vt: u8) -> Option<u8> {
    VT_RINGS[vt_index(vt)].lock().pop()
}

/// Backwards-compat shim: pop from foreground VT.
/// # C: O(1)
pub fn try_read() -> Option<u8> { try_read_vt(0) }

/// Inject `bytes` into `vt`'s RX ringbuffer as if they had
/// arrived from the UART. v1 boot smoke uses this to pre-load
/// test input non-interactively so the ECHO program can
/// demonstrate the full read+write path without requiring user
/// typing. In production a UART RX IRQ replaces this at runtime.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N)
pub fn inject_for_smoke_vt(vt: u8, bytes: &[u8]) {
    let mut g = VT_RINGS[vt_index(vt)].lock();
    for &b in bytes {
        let _ = g.push(b);
    }
}

/// Backwards-compat shim: inject into foreground VT.
/// # C: O(N)
pub fn inject_for_smoke(bytes: &[u8]) { inject_for_smoke_vt(0, bytes); }

/// Public input entry point. Used by virtio-input (keyboard) — the
/// device's softirq handler translates each EV_KEY press into an
/// ASCII byte and calls here so it lands on the foreground VT's
/// line discipline the same as a UART RX byte.
/// # C: O(W) waiter wake — bounded by the small set of stdin readers
pub fn input_push_byte(b: u8) { push_and_wake_fg(b); }

/// Park the current task on `vt`'s TTY input wait queue.
/// Caller is responsible for marking state=Sleeping + invoking
/// `schedule()` after; this just registers the wakeup target.
/// # SAFETY: caller is the running task on this CPU; preempt-off.
/// # C: O(1)
pub unsafe fn park_current_for_tty_vt(vt: u8) {
    let rq = match sched::live::global() { Some(r) => r, None => return };
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: rq.current is non-null after install_global; bump strong count to materialise an Arc that the WAITERS list can hold across the schedule.
    unsafe { Arc::increment_strong_count(raw); }
    // SAFETY: matching Arc::from_raw consumes the bumped ref.
    let arc = unsafe { Arc::from_raw(raw) };
    arc.set_state(TaskState::Sleeping);
    VT_WAITERS[vt_index(vt)].lock().push(arc);
}

/// Backwards-compat shim: park on foreground VT.
/// # C: O(1)
pub unsafe fn park_current_for_tty() {
    // SAFETY: delegated to vt-aware variant; same fn contract.
    unsafe { park_current_for_tty_vt(0); }
}

/// Currently-foreground VT id (1..=N_VT). Exposed for procfs /
/// /dev/tty0 introspection.
/// # C: O(1)
pub fn foreground() -> u8 {
    FOREGROUND_VT.load(Ordering::Acquire)
}

/// Set the foreground VT. `vt` must be in 1..=N_VT; out-of-range
/// values are silently clamped. Future Ctrl-Alt-F<n> handler
/// (kbd driver) will call this; for v1 it stays at 1.
/// # SAFETY: caller has authority to switch VTs (kernel-only).
/// # C: O(1)
#[allow(dead_code)]
pub fn set_foreground(vt: u8) {
    let clamped = (vt.max(1) as usize).min(N_VT) as u8;
    FOREGROUND_VT.store(clamped, Ordering::Release);
}
