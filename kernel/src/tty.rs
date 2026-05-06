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
//   timer IRQ → eoi → tick_pick_next → tty::tick_poll_uart
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

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use sched::{Task, TaskState};
use sync::{Spinlock, Tty as TtyClass};

/// Fixed-capacity byte ringbuffer. 64 B is plenty for v1's
/// interactive shell pacing (UART data trickles in at 115200 ≈
/// 11 KB/s; even at full rate the ringbuffer drains every few
/// thousand timer ticks).
const RX_CAP: usize = 64;

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
pub const N_VT: usize = 6;

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
/// `tick_poll_uart` (timer ISR ctx) and `kernel_sys_read`
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
    let va = crate::pl011::base_va();
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

/// Push `b` to the foreground VT's ring + wake its waiters.
/// Called from each arch's timer-tick poller.
///
/// v1 line-discipline: translate CR (0x0d) → NL (0x0a) — the
/// equivalent of termios `ICRNL`. Real serial terminals + most
/// host terminals running QEMU `-serial stdio` send CR on Enter;
/// userspace `read_line` loops uniformly look for `\n`. Without
/// this translation, Enter never terminates a line and the user
/// has to keep typing until login's input buffer fills.
/// Real termios + per-fd c_iflag rides a follow-up.
fn push_and_wake_fg(b: u8) {
    let translated = if b == b'\r' { b'\n' } else { b };
    let idx = vt_index(0);
    let pushed = VT_RINGS[idx].lock().push(translated);
    if !pushed { return; }
    wake_waiters(idx);
}

fn wake_waiters(idx: usize) {
    let mut waiters = VT_WAITERS[idx].lock();
    if waiters.is_empty() { return; }
    let rq = match crate::sched::global() {
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
    crate::preempt::set_need_resched();
}

/// Pop one byte from `vt`'s RX ringbuffer. `vt == 0` reads from
/// the current foreground VT. `None` means "no data right now"
/// — caller should park via `park_current_for_tty_vt` if blocking.
/// # C: O(1)
pub fn try_read_vt(vt: u8) -> Option<u8> {
    VT_RINGS[vt_index(vt)].lock().pop()
}

/// Backwards-compat shim: pop from foreground VT.
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
pub fn inject_for_smoke(bytes: &[u8]) { inject_for_smoke_vt(0, bytes); }

/// Park the current task on `vt`'s TTY input wait queue.
/// Caller is responsible for marking state=Sleeping + invoking
/// `schedule()` after; this just registers the wakeup target.
/// # SAFETY: caller is the running task on this CPU; preempt-off.
/// # C: O(1)
pub unsafe fn park_current_for_tty_vt(vt: u8) {
    let rq = match crate::sched::global() { Some(r) => r, None => return };
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
