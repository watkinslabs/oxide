// TTY input plumbing per docs/28. v1 implementation: timer-tick-
// driven UART polling (avoids the IOAPIC/PIC routing IRQ4 would
// need), kernel ringbuffer, blocking `sys_read(fd=0)` via a
// task `WaitQueue`.
//
// Flow:
//   timer IRQ → eoi → tick_pick_next → tty::tick_poll_uart
//     ↓
//     UART LSR.DR set?  → read RBR byte, push to RX_BUF
//     buffer non-empty?  → wake all WAITERS (Sleeping → Runnable + enqueue)
//
//   user calls sys_read(fd=0)
//     → if RX_BUF empty: state=Sleeping, push self to WAITERS, schedule()
//                        (on resume, retry)
//       else: pop one byte, write to user buf, return 1
//
// Single-CPU UP. Per-CPU partitioning + a real RX-IRQ rewrite
// rides full TTY support per docs/28.

#![cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

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

    fn is_empty(&self) -> bool { self.len == 0 }
}

static RX_BUF:  Spinlock<RxBuf, TtyClass>      = Spinlock::new(RxBuf::new());
static WAITERS: Spinlock<Vec<Arc<Task>>, TtyClass> = Spinlock::new(Vec::new());

/// Read one COM1 byte non-blocking via I/O ports. Used by
/// `tick_poll_uart` (timer ISR ctx) and `kernel_sys_read`
/// (process ctx).
/// # SAFETY: privileged port I/O legal at CPL=0.
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
pub unsafe fn tick_poll_uart() {
    // SAFETY: per fn contract — privileged port I/O.
    let lsr = unsafe { uart_inb(0x3FD) };
    if lsr & 0x01 == 0 {
        return;
    }
    // SAFETY: per fn contract — privileged port I/O at CPL=0; LSR.DR was just observed set so RBR has a byte.
    let b = unsafe { uart_inb(0x3F8) };
    let pushed = RX_BUF.lock().push(b);
    if !pushed {
        // Ringbuffer full — drop the byte. v1 doesn't surface
        // overrun; a real impl would return -EIO via the next
        // `sys_read` and clear an overrun flag.
        return;
    }
    // Wake every waiter. We don't know which task wants this
    // specific byte (no fd-keyed wait queue yet); each waiter
    // re-tries `sys_read` on resume.
    let mut waiters = WAITERS.lock();
    if waiters.is_empty() { return; }
    let rq = match crate::sched::global() {
        Some(r) => r,
        None    => { waiters.clear(); return; }
    };
    let mut inner = rq.inner.lock();
    while let Some(task) = waiters.pop() {
        task.set_state(TaskState::Runnable);
        // Lift vruntime to current min so the woken task enters
        // CFS at a fair position per `13§5` invariant 5.
        task.lift_vruntime(inner.cfs.min_vruntime());
        inner.enqueue(task);
    }
    rq.nr_running.store(inner.nr_running(), Ordering::Release);
    crate::preempt::NEED_RESCHED.store(true, Ordering::Release);
}

/// Pop one byte from the RX ringbuffer, returning it as
/// `Some(b)` if available. `None` means "no data right now"
/// (caller should park on `WAITERS` if blocking).
/// # C: O(1)
pub fn try_read() -> Option<u8> {
    RX_BUF.lock().pop()
}

/// Park the current task on the TTY input wait queue. Caller is
/// responsible for marking state=Sleeping + invoking `schedule()`
/// after; this just registers the wakeup target.
/// # SAFETY: caller is the running task on this CPU; preempt-off.
/// # C: O(1)
pub unsafe fn park_current_for_tty() {
    let rq = match crate::sched::global() { Some(r) => r, None => return };
    let raw = rq.current.load(Ordering::Acquire);
    if raw.is_null() { return; }
    // SAFETY: rq.current is non-null after install_global; bump strong count to materialise an Arc that the WAITERS list can hold across the schedule.
    unsafe { Arc::increment_strong_count(raw); }
    // SAFETY: matching Arc::from_raw consumes the bumped ref.
    let arc = unsafe { Arc::from_raw(raw) };
    arc.set_state(TaskState::Sleeping);
    WAITERS.lock().push(arc);
}
