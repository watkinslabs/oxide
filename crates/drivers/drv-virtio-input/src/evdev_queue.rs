// Per-device evdev event queue. virtio-input's drain pushes
// 24-byte Linux `struct input_event` records here; `/dev/input/
// event0` reads pop one record at a time, blocking on a WaitList
// when the queue is empty (matching real evdev semantics — X11,
// Wayland, evdev, libinput etc. all rely on blocking reads).

#![cfg(target_os = "oxide-kernel")]

use alloc::collections::VecDeque;
use core::sync::atomic::Ordering;

use sched::live::wait_list::WaitList;
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::PollSubscribers;

/// One `struct input_event` per Linux input.h (24 B on 64-bit).
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct InputEvent {
    pub tv_sec:  u64,
    pub tv_usec: u64,
    pub ev_type: u16,
    pub code:    u16,
    pub value:   i32,
}

pub const INPUT_EVENT_BYTES: usize = 24;

/// Per-evdev-device queue cap. Past this, oldest events drop
/// (matches Linux's per-evdev buffer-overflow policy when the
/// userspace reader can't keep up).
const QUEUE_CAP: usize = 256;

pub struct EvdevQueue {
    pub buf:     Spinlock<VecDeque<InputEvent>, TaskListClass>,
    pub waiters: WaitList,
    pub subs:    PollSubscribers,
}

impl EvdevQueue {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            buf:     Spinlock::new(VecDeque::new()),
            waiters: WaitList::new(),
            subs:    PollSubscribers::new(),
        }
    }

    /// True iff no event is queued (drives evdev `->poll`: POLLIN is
    /// reported only when at least one record is ready, matching Linux
    /// evdev_poll). # C: O(1)
    pub fn is_empty(&self) -> bool { self.buf.lock().is_empty() }

    /// Push an event; if cap-full, drop oldest (Linux evdev:
    /// overflow drops the oldest record + signals SYN_DROPPED).
    /// Wakes one parked reader and notifies poll/epoll subscribers.
    /// # C: O(1)
    pub fn push(&self, ev: InputEvent) {
        let mut g = self.buf.lock();
        while g.len() >= QUEUE_CAP { g.pop_front(); }
        g.push_back(ev);
        drop(g);
        self.waiters.wake_one();
        self.subs.notify();
    }

    /// Non-blocking pop. Returns the record bytes if available.
    /// # C: O(1)
    pub fn try_pop_bytes(&self, dst: &mut [u8]) -> Option<usize> {
        if dst.len() < INPUT_EVENT_BYTES { return None; }
        let ev = self.buf.lock().pop_front()?;
        let bytes = ev_to_bytes(&ev);
        dst[..INPUT_EVENT_BYTES].copy_from_slice(&bytes);
        Some(INPUT_EVENT_BYTES)
    }

    /// Block-and-pop. Parks on `waiters` until an event arrives
    /// or the caller is interrupted (signal — checked by the
    /// kernel signal-on-syscall-return path; we re-enter the
    /// loop on spurious wakeup).
    /// # SAFETY: caller is the running task; preempt-off; only
    /// called from process context.
    /// # C: O(1) per attempt
    pub unsafe fn read_blocking(&self, dst: &mut [u8]) -> usize {
        if dst.len() < INPUT_EVENT_BYTES { return 0; }
        loop {
            if let Some(n) = self.try_pop_bytes(dst) { return n; }
            // SAFETY: caller is running task; preempt-off; WaitList::park bumps Arc + marks Sleeping before we schedule.
            unsafe { self.waiters.park(); }
            // SAFETY: process ctx; runqueue installed; preempt-off; current is Sleeping so schedule won't re-enqueue until a push wakes us.
            unsafe { sched::live::schedule::schedule(); }
        }
    }
}

fn ev_to_bytes(ev: &InputEvent) -> [u8; INPUT_EVENT_BYTES] {
    let mut b = [0u8; INPUT_EVENT_BYTES];
    b[ 0.. 8].copy_from_slice(&ev.tv_sec.to_le_bytes());
    b[ 8..16].copy_from_slice(&ev.tv_usec.to_le_bytes());
    b[16..18].copy_from_slice(&ev.ev_type.to_le_bytes());
    b[18..20].copy_from_slice(&ev.code.to_le_bytes());
    b[20..24].copy_from_slice(&ev.value.to_le_bytes());
    b
}

/// Max simultaneous evdev devices (kbd + mouse/tablet + spares). Matches
/// the drain's CTXS slot count; the CTXS slot index IS the evdev id.
pub const MAX_EVDEV: usize = 8;

/// Per-device evdev queues. `EVENT_QUEUES[id]` backs `/dev/input/event<id>`;
/// the drain pushes by the device's CTXS slot index = its evdev id.
pub static EVENT_QUEUES: [EvdevQueue; MAX_EVDEV] =
    [const { EvdevQueue::new() }; MAX_EVDEV];

/// The queue backing `/dev/input/event<id>` (clamped to MAX_EVDEV-1).
/// # C: O(1)
pub fn queue(id: u32) -> &'static EvdevQueue {
    &EVENT_QUEUES[(id as usize).min(MAX_EVDEV - 1)]
}

/// Push a (type, code, value) event onto `/dev/input/event<id>` with the
/// current monotonic timestamp. # C: O(1)
pub fn push_event(id: u32, ev_type: u16, code: u16, value: i32) {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    let ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let ns = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    let _ = Ordering::Acquire; // suppress unused-import warning when no-op cfg.
    let tv_sec  = ns / 1_000_000_000;
    let tv_usec = (ns % 1_000_000_000) / 1_000;
    queue(id).push(InputEvent { tv_sec, tv_usec, ev_type, code, value });
}
