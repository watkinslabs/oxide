// Linux evdev client queues. Each open file description owns one queue; an
// endpoint generation fans input values to every live client, or only its grab.

#![cfg(any(target_os = "oxide-kernel", test))]

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicI32, Ordering};

#[cfg(target_os = "oxide-kernel")]
use sched::live::wait_list::WaitList;
use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{PollSubscribers, POLL_ERR, POLL_HUP, POLL_IN, POLL_OUT};

use crate::{
    EVDEV_CLOCK_BOOTTIME as CLOCK_BOOTTIME,
    EVDEV_CLOCK_MONOTONIC as CLOCK_MONOTONIC,
    EVDEV_CLOCK_REALTIME as CLOCK_REALTIME,
    EV_SYN,
    SYN_DROPPED,
    SYN_REPORT,
};

#[cfg(test)]
pub(crate) struct WaitList;
#[cfg(test)]
impl WaitList {
    pub(crate) const fn new() -> Self { Self }
    pub(crate) fn wake_one(&self) {}
    pub(crate) fn wake_all(&self) {}
    pub(crate) unsafe fn park(&self) {}
    pub(crate) fn cancel_current_park(&self) {}
}

/// One 64-bit Linux `struct input_event`.
#[repr(C)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputEvent {
    pub tv_sec:  u64,
    pub tv_usec: u64,
    pub ev_type: u16,
    pub code:    u16,
    pub value:   i32,
}

pub const INPUT_EVENT_BYTES: usize = core::mem::size_of::<InputEvent>();
pub const MAX_EVDEV: usize = crate::MAX_INPUT_DEVICES;
const QUEUE_CAP: usize = 256;
const NSEC_PER_SEC: u64 = 1_000_000_000;
const NSEC_PER_USEC: u64 = 1_000;
const TV_SEC_OFF: usize = 0;
const TV_USEC_OFF: usize = TV_SEC_OFF + core::mem::size_of::<u64>();
const EVENT_TYPE_OFF: usize = TV_USEC_OFF + core::mem::size_of::<u64>();
const EVENT_CODE_OFF: usize = EVENT_TYPE_OFF + core::mem::size_of::<u16>();
const EVENT_VALUE_OFF: usize = EVENT_CODE_OFF + core::mem::size_of::<u16>();

struct ClientBuffer {
    events: VecDeque<InputEvent>,
    ready: usize,
}

/// Queue and wait sources owned by one evdev open file description.
pub(crate) struct EvdevClientQueue {
    buf: Spinlock<ClientBuffer, TaskListClass>,
    revoked: AtomicBool,
    disconnected: AtomicBool,
    clock_id: AtomicI32,
    pub(crate) waiters: WaitList,
    poll_subs: Arc<PollSubscribers>,
}

impl EvdevClientQueue {
    /// # C: O(1)
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            buf: Spinlock::new(ClientBuffer { events: VecDeque::new(), ready: 0 }),
            revoked: AtomicBool::new(false),
            disconnected: AtomicBool::new(false),
            clock_id: AtomicI32::new(CLOCK_REALTIME),
            waiters: WaitList::new(),
            poll_subs: Arc::new(PollSubscribers::new()),
        })
    }

    /// # C: O(1)
    pub(crate) fn poll_subscribers(&self) -> Arc<PollSubscribers> {
        Arc::clone(&self.poll_subs)
    }

    /// # C: O(1)
    pub(crate) fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    /// # C: O(1)
    pub(crate) fn is_disconnected(&self) -> bool {
        self.disconnected.load(Ordering::Acquire)
    }

    /// # C: O(1)
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.lock().ready == 0
    }

    /// Append one completed synchronization packet under one queue lock and
    /// one client-selected timestamp.
    /// # C: O(packet values)
    pub(crate) fn push_packet(&self, values: &[input::InputValue], times: EventTimes) {
        if values.len() < 2 || !values.last().is_some_and(|value| {
            value.ev_type == EV_SYN && value.code == SYN_REPORT
        }) {
            return;
        }
        let mut g = self.buf.lock();
        if self.revoked.load(Ordering::Acquire)
            || self.disconnected.load(Ordering::Acquire)
        {
            return;
        }
        let ns = match self.clock_id.load(Ordering::Acquire) {
            CLOCK_MONOTONIC => times.monotonic,
            CLOCK_BOOTTIME => times.boottime,
            _ => times.realtime,
        };
        let (tv_sec, tv_usec) = (
            ns / NSEC_PER_SEC,
            (ns % NSEC_PER_SEC) / NSEC_PER_USEC,
        );
        let overflow = g.events.len().saturating_add(values.len()) > QUEUE_CAP;
        let values = if overflow {
            g.events.clear();
            g.ready = 0;
            g.events.push_back(InputEvent {
                tv_sec,
                tv_usec,
                ev_type: EV_SYN,
                code: SYN_DROPPED,
                value: 0,
            });
            let retained = QUEUE_CAP.saturating_sub(1);
            &values[values.len().saturating_sub(retained)..]
        } else {
            values
        };
        for value in values {
            g.events.push_back(InputEvent {
                tv_sec,
                tv_usec,
                ev_type: value.ev_type,
                code: value.code,
                value: value.value,
            });
        }
        g.ready = g.events.len();
        drop(g);
        self.waiters.wake_all();
        self.poll_subs.notify_mask(POLL_IN | POLL_OUT);
    }

    /// # C: O(min(queued, dst / INPUT_EVENT_BYTES))
    pub(crate) fn try_pop_bytes(&self, dst: &mut [u8]) -> Option<usize> {
        if dst.len() < INPUT_EVENT_BYTES { return None; }
        let mut g = self.buf.lock();
        if self.revoked.load(Ordering::Acquire)
            || self.disconnected.load(Ordering::Acquire)
        {
            return None;
        }
        let count = (dst.len() / INPUT_EVENT_BYTES).min(g.ready);
        if count == 0 { return None; }
        for index in 0..count {
            let ev = g.events.pop_front().expect("count bounded by queue length");
            let start = index * INPUT_EVENT_BYTES;
            dst[start..start + INPUT_EVENT_BYTES].copy_from_slice(&ev_to_bytes(&ev));
        }
        g.ready -= count;
        Some(count * INPUT_EVENT_BYTES)
    }

    /// Copy canonical state and reconcile only this client's pending events.
    /// Caller holds the canonical input event/state lock before entering, so
    /// this queue lock gives Linux's event_lock -> client buffer_lock order.
    /// # C: O(bits + queued)
    pub(crate) fn copy_state_and_flush(
        &self,
        ev_type: u16,
        bits: &[u8],
        out: &mut [u8],
    ) -> usize {
        let mut g = self.buf.lock();
        let len = bits.len().min(out.len());
        out[..len].copy_from_slice(&bits[..len]);
        flush_type_locked(&mut g, ev_type);
        len
    }

    /// Set this client's timestamp clock and apply Linux's queue discontinuity.
    /// # C: O(queued)
    pub(crate) fn set_clock(&self, clock_id: i32) -> bool {
        if !matches!(clock_id, CLOCK_REALTIME | CLOCK_MONOTONIC | CLOCK_BOOTTIME) {
            return false;
        }
        let times = event_times();
        let now_ns = match clock_id {
            CLOCK_MONOTONIC => times.monotonic,
            CLOCK_BOOTTIME => times.boottime,
            _ => times.realtime,
        };
        let mut g = self.buf.lock();
        if self.clock_id.load(Ordering::Acquire) == clock_id { return true; }
        self.clock_id.store(clock_id, Ordering::Release);
        if !g.events.is_empty() {
            g.events.clear();
            g.ready = 0;
            g.events.push_back(InputEvent {
                tv_sec: now_ns / NSEC_PER_SEC,
                tv_usec: (now_ns % NSEC_PER_SEC) / NSEC_PER_USEC,
                ev_type: EV_SYN,
                code: SYN_DROPPED,
                value: 0,
            });
        }
        true
    }

    /// # C: O(queued)
    pub(crate) fn revoke(&self) {
        {
            let _g = self.buf.lock();
            self.revoked.store(true, Ordering::Release);
        }
        self.waiters.wake_all();
        self.poll_subs.notify_mask(POLL_HUP | POLL_ERR);
    }

    /// # C: O(queued)
    pub(crate) fn disconnect(&self) {
        {
            let _g = self.buf.lock();
            self.disconnected.store(true, Ordering::Release);
        }
        self.waiters.wake_all();
        self.poll_subs.notify_mask(POLL_HUP | POLL_ERR);
    }

}

fn flush_type_locked(buf: &mut ClientBuffer, ev_type: u16) {
    if ev_type == EV_SYN { return; }
    // Preserve packet framing, but remove a report that becomes empty after
    // all pending values of the selected type are reconciled.
    let mut values_in_report = 0usize;
    buf.events.retain(|ev| {
        let is_report = ev.ev_type == EV_SYN && ev.code == SYN_REPORT;
        let keep = ev.ev_type != ev_type && !(is_report && values_in_report == 0);
        if keep {
            if is_report {
                values_in_report = 0;
            } else {
                values_in_report += 1;
            }
        }
        keep
    });
    buf.ready = buf.events.iter().rposition(|ev| {
        ev.ev_type == EV_SYN && ev.code == SYN_REPORT
    }).map_or(0, |index| index + 1);
}

fn ev_to_bytes(ev: &InputEvent) -> [u8; INPUT_EVENT_BYTES] {
    let mut b = [0u8; INPUT_EVENT_BYTES];
    b[TV_SEC_OFF..TV_USEC_OFF].copy_from_slice(&ev.tv_sec.to_le_bytes());
    b[TV_USEC_OFF..EVENT_TYPE_OFF].copy_from_slice(&ev.tv_usec.to_le_bytes());
    b[EVENT_TYPE_OFF..EVENT_CODE_OFF].copy_from_slice(&ev.ev_type.to_le_bytes());
    b[EVENT_CODE_OFF..EVENT_VALUE_OFF].copy_from_slice(&ev.code.to_le_bytes());
    b[EVENT_VALUE_OFF..INPUT_EVENT_BYTES].copy_from_slice(&ev.value.to_le_bytes());
    b
}

pub(crate) fn output_value_from_bytes(record: &[u8]) -> Option<input::OutputEvent> {
    if record.len() != INPUT_EVENT_BYTES {
        return None;
    }
    Some(input::OutputEvent {
        ev_type: u16::from_le_bytes(
            record[EVENT_TYPE_OFF..EVENT_CODE_OFF].try_into().ok()?,
        ),
        code: u16::from_le_bytes(
            record[EVENT_CODE_OFF..EVENT_VALUE_OFF].try_into().ok()?,
        ),
        value: i32::from_le_bytes(
            record[EVENT_VALUE_OFF..INPUT_EVENT_BYTES].try_into().ok()?,
        ),
    })
}

#[derive(Copy, Clone)]
pub(crate) struct EventTimes {
    pub monotonic: u64,
    pub realtime: u64,
    pub boottime: u64,
}

fn event_times() -> EventTimes {
    use hal::TimerOps;
    #[cfg(target_arch = "x86_64")]
    let monotonic = hal_x86_64::X86TimerOps::monotonic_ns().0;
    #[cfg(target_arch = "aarch64")]
    let monotonic = hal_aarch64::ArmTimerOps::monotonic_ns().0;
    EventTimes {
        monotonic,
        realtime: timekeeper::realtime_ns(),
        boottime: timekeeper::boottime_ns(),
    }
}

/// Dispatch one canonical synchronization packet to clients of the current
/// endpoint generation.
/// # C: O(open clients × packet values)
pub fn push_packet(id: u32, values: &[input::InputValue]) {
    let times = event_times();
    if let Some(endpoint) = crate::devfs::current_endpoint(id) {
        endpoint.push_packet(values, times);
    }
}

#[cfg(test)]
mod tests;
