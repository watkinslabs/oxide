//! The per-handle event queue behind `SUBSCRIBE_EVENT`, `DQEVENT` and the
//! `POLLPRI` half of readiness.
//!
//! Events are per open file description, not per device: two programs watching
//! the same camera each get their own ring, so a slow one cannot starve a fast
//! one. Each subscription has a fixed depth chosen by the driver, and when it
//! overflows the OLDEST event of that subscription is dropped — the newest
//! state is the one worth keeping. Nothing counts the drops: the only signal
//! is a gap in the per-handle sequence number, which keeps rising across
//! dropped events precisely so the gap appears.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::uapi::flags;
use crate::uapi::layout;

/// One event, in the shape it reaches userspace.
#[derive(Copy, Clone, Debug)]
pub struct Event {
    pub ev_type: u32,
    pub id: u32,
    /// The 64-byte payload union, already encoded.
    pub payload: [u8; layout::EVENT_U_LEN],
    pub timestamp_sec: u64,
    pub timestamp_nsec: u64,
    /// Per-handle sequence, stamped at delivery.
    pub sequence: u32,
}

impl Event {
    /// An event of `ev_type` for object `id` with an empty payload. # C: O(1)
    pub fn new(ev_type: u32, id: u32) -> Event {
        Event { ev_type, id, payload: [0u8; layout::EVENT_U_LEN],
                timestamp_sec: 0, timestamp_nsec: 0, sequence: 0 }
    }
    /// A control-change event, with `v4l2_event_ctrl` in the payload.
    /// # C: O(1)
    pub fn control(id: u32, changes: u32, ctrl_type: u32, value: i64,
                   ctrl_flags: u32, minimum: i32, maximum: i32, step: i32, default_value: i32)
        -> Event
    {
        let mut ev = Event::new(flags::EVENT_CTRL, id);
        let p = &mut ev.payload;
        crate::usermem::w32(p, layout::EVENT_CTRL_CHANGES, changes);
        crate::usermem::w32(p, layout::EVENT_CTRL_TYPE, ctrl_type);
        // The value union is 64 bits wide; a 32-bit control's value occupies
        // its low half and the high half stays zero.
        crate::usermem::w64i(p, layout::EVENT_CTRL_VALUE, value);
        crate::usermem::w32(p, layout::EVENT_CTRL_FLAGS, ctrl_flags);
        crate::usermem::w32i(p, layout::EVENT_CTRL_MINIMUM, minimum);
        crate::usermem::w32i(p, layout::EVENT_CTRL_MAXIMUM, maximum);
        crate::usermem::w32i(p, layout::EVENT_CTRL_STEP, step);
        crate::usermem::w32i(p, layout::EVENT_CTRL_DEFAULT_VALUE, default_value);
        ev
    }
    /// A frame-sync event carrying the frame's sequence. # C: O(1)
    pub fn frame_sync(sequence: u32) -> Event {
        let mut ev = Event::new(flags::EVENT_FRAME_SYNC, 0);
        crate::usermem::w32(&mut ev.payload, layout::EVENT_FRAME_SYNC_SEQUENCE, sequence);
        ev
    }
    /// A source-change event naming what changed. # C: O(1)
    pub fn source_change(id: u32, changes: u32) -> Event {
        let mut ev = Event::new(flags::EVENT_SOURCE_CHANGE, id);
        crate::usermem::w32(&mut ev.payload, layout::EVENT_SRC_CHANGE_CHANGES, changes);
        ev
    }
}

/// Default ring depth for a subscription whose driver named none.
pub const DEFAULT_ELEMS: usize = 8;
/// Largest ring a subscription may have, so one handle cannot pin unbounded
/// memory by subscribing to a chatty event.
pub const MAX_ELEMS: usize = 64;

struct Subscription {
    ev_type: u32,
    id: u32,
    flags: u32,
    elems: usize,
    ring: VecDeque<Event>,
}

/// Every event one open file description is watching for.
pub struct EventQueue {
    subs: Vec<Subscription>,
    /// Arrival order across subscriptions, as subscription indices, so
    /// `DQEVENT` returns events in the order they happened rather than
    /// grouped by type.
    order: VecDeque<usize>,
    sequence: u32,
}

impl EventQueue {
    /// An empty queue with nothing subscribed. # C: O(1)
    pub fn new() -> EventQueue {
        EventQueue { subs: Vec::new(), order: VecDeque::new(), sequence: 0 }
    }

    /// How many events are waiting. # C: O(1)
    pub fn available(&self) -> usize { self.order.len() }
    /// Is anything waiting? This is the `POLLPRI` condition. # C: O(1)
    pub fn pending(&self) -> bool { !self.order.is_empty() }

    fn find(&self, ev_type: u32, id: u32) -> Option<usize> {
        self.subs.iter().position(|s| s.ev_type == ev_type && s.id == id)
    }

    /// `VIDIOC_SUBSCRIBE_EVENT`.
    ///
    /// The catch-all type may be unsubscribed but never subscribed: it names
    /// no event, and admitting it would leave a handle subscribed to something
    /// nothing ever delivers. Subscribing twice to the same event is a
    /// silent success, so a program that re-subscribes on reconnect does not
    /// have to track what it already has.
    /// # C: O(subscriptions)
    pub fn subscribe(&mut self, ev_type: u32, id: u32, sub_flags: u32, elems: usize)
        -> Result<(), Errno>
    {
        if ev_type == flags::EVENT_ALL { return Err(Errno::Einval); }
        if self.find(ev_type, id).is_some() { return Ok(()); }
        let elems = elems.clamp(1, MAX_ELEMS);
        self.subs.push(Subscription {
            ev_type, id, flags: sub_flags, elems, ring: VecDeque::new(),
        });
        Ok(())
    }

    /// Does this handle want the initial state of `ev_type`/`id` delivered
    /// straight after subscribing? # C: O(subscriptions)
    pub fn wants_initial(&self, ev_type: u32, id: u32) -> bool {
        self.find(ev_type, id)
            .map(|i| self.subs[i].flags & flags::EVENT_SUB_FL_SEND_INITIAL != 0)
            .unwrap_or(false)
    }

    /// Does this handle want its own writes echoed back to it? Without the
    /// feedback flag a control change this handle caused is not delivered to
    /// it, so a program does not process its own settings.
    /// # C: O(subscriptions)
    pub fn wants_feedback(&self, ev_type: u32, id: u32) -> bool {
        self.find(ev_type, id)
            .map(|i| self.subs[i].flags & flags::EVENT_SUB_FL_ALLOW_FEEDBACK != 0)
            .unwrap_or(false)
    }

    /// `VIDIOC_UNSUBSCRIBE_EVENT`. The catch-all type drops every
    /// subscription, which is what a handle does at close.
    /// # C: O(subscriptions + queued)
    pub fn unsubscribe(&mut self, ev_type: u32, id: u32) -> Result<(), Errno> {
        if ev_type == flags::EVENT_ALL {
            self.subs.clear();
            self.order.clear();
            return Ok(());
        }
        let Some(index) = self.find(ev_type, id) else { return Ok(()) };
        self.subs.remove(index);
        self.order.retain(|i| *i != index);
        // Indices above the removed one shift down; the order list holds
        // indices, so it has to follow.
        for slot in self.order.iter_mut() { if *slot > index { *slot -= 1; } }
        Ok(())
    }

    /// Deliver `ev` if this handle is subscribed to it.
    ///
    /// Returns `true` when the event was queued, which is the signal to wake
    /// the handle's pollers. The sequence advances on every delivery to a
    /// subscribed handle, including one whose ring was full — that is what
    /// makes a dropped event visible as a gap.
    /// # C: O(subscriptions)
    pub fn queue(&mut self, mut ev: Event, timestamp_sec: u64, timestamp_nsec: u64) -> bool {
        let Some(index) = self.find(ev.ev_type, ev.id) else { return false };
        self.sequence = self.sequence.wrapping_add(1);
        let elems = self.subs[index].elems;
        if self.subs[index].ring.len() >= elems {
            self.subs[index].ring.pop_front();
            if let Some(position) = self.order.iter().position(|i| *i == index) {
                self.order.remove(position);
            }
        }
        ev.sequence = self.sequence;
        ev.timestamp_sec = timestamp_sec;
        ev.timestamp_nsec = timestamp_nsec;
        self.subs[index].ring.push_back(ev);
        self.order.push_back(index);
        true
    }

    /// `VIDIOC_DQEVENT`.
    ///
    /// An empty queue is `ENOENT`, not `EAGAIN` — the reference deliberately
    /// differs from the buffer path here, and a program written against Linux
    /// tests for exactly that.
    ///
    /// The returned count is what remains AFTER this dequeue, which is what
    /// `v4l2_event.pending` reports.
    /// # C: O(1)
    pub fn dequeue(&mut self) -> Result<(Event, u32), Errno> {
        let Some(index) = self.order.pop_front() else { return Err(Errno::Enoent) };
        let Some(ev) = self.subs.get_mut(index).and_then(|s| s.ring.pop_front()) else {
            return Err(Errno::Enoent);
        };
        Ok((ev, self.order.len() as u32))
    }
}

impl Default for EventQueue {
    /// # C: O(1)
    fn default() -> Self { EventQueue::new() }
}
