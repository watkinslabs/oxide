//! Event cache. Changes made while handling one packet are coalesced and
//! delivered once, at the end — a per-field notification per packet would put
//! more work on the wire than the traffic it describes.

extern crate alloc;
use alloc::vec::Vec;
use alloc::sync::Arc;

use sync::{Socket as SocketLockClass, Spinlock};

use crate::uapi::*;
use crate::entry::Conn;

/// A pending conntrack event.
#[derive(Clone, Debug)]
pub struct CtEvent { pub conn: Arc<Conn>, pub events: u32 }

/// A pending expectation event.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ExpEvent { pub master_id: u64, pub events: u32 }

/// Per-entry accumulated event mask, flushed when the packet is done.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct EventCache { pub pending: u32, pub missed: u32 }

impl EventCache {
    /// # C: O(1)
    pub fn cache(&mut self, bit: u32) { self.pending |= bit; }
    /// Take the accumulated mask. # C: O(1)
    pub fn take(&mut self) -> u32 { core::mem::take(&mut self.pending) }
    /// Record that a delivery failed, so the next one reports the loss rather
    /// than a state transition silently vanishing from the stream. # C: O(1)
    pub fn miss(&mut self, mask: u32) { self.missed |= mask; }
}

/// Queue of events awaiting delivery to ctnetlink listeners.
pub struct EventQueue {
    ct: Spinlock<Vec<CtEvent>, SocketLockClass>,
    exp: Spinlock<Vec<ExpEvent>, SocketLockClass>,
    /// Groups with at least one listener; events for other groups are dropped
    /// at the source rather than queued for nobody.
    pub subscribed: Spinlock<u32, SocketLockClass>,
}

/// ctnetlink multicast groups.
pub const NF_NETLINK_CONNTRACK_NEW:      u32 = 1 << 0;
pub const NF_NETLINK_CONNTRACK_UPDATE:   u32 = 1 << 1;
pub const NF_NETLINK_CONNTRACK_DESTROY:  u32 = 1 << 2;
pub const NF_NETLINK_CONNTRACK_EXP_NEW:     u32 = 1 << 3;
pub const NF_NETLINK_CONNTRACK_EXP_UPDATE:  u32 = 1 << 4;
pub const NF_NETLINK_CONNTRACK_EXP_DESTROY: u32 = 1 << 5;

/// The multicast group an event mask belongs to. New, destroy and update are
/// separate groups so a listener can take only the ones it needs.
/// # C: O(1)
pub fn group_for(events: u32) -> u32 {
    if events & IPCT_DESTROY != 0 { return NF_NETLINK_CONNTRACK_DESTROY; }
    if events & IPCT_NEW != 0 { return NF_NETLINK_CONNTRACK_NEW; }
    NF_NETLINK_CONNTRACK_UPDATE
}

/// The group one expectation event mask belongs to. # C: O(1)
pub fn exp_group_for(events: u32) -> u32 {
    if events & IPEXP_DESTROY != 0 { return NF_NETLINK_CONNTRACK_EXP_DESTROY; }
    if events & IPEXP_NEW != 0 { return NF_NETLINK_CONNTRACK_EXP_NEW; }
    NF_NETLINK_CONNTRACK_EXP_UPDATE
}

impl EventQueue {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { ct: Spinlock::new(Vec::new()), exp: Spinlock::new(Vec::new()),
               subscribed: Spinlock::new(0) }
    }

    /// Queue an event if anyone is listening for its group. # C: O(1)
    pub fn post(&self, conn: &Arc<Conn>, events: u32) -> bool {
        if events == 0 { return false; }
        if *self.subscribed.lock() & group_for(events) == 0 { return false; }
        self.ct.lock().push(CtEvent { conn: Arc::clone(conn), events });
        true
    }

    /// # C: O(1)
    pub fn post_expect(&self, master_id: u64, events: u32) -> bool {
        if events == 0 { return false; }
        if *self.subscribed.lock() & exp_group_for(events) == 0 { return false; }
        self.exp.lock().push(ExpEvent { master_id, events });
        true
    }

    /// # C: O(N)
    pub fn drain(&self) -> Vec<CtEvent> { core::mem::take(&mut *self.ct.lock()) }
    /// # C: O(N)
    pub fn drain_expect(&self) -> Vec<ExpEvent> { core::mem::take(&mut *self.exp.lock()) }

    /// # C: O(1)
    pub fn subscribe(&self, groups: u32) { *self.subscribed.lock() |= groups; }
    /// # C: O(1)
    pub fn unsubscribe(&self, groups: u32) { *self.subscribed.lock() &= !groups; }

    /// Replace all ctnetlink group subscriptions for this namespace. # C: O(1)
    pub fn set_subscribed(&self, groups: u32) { *self.subscribed.lock() = groups; }
}

impl Default for EventQueue { fn default() -> Self { Self::new() } }
