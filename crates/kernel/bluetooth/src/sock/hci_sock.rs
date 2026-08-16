//! The raw controller socket and its channels.
//!
//! A socket's channel is fixed at bind and decides what it carries: raw frames
//! for its controller, exclusive ownership of a controller, a copy of every
//! frame on every controller, the management surface, or a logging sink.
//!
//! The channel is chosen at bind and never afterwards, because everything a
//! socket may do depends on it — a socket that could change channel would carry
//! one channel's traffic under another's permission screen.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::hci::filter::Filter;
use crate::uapi::hci_sock::{
    HCI_CHANNEL_CONTROL, HCI_CHANNEL_LOGGING, HCI_CHANNEL_MONITOR, HCI_CHANNEL_RAW,
    HCI_CHANNEL_USER, HCI_DEV_NONE,
};

/// How many frames may wait on one socket before the oldest is dropped. A
/// socket that stops reading must not grow kernel memory without bound.
pub const RX_QUEUE_LIMIT: usize = 512;

/// What a bind request asks for, once validated.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct BindPlan {
    pub channel: u16,
    /// The controller the socket attaches to, or `None` for the channels that
    /// are not bound to one.
    pub dev: Option<u16>,
}

/// Whether a channel number names a real channel. # C: O(1)
pub fn channel_known(channel: u16) -> bool {
    matches!(channel, HCI_CHANNEL_RAW | HCI_CHANNEL_USER | HCI_CHANNEL_MONITOR
        | HCI_CHANNEL_CONTROL | HCI_CHANNEL_LOGGING)
}

/// Whether a channel is bound to one controller. The monitor sees every
/// controller and the management and logging channels address controllers by
/// index inside their own messages, so none of the three takes one here.
/// # C: O(1)
pub fn channel_takes_device(channel: u16) -> bool {
    matches!(channel, HCI_CHANNEL_RAW | HCI_CHANNEL_USER)
}

/// Whether a channel requires privilege to bind.
///
/// Every channel but the management one does: raw and user access reach the
/// controller directly, the monitor sees every controller's traffic including
/// another process's, and the logging channel injects into that trace. The
/// management channel is the one userspace binds unprivileged, and its own
/// per-command trust screen decides what it may then do. # C: O(1)
pub fn channel_privileged(channel: u16) -> bool { channel != HCI_CHANNEL_CONTROL }

/// Decide one bind request.
///
/// `controller_exists` is consulted only for the channels that name one, so a
/// monitor bind does not fail because a controller happens to be absent.
/// # C: O(1)
pub fn plan_bind<F: FnOnce(u16) -> bool>(
    channel: u16, dev: u16, has_admin: bool, controller_exists: F,
) -> Result<BindPlan, Errno> {
    if !channel_known(channel) { return Err(Errno::Einval); }
    if channel_privileged(channel) && !has_admin { return Err(Errno::Eperm); }
    if !channel_takes_device(channel) { return Ok(BindPlan { channel, dev: None }); }
    // The raw channel accepts the no-controller index, which leaves the socket
    // bound to the channel but attached to nothing; the exclusive channel does
    // not, because there is nothing to take exclusive ownership of.
    if dev == HCI_DEV_NONE {
        if channel == HCI_CHANNEL_USER { return Err(Errno::Einval); }
        return Ok(BindPlan { channel, dev: None });
    }
    if !controller_exists(dev) { return Err(Errno::Enodev); }
    Ok(BindPlan { channel, dev: Some(dev) })
}

/// One raw controller socket.
pub struct HciSocket {
    pub bound: Option<BindPlan>,
    pub filter: Filter,
    /// Whether received frames carry their direction as ancillary data.
    pub data_dir: bool,
    /// Whether received frames carry a timestamp as ancillary data.
    pub time_stamp: bool,
    queue: VecDeque<Vec<u8>>,
    dropped: u64,
}

impl Default for HciSocket {
    fn default() -> Self { Self::new() }
}

impl HciSocket {
    /// An unbound socket whose filter passes nothing. # C: O(1)
    pub fn new() -> HciSocket {
        HciSocket {
            bound: None, filter: Filter::new(), data_dir: false, time_stamp: false,
            queue: VecDeque::new(), dropped: 0,
        }
    }

    /// The channel the socket is bound to, if any. # C: O(1)
    pub fn channel(&self) -> Option<u16> { self.bound.map(|b| b.channel) }

    /// The controller the socket is attached to, if any. # C: O(1)
    pub fn device(&self) -> Option<u16> { self.bound.and_then(|b| b.dev) }

    /// Record a completed bind. A socket already bound is refused: everything a
    /// socket may do depends on its channel, so changing it would carry one
    /// channel's traffic under another's permission screen. # C: O(1)
    pub fn bind(&mut self, plan: BindPlan) -> Result<(), Errno> {
        if self.bound.is_some() { return Err(Errno::Einval); }
        self.bound = Some(plan);
        Ok(())
    }

    /// Whether a frame from this controller passes the socket's screens.
    ///
    /// The controller screen runs first: a socket attached to one controller
    /// must never see another's traffic, whatever its filter says. # C: O(1)
    pub fn accepts(&self, from_dev: u16, pkt_type: u8, head: u16) -> bool {
        let Some(plan) = self.bound else { return false; };
        if let Some(dev) = plan.dev {
            if dev != from_dev { return false; }
        }
        match plan.channel {
            // The monitor and the management channel carry their own record
            // framing and are not screened by the packet filter.
            HCI_CHANNEL_MONITOR | HCI_CHANNEL_CONTROL => true,
            HCI_CHANNEL_RAW | HCI_CHANNEL_USER => self.filter.passes(pkt_type, head),
            _ => false,
        }
    }

    /// Queue a frame, dropping the oldest if the reader has fallen behind.
    /// # C: O(1)
    pub fn push(&mut self, frame: Vec<u8>) {
        if self.queue.len() >= RX_QUEUE_LIMIT {
            self.queue.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.queue.push_back(frame);
    }

    /// Take the oldest queued frame. # C: O(1)
    pub fn pop(&mut self) -> Option<Vec<u8>> { self.queue.pop_front() }

    /// Whether a read would return without blocking. # C: O(1)
    pub fn readable(&self) -> bool { !self.queue.is_empty() }

    /// Frames discarded because the reader fell behind. # C: O(1)
    pub fn dropped(&self) -> u64 { self.dropped }
}

#[cfg(test)]
#[path = "tests/hci_sock.rs"]
mod tests;
