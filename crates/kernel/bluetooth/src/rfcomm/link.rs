//! The contract between the multiplexer and everything outside it.
//!
//! A session neither creates nor owns the channel it runs over: it is handed
//! complete frames and it hands complete frames back. One frame is one service
//! data unit on the channel below, which is what makes the check byte the last
//! byte of the unit and the address byte the first.
//!
//! The host also answers the one question the multiplexer cannot: whether an
//! inbound server channel is being listened on. Answering it from a table
//! inside the multiplexer would be a second copy of the socket layer's
//! listeners, so it is asked instead.

use alloc::vec::Vec;
use syscall::errno::Errno;

/// The channel below. One call carries one complete frame.
pub trait L2capTx {
    /// Hand one frame to the channel. # C: O(n) in frame length
    fn send(&mut self, frame: &[u8]) -> Result<(), Errno>;
}

/// What a session needs from the layer above it.
pub trait SessionHost: L2capTx {
    /// Whether an inbound server channel should be accepted. # C: O(1)
    fn connect_ind(&mut self, channel: u8) -> bool;

    /// Whether a DLC that is being accepted must complete a security procedure
    /// first. Reporting `true` means the link already satisfies the level the
    /// DLC asked for. # C: O(1)
    fn check_security(&mut self, dlci: u8, sec_level: u8) -> bool {
        let _ = (dlci, sec_level);
        true
    }

    /// Whether an accepted DLC hands the decision back to userspace before
    /// answering the peer. # C: O(1)
    fn defer_setup(&mut self, channel: u8) -> bool { let _ = channel; false }
}

/// A collector standing in for the channel below, which is what a test drives a
/// session with and what a caller can use to batch a pass's output.
#[derive(Default, Debug)]
pub struct FrameLog {
    pub frames: Vec<Vec<u8>>,
    /// Server channels that would be accepted.
    pub listening: Vec<u8>,
    /// Whether an accepted DLC defers to userspace.
    pub defer: bool,
    /// Whether the link is treated as already secure enough.
    pub secure: bool,
}

impl FrameLog {
    /// A log accepting nothing, with security satisfied. # C: O(1)
    pub fn new() -> FrameLog {
        FrameLog { frames: Vec::new(), listening: Vec::new(), defer: false, secure: true }
    }

    /// A log accepting these server channels. # C: O(n)
    pub fn listening(channels: &[u8]) -> FrameLog {
        FrameLog { frames: Vec::new(), listening: channels.to_vec(), defer: false, secure: true }
    }

    /// Drop everything collected so far. # C: O(n)
    pub fn clear(&mut self) { self.frames.clear(); }

    /// Number of frames collected. # C: O(1)
    pub fn len(&self) -> usize { self.frames.len() }

    /// Whether nothing has been collected. # C: O(1)
    pub fn is_empty(&self) -> bool { self.frames.is_empty() }

    /// The last frame collected. # C: O(1)
    pub fn last(&self) -> Option<&Vec<u8>> { self.frames.last() }
}

impl L2capTx for FrameLog {
    /// Collect one frame. # C: O(n)
    fn send(&mut self, frame: &[u8]) -> Result<(), Errno> {
        self.frames.push(frame.to_vec());
        Ok(())
    }
}

impl SessionHost for FrameLog {
    /// Accept the channels the log was built with. # C: O(n)
    fn connect_ind(&mut self, channel: u8) -> bool { self.listening.contains(&channel) }

    /// Report the configured security verdict. # C: O(1)
    fn check_security(&mut self, _dlci: u8, _sec_level: u8) -> bool { self.secure }

    /// Report the configured deferral. # C: O(1)
    fn defer_setup(&mut self, _channel: u8) -> bool { self.defer }
}

/// What a session reports upward. A state change carries the errno the peer's
/// refusal maps onto, zero when the change is not a failure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DlcEvent {
    StateChange { dlci: u8, state: u8, err: i32 },
    Data { dlci: u8, data: Vec<u8> },
    ModemStatus { dlci: u8, v24_sig: u8 },
    LineStatus { dlci: u8, status: u8 },
}
