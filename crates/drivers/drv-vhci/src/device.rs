//! The device state behind one open description.
//!
//! Reads and writes run in opposite directions and both are the host stack's
//! view inverted: what the stack sends the controller, this device hands to the
//! reading process, and what the process writes, the stack receives. The queue
//! between them is the transport's send path, so implementing the transport
//! contract is just enqueueing.

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use bluetooth::hci::transport::HciTransport;
use bluetooth::uapi::hci::HCI_VIRTUAL;
use sync::{HciDev as VhciLockClass, Spinlock};
use syscall::errno::Errno;

use crate::protocol::CreateFlags;

/// How many frames may wait for a reader before the queue drops the oldest.
///
/// A process that stops reading must not be able to grow kernel memory without
/// bound, and dropping the OLDEST rather than refusing the newest is what a
/// transport does: a stalled reader has already lost the trace, and refusing
/// new frames would instead stall the stack that is producing them.
pub const READ_QUEUE_LIMIT: usize = 256;

/// Frames waiting for the reading process, and how many were dropped.
#[derive(Default)]
pub struct ReadQueue {
    frames: VecDeque<Vec<u8>>,
    dropped: u64,
}

impl ReadQueue {
    /// An empty queue. # C: O(1)
    pub fn new() -> ReadQueue { ReadQueue { frames: VecDeque::new(), dropped: 0 } }

    /// Number of frames waiting. # C: O(1)
    pub fn len(&self) -> usize { self.frames.len() }

    /// Whether nothing is waiting. # C: O(1)
    pub fn is_empty(&self) -> bool { self.frames.is_empty() }

    /// Frames discarded because the reader fell too far behind. # C: O(1)
    pub fn dropped(&self) -> u64 { self.dropped }

    /// Queue a frame, discarding the oldest if the reader has fallen behind.
    /// # C: O(1)
    pub fn push(&mut self, frame: Vec<u8>) {
        if self.frames.len() >= READ_QUEUE_LIMIT {
            self.frames.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.frames.push_back(frame);
    }

    /// Queue a frame at the head, so an acknowledgement reaches the process
    /// before whatever the stack has already produced. # C: O(1)
    pub fn push_front(&mut self, frame: Vec<u8>) { self.frames.push_front(frame); }

    /// Take the oldest frame. # C: O(1)
    pub fn pop(&mut self) -> Option<Vec<u8>> { self.frames.pop_front() }

    /// Drop everything waiting. # C: O(n)
    pub fn clear(&mut self) { self.frames.clear(); }
}

/// One open description's device.
pub struct VhciDevice {
    queue: Spinlock<ReadQueue, VhciLockClass>,
    /// The controller index once one has been created, and `None` before.
    index: Spinlock<Option<u16>, VhciLockClass>,
    flags: Spinlock<CreateFlags, VhciLockClass>,
}

impl Default for VhciDevice {
    fn default() -> Self { Self::new() }
}

impl VhciDevice {
    /// A description with no controller behind it yet. # C: O(1)
    pub fn new() -> VhciDevice {
        VhciDevice {
            queue: Spinlock::new(ReadQueue::new()),
            index: Spinlock::new(None),
            flags: Spinlock::new(CreateFlags::default()),
        }
    }

    /// Whether a controller has been created on this description. # C: O(1)
    pub fn has_device(&self) -> bool { self.index.lock().is_some() }

    /// The controller index, once one exists. # C: O(1)
    pub fn index(&self) -> Option<u16> { *self.index.lock() }

    /// The properties the creation request asked for. # C: O(1)
    pub fn flags(&self) -> CreateFlags { *self.flags.lock() }

    /// Record the controller this description now owns and queue the
    /// acknowledgement ahead of anything else waiting. # C: O(1)
    pub fn attach(&self, flags: CreateFlags, index: u16) {
        *self.flags.lock() = flags;
        *self.index.lock() = Some(index);
        self.queue.lock().push_front(crate::protocol::creation_ack(flags, index));
    }

    /// Forget the controller and discard everything queued for it. # C: O(n)
    pub fn detach(&self) {
        *self.index.lock() = None;
        self.queue.lock().clear();
    }

    /// Take the next frame for the reading process. # C: O(1)
    pub fn read_frame(&self) -> Option<Vec<u8>> { self.queue.lock().pop() }

    /// Whether a read would return without blocking. # C: O(1)
    pub fn readable(&self) -> bool { !self.queue.lock().is_empty() }

    /// Frames discarded because the reader fell behind. # C: O(1)
    pub fn dropped(&self) -> u64 { self.queue.lock().dropped() }
}

impl HciTransport for VhciDevice {
    /// A virtual controller has nothing to bring up: the description through
    /// which it is served is already open, which is what created it.
    /// # C: O(1)
    fn open(&self) -> Result<(), Errno> {
        if self.index.lock().is_none() { return Err(Errno::Enodev); }
        Ok(())
    }

    /// # C: O(n)
    fn close(&self) { self.queue.lock().clear(); }

    /// # C: O(len)
    fn send(&self, frame: &[u8]) -> Result<(), Errno> {
        if self.index.lock().is_none() { return Err(Errno::Enodev); }
        self.queue.lock().push(frame.to_vec());
        Ok(())
    }

    /// # C: O(1)
    fn bus(&self) -> u8 { HCI_VIRTUAL }

    /// # C: O(1)
    fn driver_name(&self) -> String { "vhci".to_string() }
}

#[cfg(test)]
#[path = "tests/device.rs"]
mod tests;
