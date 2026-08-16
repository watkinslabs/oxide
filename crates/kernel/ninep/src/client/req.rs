// One in-flight transaction and its lifecycle state.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};

use sync::{Spinlock, Tty as NpClass};

/// Lifecycle of a request. The ordering is load-bearing: every terminal state
/// compares GREATER THAN OR EQUAL to [`ReqStatus::Received`], so one numeric
/// test wakes a waiter for a reply, an error and a flush alike.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum ReqStatus {
    /// Allocated, not yet handed to the transport.
    Allocated = 0,
    /// Queued in the transport, bytes not yet on the wire.
    Unsent = 1,
    /// Bytes written; a reply is expected.
    Sent = 2,
    /// Reply received and stored.
    Received = 3,
    /// Abandoned by a `Tflush`; a late reply for this tag MUST be discarded.
    Flushed = 4,
    /// The transport failed or the connection dropped.
    Errored = 5,
}

impl ReqStatus {
    /// # C: O(1)
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => ReqStatus::Allocated,
            1 => ReqStatus::Unsent,
            2 => ReqStatus::Sent,
            3 => ReqStatus::Received,
            4 => ReqStatus::Flushed,
            _ => ReqStatus::Errored,
        }
    }
    /// True once the request will never change state again, so a waiter may
    /// stop parking. # C: O(1)
    pub fn is_terminal(self) -> bool { self >= ReqStatus::Received }
}

/// One 9P transaction. The encoded request bytes live in `tc`; the transport
/// fills `rc` with the whole received frame (header included) and then moves
/// the status to a terminal value.
pub struct Request {
    /// Transaction tag this request occupies until it is released.
    pub tag: u16,
    /// Request opcode, kept so a reply of the wrong type is caught.
    pub ty: u8,
    /// Encoded outgoing frame.
    pub tc: Vec<u8>,
    /// Received reply frame, header included.
    pub rc: Spinlock<Vec<u8>, NpClass>,
    status: AtomicU8,
}

impl Request {
    /// # C: O(1)
    pub fn new(tag: u16, ty: u8, tc: Vec<u8>) -> Self {
        Self { tag, ty, tc, rc: Spinlock::new(Vec::new()), status: AtomicU8::new(ReqStatus::Allocated as u8) }
    }

    /// # C: O(1)
    pub fn status(&self) -> ReqStatus { ReqStatus::from_u8(self.status.load(Ordering::Acquire)) }

    /// # C: O(1)
    pub fn set_status(&self, s: ReqStatus) { self.status.store(s as u8, Ordering::Release); }

    /// Move to `s` only if the current status is `from`, reporting whether the
    /// move happened. Used where two paths race for one transition — a reply
    /// arriving while a flush decides to abandon the request — so exactly one
    /// of them completes it. # C: O(1)
    pub fn compare_set_status(&self, from: ReqStatus, s: ReqStatus) -> bool {
        self.status.compare_exchange(from as u8, s as u8, Ordering::AcqRel, Ordering::Acquire).is_ok()
    }

    /// # C: O(1)
    pub fn is_done(&self) -> bool { self.status().is_terminal() }

    /// Store a received frame and complete the request. A request already in a
    /// terminal state is NOT overwritten: a reply that arrives after a flush
    /// abandoned the tag is stale and its bytes must not reach the caller, who
    /// may already have returned. Reports whether the reply was accepted.
    /// # C: O(frame)
    pub fn complete(&self, frame: &[u8]) -> bool {
        // The bytes are published BEFORE the status flips, and the flip happens
        // while the reply lock is still held. A waiter observes the terminal
        // status and only then takes the lock, so it can never see `Received`
        // over an empty buffer — the ordering the other way round hands the
        // caller a zero-length reply that decodes as a truncated message.
        let mut g = self.rc.lock();
        if self.status().is_terminal() { return false; }
        g.clear();
        g.extend_from_slice(frame);
        let took = self.compare_set_status(ReqStatus::Sent, ReqStatus::Received)
            || self.compare_set_status(ReqStatus::Unsent, ReqStatus::Received)
            || self.compare_set_status(ReqStatus::Allocated, ReqStatus::Received);
        if !took { g.clear(); }
        took
    }

    /// Fail the request (transport death, submit failure). # C: O(1)
    pub fn fail(&self) { self.set_status(ReqStatus::Errored); }
}

impl core::fmt::Debug for Request {
    /// Names the tag and opcode only: the encoded frame is bulk and the reply
    /// lock must not be taken from a formatting path. # C: O(1)
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Request")
            .field("tag", &self.tag)
            .field("ty", &self.ty)
            .field("status", &self.status())
            .finish()
    }
}
