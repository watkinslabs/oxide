// The transport layer: what carries a call and matches its reply.
//
// Module manifest:
//   * `xid`     — transaction-identifier allocation.
//   * `timeout` — the retransmission schedule and its major/minor deadlines.
//   * `pending` — the outstanding-call table a reply is routed through.
//
// The transport trait itself lives here because it is the seam, and a seam
// belongs at the boundary it separates.

extern crate alloc;
use alloc::sync::{Arc, Weak};

use crate::err::RpcResult;

pub mod xid;
pub mod timeout;
pub mod pending;

pub use xid::XidGen;
pub use timeout::{RetryState, RpcTimeout, TimeoutOutcome};
pub use pending::{PendingCall, PendingTable};

/// Where a transport hands whole received RPC records.
pub trait RecordSink: Send + Sync {
    /// Deliver one complete record — an RPC message with framing already
    /// stripped. A record whose xid matches nothing outstanding is DROPPED, not
    /// an error: that is what a duplicate reply to a retransmission looks like,
    /// and it is the normal case on a lossy transport. # C: O(len)
    fn deliver(&self, record: &[u8]);
    /// The peer is gone. Every outstanding call fails and every waiter wakes.
    /// Idempotent. # C: O(N_pending)
    fn disconnect(&self);
}

/// A transport that carries RPC messages.
pub trait Transport: Send + Sync {
    /// Bind the sink received records are delivered to. Called once, before any
    /// call. # C: O(1)
    fn attach_sink(&self, sink: Weak<dyn RecordSink>);

    /// Transmit one complete RPC message. The transport applies whatever
    /// framing it needs — record marking on a stream, none on a datagram.
    /// Returning `Ok` means the bytes were handed to the network, NOT that a
    /// reply arrived. # C: transport-dependent
    fn send(&self, msg: &[u8]) -> RpcResult<()>;

    /// Largest RPC message this transport can carry in either direction.
    /// # C: O(1)
    fn max_record(&self) -> usize;

    /// Whether retransmitting a call is the transport's job or pointless.
    ///
    /// A datagram transport loses messages, so an unanswered call is resent. A
    /// stream transport does not: TCP already retransmits, and a second copy of
    /// the call would make the server execute a non-idempotent operation twice.
    /// # C: O(1)
    fn retransmits(&self) -> bool;

    /// False once the peer is gone. # C: O(1)
    fn is_connected(&self) -> bool;

    /// Tear the transport down; every later send fails. # C: O(1)
    fn shutdown(&self) {}
}

/// A transport shared by a client and whatever owns the socket.
pub type TransportRef = Arc<dyn Transport>;
