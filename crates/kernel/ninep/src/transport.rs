// The transport seam.
//
// A transport moves encoded frames and nothing else: it never inspects a tag,
// never decodes a body, and never decides whether an operation succeeded. It
// submits what the client hands it and delivers whole received frames back
// through a [`ReplySink`]. Both transports this kernel ships — a virtio queue
// and a byte stream — implement exactly this and share every line of protocol
// logic above it.
//
// Module manifest:
//   * `registry` — the `trans=` directory a mount resolves a transport through.

extern crate alloc;
use alloc::sync::{Arc, Weak};

use crate::err::NpResult;

pub mod registry;
pub use registry::{available, register, unregister, TransportFactory};
use crate::client::req::Request;

/// Where a transport hands received frames. The client implements it.
pub trait ReplySink: Send + Sync {
    /// Deliver one complete frame (`size[4] type[1] tag[2]` plus body). A frame
    /// whose tag matches nothing outstanding is dropped, not an error: that is
    /// what a duplicate or post-flush reply looks like. # C: O(frame)
    fn deliver(&self, frame: &[u8]);
    /// The peer is gone. Every outstanding request fails and every waiter
    /// wakes. Idempotent. # C: O(N_inflight)
    fn disconnect(&self);
}

/// A 9P transport.
pub trait Transport: Send + Sync {
    /// Bind the sink received frames are delivered to. Called once, before any
    /// request. # C: O(1)
    fn attach_sink(&self, sink: Weak<dyn ReplySink>);

    /// Submit `req` for transmission. Returning `Ok` means the bytes are queued
    /// or sent, NOT that a reply arrived. # C: transport-dependent
    fn submit(&self, req: &Arc<Request>) -> NpResult<()>;

    /// Try to withdraw a request that has not reached the wire.
    ///
    /// Returns `true` when the request is still in flight and can only be
    /// abandoned by an explicit `Tflush` — which is the CONSERVATIVE answer and
    /// therefore the default. A transport that wrongly reports a withdrawal
    /// lets the client release a tag whose reply is still coming, and that
    /// reply then lands on whichever request next takes the tag.
    /// # C: transport-dependent
    fn try_cancel(&self, _req: &Arc<Request>) -> bool { true }

    /// The server has confirmed (via `Rflush`) that `req` will never be
    /// answered, so the transport may forget it. # C: transport-dependent
    fn forget(&self, _req: &Arc<Request>) {}

    /// Largest frame this transport can carry. The negotiated `msize` is capped
    /// by it before the handshake, because a frame the transport cannot place
    /// in its descriptor chain is not recoverable at the protocol layer.
    /// # C: O(1)
    fn max_msize(&self) -> u32;

    /// False once the peer is gone. # C: O(1)
    fn is_connected(&self) -> bool;

    /// Tear the transport down; every later submit fails. # C: O(1)
    fn shutdown(&self) {}
}

/// A transport shared by a client and whatever owns the device.
pub type TransportRef = Arc<dyn Transport>;
