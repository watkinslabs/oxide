// The FUSE transport seam.
//
// A FUSE connection is a request broker; how an encoded request REACHES the
// server is a separate concern. Over `/dev/fuse` a request is appended to a
// queue that a userspace daemon drains with `read(2)`. Over a virtio queue
// there is no daemon and no `read`: the same encoded bytes are placed in a
// descriptor chain and the device writes the reply back.
//
// Everything above this seam — `unique` allocation, reply matching, the
// `ENOSYS` latches, the negotiated handshake, abort — is identical for both and
// lives once in the filesystem crate. A transport supplies only the send hooks
// and a teardown.
//
// The seam lives in its own crate because the two sides sit on opposite shores
// of the layering: the connection is a kernel filesystem, the virtio transport
// is a device driver, and neither may depend on the other. One shared trait is
// what keeps virtiofs from becoming a second FUSE implementation.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
use alloc::sync::{Arc, Weak};

/// Where a transport hands received reply frames — the connection implements it.
pub trait FuseReplySink: Send + Sync {
    /// Deliver one complete reply (`fuse_out_header` plus body). A frame whose
    /// `unique` matches nothing outstanding is DROPPED, not an error: that is
    /// what a duplicate or post-abort reply looks like. # C: O(frame)
    fn deliver(&self, frame: &[u8]);
    /// The server is gone. Every outstanding request fails and every waiter
    /// wakes. Idempotent. # C: O(N_inflight)
    fn disconnect(&self);
}

/// What a transport must do with an encoded FUSE message.
pub trait FuseTransportOps: Send + Sync {
    /// Bind the sink replies are delivered to. Called once, before the first
    /// request. # C: O(1)
    fn attach_sink(&self, sink: Weak<dyn FuseReplySink>);

    /// Deliver `msg` (a complete `fuse_in_header` plus body) toward the server.
    /// # C: transport-dependent
    fn send_req(&self, msg: &[u8]);

    /// Deliver a FORGET, which expects no reply and may take a priority path so
    /// a backlog of them cannot starve real requests. Defaults to the ordinary
    /// send. # C: transport-dependent
    fn send_forget(&self, msg: &[u8]) { self.send_req(msg); }

    /// Tell the server that the request carrying `unique` is being abandoned.
    ///
    /// The default does NOTHING, and that is the honest behaviour for a
    /// transport with no out-of-band channel: pretending to interrupt would
    /// leave the server working on a request whose caller has gone while the
    /// client believed it had been told. # C: transport-dependent
    fn send_interrupt(&self, _unique: u64) {}

    /// The connection is being torn down. # C: transport-dependent
    fn release(&self) {}

    /// Largest single message this transport can carry, capping the negotiated
    /// write size BEFORE the handshake. A message the transport cannot place in
    /// its descriptor chain is not recoverable at the protocol layer, so the
    /// limit is applied before the server is asked, never after. # C: O(1)
    fn max_message(&self) -> u32 { u32::MAX }
}

/// A transport shared by a connection and the device that owns it.
pub type FuseTransportRef = Arc<dyn FuseTransportOps>;

/// The directory a virtiofs mount resolves its `tag` through.
///
/// The transport lives in the driver crate that owns the device and publishes
/// itself here; the filesystem asks for a tag and never names the driver. One
/// opener, replaced rather than stacked: two openers for one tag is a second
/// source of truth about which device a mount reaches.
pub mod registry {
    use core::sync::atomic::{AtomicUsize, Ordering};
    use super::FuseTransportRef;

    /// Open the device carrying `tag`. `None` when no such device exists or a
    /// mount already holds it.
    pub type TagOpener = fn(&str) -> Option<FuseTransportRef>;

    /// The installed opener as a raw function address; `0` means none. A plain
    /// atomic rather than a lock because this is read on every mount and
    /// written twice in a boot.
    static OPENER: AtomicUsize = AtomicUsize::new(0);

    /// Publish `opener`. Idempotent; a later call replaces the earlier one.
    /// # C: O(1)
    pub fn register(opener: TagOpener) { OPENER.store(opener as usize, Ordering::Release); }

    /// Withdraw the opener, so a mount fails instead of reaching a driver that
    /// is going away. # C: O(1)
    pub fn unregister() { OPENER.store(0, Ordering::Release); }

    /// True when some driver can serve a virtiofs mount. # C: O(1)
    pub fn available() -> bool { OPENER.load(Ordering::Acquire) != 0 }

    /// Open the device carrying `tag` through the installed opener. # C: opener
    pub fn open(tag: &str) -> Option<FuseTransportRef> {
        let raw = OPENER.load(Ordering::Acquire);
        if raw == 0 { return None; }
        // SAFETY: `OPENER` only ever holds a value stored by `register`, which
        // takes a `TagOpener` and casts that exact function pointer; the zero
        // sentinel is filtered above, so the transmute reconstructs the same
        // function type it was written from.
        let f: TagOpener = unsafe { core::mem::transmute::<usize, TagOpener>(raw) };
        f(tag)
    }
}
