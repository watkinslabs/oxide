// The 9P client — everything above the transport and below the filesystem.
//
// Module manifest:
//   * `req`         — one in-flight transaction and its lifecycle states.
//   * `tags`        — transaction-tag occupancy; the reply-matching authority.
//   * `fid`         — fid numbers, handle identity, and clunk-on-drop.
//   * `rpc`         — submit/park/match/decode, `Tflush`, disconnect.
//   * `session`     — version negotiation, attach, auth.
//   * `walk`        — path walking with its element-count chunking.
//   * `io`          — read/write/readdir transfer sizing and short-transfer loops.
//   * `ops_dotl`    — the `9P2000.L` operation set.
//   * `ops_legacy`  — the 9P2000(.u) operation set.

extern crate alloc;
use alloc::sync::{Arc, Weak};
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sync::{Spinlock, Tty as NpClass};

use crate::codec::Dialect;
use crate::err::{NpError, NpResult};
use crate::transport::{ReplySink, TransportRef};
use crate::uapi::{limits, op};

pub mod req;
pub mod tags;
pub mod fid;
pub mod rpc;
pub mod session;
pub mod walk;
pub mod io;
pub mod ops_dotl;
pub mod ops_legacy;

pub use fid::{Fid, FidOwner, FidRef, FidTable};
pub use req::{ReqStatus, Request};
pub use rpc::{decode_reply, Reply};
pub use tags::TagTable;

/// Hosted-test stand-in for the live wait list, mirroring the FUSE channel's:
/// the park is unreachable without a scheduler, and the hosted tests drive
/// completion synchronously from the scripted transport.
#[cfg(not(target_os = "oxide-kernel"))]
pub struct WaitList;
#[cfg(not(target_os = "oxide-kernel"))]
impl WaitList {
    /// # C: O(1)
    pub const fn new() -> Self { Self }
    /// # C: O(1)
    pub fn wake_all(&self) {}
}
#[cfg(not(target_os = "oxide-kernel"))]
impl Default for WaitList {
    fn default() -> Self { Self::new() }
}

/// The wait list blocked callers park on.
#[cfg(target_os = "oxide-kernel")]
pub type WaitList = sched::live::wait_list::WaitList;

/// A 9P session: one transport, one negotiated dialect, one fid space.
pub struct Client {
    pub(crate) transport: TransportRef,
    pub(crate) tags: TagTable,
    pub(crate) fids: FidTable,
    pub(crate) msize: AtomicU32,
    pub(crate) dialect: Spinlock<Dialect, NpClass>,
    pub(crate) reply_wait: WaitList,
    pub(crate) dead: AtomicBool,
    /// Weak self-reference so a [`Fid`] can clunk itself on drop without
    /// keeping the client alive past its last mount.
    pub(crate) me: Weak<Client>,
}

impl Client {
    /// Build a session over `transport`, requesting `dialect` and `msize`.
    ///
    /// `msize` is clamped to what the transport can frame BEFORE the handshake,
    /// because a value the transport cannot place in a descriptor chain is not
    /// recoverable once the server has agreed to it. A request below the
    /// protocol floor is refused outright rather than raised — a mount that
    /// asked for an unusable size should hear about it. # C: O(1)
    pub fn new(transport: TransportRef, dialect: Dialect, msize: u32) -> NpResult<Arc<Self>> {
        if msize < limits::MIN_MSIZE { return Err(NpError::BadVersion); }
        let capped = msize.min(transport.max_msize());
        if capped < limits::MIN_MSIZE { return Err(NpError::BadVersion); }
        let client = Arc::new_cyclic(|me: &Weak<Client>| Client {
            transport,
            tags: TagTable::new(),
            fids: FidTable::new(),
            msize: AtomicU32::new(capped),
            dialect: Spinlock::new(dialect),
            reply_wait: WaitList::new(),
            dead: AtomicBool::new(false),
            me: me.clone(),
        });
        let sink: Weak<dyn ReplySink> = {
            let strong: Arc<dyn ReplySink> = client.clone();
            Arc::downgrade(&strong)
        };
        client.transport.attach_sink(sink);
        Ok(client)
    }

    /// The transport this session speaks over. # C: O(1)
    pub fn transport(&self) -> &TransportRef { &self.transport }

    /// Allocate a fid handle that clunks itself when the last reference drops.
    /// The number is reserved immediately so a concurrent walk cannot take it.
    /// # C: O(log N)
    pub fn new_fid(&self, uid: u32) -> NpResult<FidRef> {
        let n = self.fids.alloc()?;
        let owner: Weak<dyn FidOwner + Send + Sync> = match self.me.upgrade() {
            Some(strong) => {
                let o: Arc<dyn FidOwner + Send + Sync> = strong;
                Arc::downgrade(&o)
            }
            // The session is already being torn down; the handle can still be
            // built, and its drop simply releases the number locally.
            None => Weak::<Client>::new() as Weak<dyn FidOwner + Send + Sync>,
        };
        Ok(Arc::new(Fid::new(n, uid, owner)))
    }

    /// Tear the session down: fail every outstanding request and stop the
    /// transport. # C: O(N_inflight)
    pub fn shutdown(&self) {
        self.disconnect();
        self.transport.shutdown();
    }
}

impl FidOwner for Client {
    /// # C: RPC
    fn clunk(&self, fid: u32) -> NpResult<()> {
        let r = if self.is_dead() { Err(NpError::Disconnected) }
                else { self.rpc(op::TCLUNK, |e| e.u32(fid)).map(|_| ()) };
        // The number returns to the pool whatever the server said: the client
        // can no longer address the handle, and holding the number back would
        // leak the local slot on every failed clunk.
        self.fids.release(fid);
        r
    }

    /// # C: O(log N)
    fn forget(&self, fid: u32) { self.fids.release(fid); }
}

impl Client {
    /// Publish the outcome of a version handshake. # C: O(1)
    pub(crate) fn set_negotiated(&self, dialect: Dialect, msize: u32) {
        *self.dialect.lock() = dialect;
        self.msize.store(msize, Ordering::Release);
    }
}

impl core::fmt::Debug for Client {
    /// # C: O(1)
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("dialect", &self.dialect())
            .field("msize", &self.msize())
            .field("in_flight", &self.in_flight())
            .field("live_fids", &self.live_fids())
            .finish()
    }
}
