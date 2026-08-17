// The RPC client: encode a call, park for its reply, decode the header, hand
// the results back.
//
// Module manifest:
//   * `call`  — the request/reply engine and its retry ladder.
//   * `reply` — the decoded-reply handle callers read results from.
//   * `park_kernel` / `park_hosted` — how a caller waits, selected by target.

extern crate alloc;
use alloc::sync::Arc;

use sync::{Spinlock, Tty as RpcClass};

use crate::auth::Cred;
use crate::xprt::{PendingTable, RpcTimeout, TransportRef, XidGen};

pub mod call;
pub mod reply;

#[cfg(target_os = "oxide-kernel")]
mod park_kernel;
#[cfg(not(target_os = "oxide-kernel"))]
mod park_hosted;

pub use reply::Reply;

/// A monotonic clock in nanoseconds. Injected rather than reached for so the
/// retransmission schedule can be driven by a test clock; a module that called
/// the hardware timer directly could only be exercised by booting.
pub type NowNs = fn() -> u64;

/// How many times a call is retried before its failure is reported.
///
/// Two of each, matching the reference: enough that a credential the server
/// aged out, or a single garbled exchange, recovers without the application
/// seeing it, and few enough that a server which will never accept this
/// credential is reported rather than hammered.
pub const MAX_CRED_RETRY: u32 = 2;
/// See [`MAX_CRED_RETRY`].
pub const MAX_GARBAGE_RETRY: u32 = 2;

/// A bound RPC client: one program, one version, one transport, one credential.
pub struct RpcClient {
    /// RPC program number.
    pub prog: u32,
    /// Program version.
    pub vers: u32,
    transport: TransportRef,
    cred: Spinlock<Cred, RpcClass>,
    xids: XidGen,
    pending: PendingTable,
    timeout: RpcTimeout,
    now_ns: NowNs,
    dead: core::sync::atomic::AtomicBool,
    #[cfg(target_os = "oxide-kernel")]
    reply_wait: sched::live::WaitList,
}

impl RpcClient {
    /// Bind a client. `xid_seed` should come from the kernel's random source.
    /// # C: O(1)
    pub fn new(prog: u32, vers: u32, transport: TransportRef, cred: Cred,
               timeout: RpcTimeout, xid_seed: u32, now_ns: NowNs) -> Arc<Self> {
        let c = Arc::new(Self {
            prog, vers, transport, cred: Spinlock::new(cred),
            xids: XidGen::new(xid_seed),
            pending: PendingTable::new(),
            timeout, now_ns,
            dead: core::sync::atomic::AtomicBool::new(false),
            #[cfg(target_os = "oxide-kernel")]
            reply_wait: sched::live::WaitList::new(),
        });
        let sink: Arc<dyn crate::xprt::RecordSink> = c.clone();
        c.transport.attach_sink(Arc::downgrade(&sink));
        c
    }

    /// The credential calls are made under. # C: O(1)
    pub fn cred(&self) -> Cred { self.cred.lock().clone() }

    /// Replace the credential — a caller whose identity changed, or a
    /// re-authentication after the server aged the old one out. # C: O(1)
    pub fn set_cred(&self, cred: Cred) { *self.cred.lock() = cred; }

    /// The retransmission policy in force. # C: O(1)
    pub fn timeout(&self) -> RpcTimeout { self.timeout }

    /// Calls outstanding, for tests and diagnostics. # C: O(1)
    pub fn in_flight(&self) -> usize { self.pending.len() }

    /// The transport this client rides. # C: O(1)
    pub fn transport(&self) -> &TransportRef { &self.transport }
}
