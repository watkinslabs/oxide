// AF_VSOCK STREAM connection state machine + credit accounting +
// connection table. PURE protocol logic over the wire format in
// `super::hdr` — the actual ring DMA is a TX hook installed by the
// driver (drv-virtio-vsock). Host-testable: every state transition,
// credit-math path, and the 5 STREAM ops are exercised in `tests`.
//
// Credit model (virtio 1.2 §5.10.6.3): each side advertises buf_alloc
// (its RX ring capacity) + fwd_cnt (bytes it has consumed). A sender
// may have at most `peer_buf_alloc - (tx_cnt - peer_fwd_cnt)` bytes in
// flight. We track our own rx_cnt (bytes delivered to userspace) to
// publish fwd_cnt, and the peer's last-seen buf_alloc/fwd_cnt to gate
// OP_RW sends.

use alloc::vec::Vec;
use alloc::collections::VecDeque;
use sync::{Spinlock, Socket as SockLockClass};
use super::hdr::*;

/// Per-connection RX buffer budget advertised to the peer. Matches the
/// driver's RX ring in-flight capacity (8 × 4 KiB buffers, refilled each
/// tick) so the credit we grant never overcommits what the device ring
/// can hold between drains. # C: O(1)
pub const VSOCK_DEFAULT_BUF_ALLOC: u32 = 8 * 4096;

/// Connection life-cycle. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VsockState {
    /// Local connect() sent OP_REQUEST, awaiting OP_RESPONSE.
    Connecting,
    /// OP_RESPONSE seen (client) or OP_REQUEST accepted (server).
    Connected,
    /// Peer sent OP_SHUTDOWN(SEND) or we received EOF — read side done.
    RcvShutdown,
    /// Fully torn down (OP_RST seen/sent, or close()).
    Closed,
}

/// One vsock STREAM connection. Keyed in the table by the 4-tuple
/// (local_cid, local_port, peer_cid, peer_port). # C: O(1)
pub struct VsockConn {
    pub local_cid:  u64,
    pub local_port: u32,
    pub peer_cid:   u64,
    pub peer_port:  u32,
    pub st: Spinlock<VsockState, SockLockClass>,
    /// Received OP_RW payload bytes, FIFO; recv() drains the front.
    pub rx: Spinlock<VecDeque<u8>, SockLockClass>,
    /// Credit + counter cells (see module doc). All under one lock so
    /// the send-gate computation is atomic.
    pub credit: Spinlock<Credit, SockLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub waiters: sched::live::WaitList,
}

/// Credit + byte counters for one connection. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Credit {
    /// Total payload bytes we have transmitted (OP_RW) to the peer.
    pub tx_cnt: u32,
    /// Total payload bytes we have delivered to userspace (our fwd_cnt).
    pub fwd_cnt: u32,
    /// Peer's advertised RX buffer size (last seen).
    pub peer_buf_alloc: u32,
    /// Peer's advertised fwd_cnt (bytes it has consumed; last seen).
    pub peer_fwd_cnt: u32,
    /// Our advertised RX buffer size.
    pub buf_alloc: u32,
}

impl Default for Credit {
    fn default() -> Self {
        Credit {
            tx_cnt: 0, fwd_cnt: 0,
            peer_buf_alloc: 0, peer_fwd_cnt: 0,
            buf_alloc: VSOCK_DEFAULT_BUF_ALLOC,
        }
    }
}

impl Credit {
    /// Bytes the peer can still accept = peer_buf_alloc - in-flight,
    /// where in-flight = tx_cnt - peer_fwd_cnt. Saturating so a stale
    /// snapshot never wraps. # C: O(1)
    pub fn peer_credit(&self) -> u32 {
        let in_flight = self.tx_cnt.wrapping_sub(self.peer_fwd_cnt);
        self.peer_buf_alloc.saturating_sub(in_flight)
    }
    /// Fold a credit announcement (any incoming hdr carries buf_alloc +
    /// fwd_cnt) into our view of the peer. # C: O(1)
    pub fn observe_peer(&mut self, buf_alloc: u32, fwd_cnt: u32) {
        self.peer_buf_alloc = buf_alloc;
        self.peer_fwd_cnt = fwd_cnt;
    }
}

impl VsockConn {
    /// New connection in `st`. # C: O(1)
    pub fn new(local_cid: u64, local_port: u32, peer_cid: u64, peer_port: u32,
               st: VsockState) -> Self {
        VsockConn {
            local_cid, local_port, peer_cid, peer_port,
            st: Spinlock::new(st),
            rx: Spinlock::new(VecDeque::new()),
            credit: Spinlock::new(Credit::default()),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
        }
    }

    /// Build the header for a control/data packet from this conn, filling
    /// in the live credit fields. # C: O(1)
    pub fn make_hdr(&self, op: u16, len: u32, flags: u32) -> VsockHdr {
        let c = self.credit.lock();
        VsockHdr {
            src_cid:  self.local_cid,
            dst_cid:  self.peer_cid,
            src_port: self.local_port,
            dst_port: self.peer_port,
            len,
            typ: VIRTIO_VSOCK_TYPE_STREAM,
            op,
            flags,
            buf_alloc: c.buf_alloc,
            fwd_cnt:   c.fwd_cnt,
        }
    }

    /// Match key for the table. # C: O(1)
    pub fn key(&self) -> ConnKey {
        ConnKey {
            local_cid: self.local_cid, local_port: self.local_port,
            peer_cid: self.peer_cid, peer_port: self.peer_port,
        }
    }
}

/// 4-tuple connection key. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ConnKey {
    pub local_cid:  u64,
    pub local_port: u32,
    pub peer_cid:   u64,
    pub peer_port:  u32,
}

/// Process-global vsock connection table. v1: a Vec scanned linearly —
/// vsock fan-out is small (a handful of host↔guest streams). # C: see fns
pub struct VsockTable {
    conns: Spinlock<Vec<alloc::sync::Arc<VsockConn>>, SockLockClass>,
    /// Bound listeners: (local_port) → accept backlog of pending peers.
    listeners: Spinlock<Vec<Listener>, SockLockClass>,
    /// Ephemeral local-port allocator (1024..).
    ephem_next: core::sync::atomic::AtomicU32,
}

/// A bound listener + its accept backlog of inbound OP_REQUESTs that
/// haven't been accept()ed yet. # C: O(1)
pub struct Listener {
    pub local_port: u32,
    pub backlog: Spinlock<VecDeque<ConnKey>, SockLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
}

impl VsockTable {
    /// Empty table (const so it backs the process-global static).
    /// # C: O(1)
    pub const fn new() -> Self {
        VsockTable {
            conns: Spinlock::new(Vec::new()),
            listeners: Spinlock::new(Vec::new()),
            ephem_next: core::sync::atomic::AtomicU32::new(1024),
        }
    }

    /// Allocate an unused ephemeral local port. # C: O(1) amortized
    pub fn alloc_port(&self) -> u32 {
        use core::sync::atomic::Ordering;
        let p = self.ephem_next.fetch_add(1, Ordering::Relaxed);
        if p < 1024 { 1024 } else { p }
    }

    /// Insert a connection. # C: O(1)
    pub fn insert(&self, c: alloc::sync::Arc<VsockConn>) {
        self.conns.lock().push(c);
    }

    /// Look up a connection by key. # C: O(N conns)
    pub fn find(&self, k: ConnKey) -> Option<alloc::sync::Arc<VsockConn>> {
        self.conns.lock().iter().find(|c| c.key() == k).cloned()
    }

    /// Look up by the *local* 2-tuple regardless of peer — used by the
    /// RX dispatcher which keys on (dst_cid, dst_port, src_cid, src_port)
    /// of the incoming packet. # C: O(N conns)
    pub fn find_for_rx(&self, local_cid: u64, local_port: u32,
                       peer_cid: u64, peer_port: u32)
        -> Option<alloc::sync::Arc<VsockConn>>
    {
        self.find(ConnKey { local_cid, local_port, peer_cid, peer_port })
    }

    /// Remove a connection by key. # C: O(N conns)
    pub fn remove(&self, k: ConnKey) {
        self.conns.lock().retain(|c| c.key() != k);
    }

    /// Mark every live connection closed and clear the connection table.
    /// Used when the transport driver is removed. Listeners remain bound, but
    /// no connection can make progress until a driver is installed again.
    /// # C: O(N conns)
    pub fn close_all(&self) {
        let mut conns = self.conns.lock();
        for c in conns.iter() {
            *c.st.lock() = VsockState::Closed;
            #[cfg(target_os = "oxide-kernel")]
            c.waiters.wake_all();
        }
        conns.clear();
        let listeners = self.listeners.lock();
        for l in listeners.iter() {
            l.backlog.lock().clear();
            #[cfg(target_os = "oxide-kernel")]
            l.accept_waiters.wake_all();
        }
    }

    /// Mark connections owned by `local_cid` closed and remove only those
    /// connection records. Listeners remain bound for any remaining vsock
    /// transport. # C: O(N conns + N listeners)
    pub fn close_all_for_cid(&self, local_cid: u64) {
        let mut conns = self.conns.lock();
        for c in conns.iter().filter(|c| c.local_cid == local_cid) {
            *c.st.lock() = VsockState::Closed;
            #[cfg(target_os = "oxide-kernel")]
            c.waiters.wake_all();
        }
        conns.retain(|c| c.local_cid != local_cid);
        let listeners = self.listeners.lock();
        for l in listeners.iter() {
            l.backlog.lock().retain(|k| k.local_cid != local_cid);
            #[cfg(target_os = "oxide-kernel")]
            l.accept_waiters.wake_all();
        }
    }

    /// Register a listener on `port`. # C: O(1)
    pub fn add_listener(&self, port: u32) {
        let mut g = self.listeners.lock();
        if g.iter().any(|l| l.local_port == port) { return; }
        g.push(Listener {
            local_port: port,
            backlog: Spinlock::new(VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new(),
        });
    }

    /// True iff `port` has a registered listener. # C: O(N listeners)
    pub fn is_listening(&self, port: u32) -> bool {
        self.listeners.lock().iter().any(|l| l.local_port == port)
    }

    /// Queue an accepted-but-not-yet-accept()ed peer key on `port`'s
    /// listener backlog + wake any accept() parker. # C: O(N listeners)
    pub fn queue_accept(&self, port: u32, k: ConnKey) {
        let g = self.listeners.lock();
        if let Some(l) = g.iter().find(|l| l.local_port == port) {
            l.backlog.lock().push_back(k);
            #[cfg(target_os = "oxide-kernel")]
            l.accept_waiters.wake_all();
        }
    }

    /// Pop one pending peer key from `port`'s accept backlog. # C: O(N)
    pub fn pop_accept(&self, port: u32) -> Option<ConnKey> {
        let g = self.listeners.lock();
        let k = g.iter().find(|l| l.local_port == port)?.backlog.lock().pop_front();
        k
    }

    /// True iff `port`'s accept backlog is non-empty (poll readability).
    /// # C: O(N listeners)
    pub fn pop_accept_peek(&self, port: u32) -> bool {
        let g = self.listeners.lock();
        g.iter().find(|l| l.local_port == port)
            .map(|l| !l.backlog.lock().is_empty()).unwrap_or(false)
    }
}
