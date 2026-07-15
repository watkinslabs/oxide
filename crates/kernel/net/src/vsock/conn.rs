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
use alloc::sync::Arc;
use sync::{Spinlock, Socket as SockLockClass};
use super::hdr::*;

/// No concrete driver owner; used only for VMADDR_CID_ANY wildcard binds.
pub const VSOCK_OWNER_ANY_RAW: u32 = 0;

/// Transport-neutral vsock driver endpoint owner. Nonzero by construction.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct VsockOwner(u32);

impl VsockOwner {
    /// Build from a driver-provided stable owner key. # C: O(1)
    pub fn from_raw(raw: u32) -> Option<Self> {
        if raw == VSOCK_OWNER_ANY_RAW { None } else { Some(Self(raw)) }
    }

    /// Raw key for local table comparisons and transport callbacks. # C: O(1)
    pub fn raw(self) -> u32 { self.0 }
}

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

/// One vsock STREAM connection. Keyed in the table by owner plus the 4-tuple
/// (local_cid, local_port, peer_cid, peer_port). # C: O(1)
pub struct VsockConn {
    pub owner:      VsockOwner,
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
    pub fn new(owner: VsockOwner, local_cid: u64, local_port: u32, peer_cid: u64, peer_port: u32,
               st: VsockState) -> Self {
        VsockConn {
            owner,
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
            owner: self.owner,
            local_cid: self.local_cid, local_port: self.local_port,
            peer_cid: self.peer_cid, peer_port: self.peer_port,
        }
    }
}

/// Owner-keyed 4-tuple connection key. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ConnKey {
    pub owner:      VsockOwner,
    pub local_cid:  u64,
    pub local_port: u32,
    pub peer_cid:   u64,
    pub peer_port:  u32,
}

/// Process-global vsock connection table. v1: a Vec scanned linearly —
/// vsock fan-out is small (a handful of host↔guest streams). # C: see fns
pub struct VsockTable {
    conns: Spinlock<Vec<Arc<VsockConn>>, SockLockClass>,
    /// Bound listeners: (owner, local_port) → accept backlog of pending peers.
    /// None is VMADDR_CID_ANY.
    listeners: Spinlock<Vec<Arc<Listener>>, SockLockClass>,
    /// Ephemeral local-port allocator (1024..).
    ephem_next: core::sync::atomic::AtomicU32,
}

/// A bound listener + its accept backlog of inbound OP_REQUESTs that
/// haven't been accept()ed yet. # C: O(1)
pub struct Listener {
    pub owner: Option<VsockOwner>,
    pub local_port: u32,
    pub backlog: Spinlock<VecDeque<Arc<VsockConn>>, SockLockClass>,
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

    /// Insert `c`; reject an existing record for the same tuple. # C: O(N conns)
    pub fn insert(&self, c: Arc<VsockConn>) -> bool {
        let mut conns = self.conns.lock();
        if conns.iter().any(|old| old.key() == c.key()) { return false; }
        conns.push(c);
        true
    }

    /// Look up a connection by key. # C: O(N conns)
    pub fn find(&self, k: ConnKey) -> Option<Arc<VsockConn>> {
        self.conns.lock().iter().find(|c| c.key() == k).cloned()
    }

    /// Look up by the *local* 2-tuple regardless of peer — used by the
    /// RX dispatcher which keys on (dst_cid, dst_port, src_cid, src_port)
    /// of the incoming packet. # C: O(N conns)
    pub fn find_for_rx(&self, owner: VsockOwner, local_cid: u64, local_port: u32,
                       peer_cid: u64, peer_port: u32)
        -> Option<Arc<VsockConn>>
    {
        self.find(ConnKey { owner, local_cid, local_port, peer_cid, peer_port })
    }

    /// Hosted compatibility cleanup; production removal is Arc-exact.
    /// # C: O(N conns)
    #[cfg(test)]
    pub fn remove(&self, k: ConnKey) {
        self.conns.lock().retain(|c| c.key() != k);
    }

    /// Remove only `c`, even if its tuple has since been reused. # C: O(N conns)
    pub fn remove_conn(&self, c: &VsockConn) -> bool {
        let mut conns = self.conns.lock();
        let before = conns.len();
        conns.retain(|current| !core::ptr::eq(current.as_ref(), c));
        before != conns.len()
    }

    /// Mark every live connection closed and clear the connection table.
    /// Used when the transport driver is removed. Listeners remain bound, but
    /// no connection can make progress until a driver is installed again.
    /// # C: O(N conns)
    pub fn close_all(&self) {
        let listeners = self.listeners.lock();
        let mut conns = self.conns.lock();
        let closing: Vec<Arc<VsockConn>> = conns.drain(..).collect();
        drop(conns);
        for c in closing.iter() {
            *c.st.lock() = VsockState::Closed;
            #[cfg(target_os = "oxide-kernel")]
            c.waiters.wake_all();
        }
        for l in listeners.iter() {
            l.backlog.lock().clear();
            #[cfg(target_os = "oxide-kernel")]
            l.accept_waiters.wake_all();
        }
    }

    /// Mark one owner's live connections closed, remove only those connection
    /// records, and prune that owner's accept backlog entries. Other transport
    /// owners must keep running across a single device remove.
    /// # C: O(N conns + N listeners + backlog)
    pub fn close_owner(&self, owner: VsockOwner) {
        let listeners = self.listeners.lock();
        let mut conns = self.conns.lock();
        let closing: Vec<Arc<VsockConn>> = conns.iter()
            .filter(|c| c.owner == owner).cloned().collect();
        conns.retain(|c| c.owner != owner);
        drop(conns);
        for c in closing.iter() {
            *c.st.lock() = VsockState::Closed;
            #[cfg(target_os = "oxide-kernel")]
            c.waiters.wake_all();
        }
        for l in listeners.iter() {
            l.backlog.lock().retain(|c| c.owner != owner);
            #[cfg(target_os = "oxide-kernel")]
            l.accept_waiters.wake_all();
        }
    }

    /// Register a listener on `port`; return None when that owner/address is
    /// already owned by another listener. None owner is VMADDR_CID_ANY.
    /// # C: O(N listeners)
    pub fn add_listener(&self, owner: Option<VsockOwner>, port: u32) -> Option<Arc<Listener>> {
        let mut g = self.listeners.lock();
        if g.iter().any(|l| l.local_port == port &&
            (l.owner == owner || l.owner.is_none() || owner.is_none())) { return None; }
        let l = Arc::new(Listener {
            owner,
            local_port: port,
            backlog: Spinlock::new(VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new(),
        });
        g.push(l.clone());
        Some(l)
    }

    /// Remove exactly `listener`; drain and close only children still pending
    /// on that record. Already-popped children remain live.
    /// # C: O(N listeners + N pending + N conns)
    pub fn remove_listener_exact(&self, listener: &Arc<Listener>) -> bool {
        let mut listeners = self.listeners.lock();
        let Some(pos) = listeners.iter().position(|l| Arc::ptr_eq(l, listener)) else {
            return false;
        };
        let removed = listeners.remove(pos);
        let mut conns = self.conns.lock();
        let pending: Vec<Arc<VsockConn>> = removed.backlog.lock().drain(..).collect();
        conns.retain(|c| !pending.iter().any(|child| Arc::ptr_eq(c, child)));
        drop(conns);
        drop(listeners);
        for child in pending.iter() { super::close(child); }
        #[cfg(target_os = "oxide-kernel")]
        removed.accept_waiters.wake_all();
        true
    }

    /// Address-based compatibility removal. The selected record is still
    /// removed by Arc identity, so a concurrent replacement is preserved.
    /// # C: O(N listeners + N pending + N conns)
    pub fn remove_listener(&self, owner: Option<VsockOwner>, port: u32) -> bool {
        let listener = self.listeners.lock().iter()
            .find(|l| l.owner == owner && l.local_port == port).cloned();
        listener.map(|l| self.remove_listener_exact(&l)).unwrap_or(false)
    }

    /// True iff `port` has an exact owner listener or a wildcard listener.
    /// # C: O(N listeners)
    pub fn is_listening(&self, owner: VsockOwner, port: u32) -> bool {
        self.listeners.lock().iter().any(|l| {
            l.local_port == port && (l.owner == Some(owner) || l.owner.is_none())
        })
    }

    /// Atomically insert `c` and publish it on the selected listener backlog.
    /// Exact owner listeners win over wildcard listeners. Holding the listener
    /// registry lock linearizes publication against exact listener removal.
    /// # C: O(N listeners + N conns)
    pub fn publish_accept(&self, owner: VsockOwner, port: u32, c: Arc<VsockConn>) -> bool {
        let listeners = self.listeners.lock();
        let listener = listeners.iter().find(|l| l.owner == Some(owner) && l.local_port == port)
            .or_else(|| listeners.iter().find(|l| l.owner.is_none() && l.local_port == port));
        let Some(listener) = listener else { return false; };
        let mut conns = self.conns.lock();
        if conns.iter().any(|old| old.key() == c.key()) { return false; }
        conns.push(c.clone());
        listener.backlog.lock().push_back(c);
        #[cfg(target_os = "oxide-kernel")]
        listener.accept_waiters.wake_all();
        true
    }

    /// Test/compatibility helper: queue the current record for `k`. New inbound
    /// paths must use `publish_accept` so insertion and publication are atomic.
    /// # C: O(N listeners + N conns)
    #[cfg(test)]
    pub fn queue_accept(&self, owner: VsockOwner, port: u32, k: ConnKey) {
        let Some(c) = self.find(k) else { return; };
        let listeners = self.listeners.lock();
        let listener = listeners.iter().find(|l| l.owner == Some(owner) && l.local_port == port)
            .or_else(|| listeners.iter().find(|l| l.owner.is_none() && l.local_port == port));
        if let Some(l) = listener {
            l.backlog.lock().push_back(c);
            #[cfg(target_os = "oxide-kernel")]
            l.accept_waiters.wake_all();
        }
    }

    /// Pop one pending child Arc from `port`'s accept backlog. # C: O(N)
    pub fn pop_accept(&self, owner: Option<VsockOwner>, port: u32) -> Option<Arc<VsockConn>> {
        let g = self.listeners.lock();
        let child = g.iter()
            .find(|l| l.owner == owner && l.local_port == port)?
            .backlog.lock()
            .pop_front();
        child
    }

    /// Pop from exactly `listener`; a replacement at the same address cannot
    /// satisfy an accept already bound to the old record. # C: O(N listeners)
    pub fn pop_accept_exact(&self, listener: &Arc<Listener>) -> Option<Arc<VsockConn>> {
        let listeners = self.listeners.lock();
        let current = listeners.iter().find(|l| Arc::ptr_eq(l, listener))?;
        let child = current.backlog.lock().pop_front();
        child
    }

    /// True iff exactly `listener` is registered with a pending child.
    /// # C: O(N listeners)
    pub fn pop_accept_peek_exact(&self, listener: &Arc<Listener>) -> bool {
        let listeners = self.listeners.lock();
        listeners.iter().find(|l| Arc::ptr_eq(l, listener))
            .map(|l| !l.backlog.lock().is_empty()).unwrap_or(false)
    }

    /// True iff `port`'s accept backlog is non-empty (poll readability).
    /// # C: O(N listeners)
    pub fn pop_accept_peek(&self, owner: Option<VsockOwner>, port: u32) -> bool {
        let g = self.listeners.lock();
        g.iter().find(|l| l.owner == owner && l.local_port == port)
            .map(|l| !l.backlog.lock().is_empty()).unwrap_or(false)
    }
}
