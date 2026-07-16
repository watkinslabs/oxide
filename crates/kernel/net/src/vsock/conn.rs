// AF_VSOCK STREAM connection state machine + credit accounting +
// connection table. PURE protocol logic over the wire format in
// `super::hdr` — the actual ring DMA is a TX hook installed by the
// driver (drv-virtio-vsock). Host-testable: every state transition,
// credit-math path, and the 5 STREAM ops are exercised in `tests`.
// Credit model (virtio 1.2 §5.10.6.3): each side advertises buf_alloc
// (its RX ring capacity) + fwd_cnt (bytes it has consumed). A sender
// may have at most `peer_buf_alloc - (tx_cnt - peer_fwd_cnt)` bytes in
// flight. We track our own rx_cnt (bytes delivered to userspace) to
// publish fwd_cnt, and the peer's last-seen buf_alloc/fwd_cnt to gate
// OP_RW sends.

use alloc::{collections::VecDeque, sync::{Arc, Weak}, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicUsize};
use sync::{Spinlock, Socket as SockLockClass};
use super::{hdr::*, BindReservation};

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
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// Received OP_RW payload bytes, FIFO; recv() drains the front.
    pub rx: Spinlock<VecDeque<u8>, SockLockClass>,
    /// Canonical transmit admission, shutdown, and credit gate.
    pub tx: Spinlock<TxState, SockLockClass>,
    pub(super) emit: Spinlock<(), SockLockClass>,
    pub(super) accept_ready: AtomicBool,
    pub(crate) credit_update_pending: AtomicBool,
    pub(super) connect_owner: Spinlock<Option<Weak<crate::vsock_socket::VsockSocket>>, SockLockClass>,
    pub(super) connect_error: Spinlock<Option<crate::NetError>, SockLockClass>,
    pub(super) connect_timer: Spinlock<Option<ConnectTimer>, SockLockClass>,
    poll_subs: Spinlock<Option<Weak<vfs::PollSubscribers>>, SockLockClass>,
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

/// Connection-level transmit state serialized through OP_RW emission. # C: O(1)
pub struct TxState {
    pub credit: Credit,
    pub local_shut: bool,
    pub peer_shut: bool,
}

/// Exact one-shot registration owned by one connection attempt. # C: O(1)
pub(super) struct ConnectTimer {
    pub id: timer::TimerId,
    pub raw: usize,
    pub token: Arc<ConnectTimerToken>,
}

/// Timer callback token retaining the exact connection Arc. # C: O(1)
pub(super) struct ConnectTimerToken {
    pub conn: Arc<VsockConn>,
    pub cancelled: AtomicBool,
}

impl TxState {
    /// True once either endpoint has closed its receive path. # C: O(1)
    pub fn shut(&self) -> bool { self.local_shut || self.peer_shut }
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
    #[cfg(test)]
    pub(crate) fn hold_emission_for_test(&self) -> sync::Guard<'_, (), SockLockClass> {
        self.emit.lock()
    }

    /// New connection in `st`. # C: O(1)
    pub fn new(owner: VsockOwner, local_cid: u64, local_port: u32, peer_cid: u64, peer_port: u32,
               st: VsockState) -> Self {
        Self::new_with_filter(owner, local_cid, local_port, peer_cid, peer_port, st,
            Arc::new(crate::bpf_filter::SocketFilter::new()))
    }

    /// Build a connection sharing its owning socket's filter state. # C: O(1)
    pub fn new_with_filter(owner: VsockOwner, local_cid: u64, local_port: u32,
                           peer_cid: u64, peer_port: u32, st: VsockState,
                           bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        VsockConn {
            owner,
            local_cid, local_port, peer_cid, peer_port,
            st: Spinlock::new(st),
            bpf_filter,
            rx: Spinlock::new(VecDeque::new()),
            tx: Spinlock::new(TxState {
                credit: Credit::default(), local_shut: false, peer_shut: false,
            }),
            emit: Spinlock::new(()),
            accept_ready: AtomicBool::new(false),
            credit_update_pending: AtomicBool::new(false),
            connect_owner: Spinlock::new(None),
            connect_error: Spinlock::new(None),
            connect_timer: Spinlock::new(None),
            poll_subs: Spinlock::new(None),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
        }
    }

    /// Build the header for a control/data packet from this conn, filling
    /// in the live credit fields. # C: O(1)
    pub fn make_hdr(&self, op: u16, len: u32, flags: u32) -> VsockHdr {
        let tx = self.tx.lock();
        self.make_hdr_with_credit(&tx.credit, op, len, flags)
    }

    /// Build a header while the caller holds the transmit gate. # C: O(1)
    pub fn make_hdr_with_credit(&self, c: &Credit, op: u16, len: u32, flags: u32) -> VsockHdr {
        VsockHdr {
            src_cid:  self.local_cid,
            dst_cid:  self.peer_cid,
            src_port: self.local_port,
            dst_port: self.peer_port,
            len,
            typ: VIRTIO_VSOCK_TYPE_STREAM,
            op,
            flags,
            buf_alloc: c.buf_alloc, fwd_cnt: c.fwd_cnt,
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

    /// Register the owning socket's canonical readiness source. # C: O(1)
    pub fn register_poll_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(Arc::downgrade(subs));
    }

    /// Publish a readiness transition to the owning socket. # C: O(N subscribers)
    pub fn notify_poll(&self, mask: u32) {
        let source = self.poll_subs.lock().clone();
        if let Some(subs) = source.and_then(|source| source.upgrade()) {
            subs.notify_mask(mask);
        }
    }

    fn arm_recv_wait_with(&self, sock: &crate::vsock_socket::VsockSocket, offset: usize,
                          arm: impl FnOnce()) -> bool {
        let st = self.st.lock();
        let rx = self.rx.lock();
        if rx.len() > offset || matches!(*st, VsockState::RcvShutdown | VsockState::Closed)
            || sock.has_pending_recv_error()
            || sock.read_shut.load(core::sync::atomic::Ordering::Acquire)
        { return false; }
        arm();
        drop(rx);
        drop(st);
        true
    }

    /// Atomically recheck receive state and arm one interruptible reader. # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_recv_wait(&self, sock: &crate::vsock_socket::VsockSocket, offset: usize,
                         deadline_ns: u64) -> bool {
        self.arm_recv_wait_with(sock, offset, || {
            // SAFETY: state and RX locks serialize terminal/data/error publication with registration.
            unsafe { self.waiters.park_interruptible_with_deadline(deadline_ns); }
        })
    }

    /// Hosted observation of the canonical receive wait gate. # C: O(1)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn recv_wait_would_park(&self, sock: &crate::vsock_socket::VsockSocket,
                                offset: usize) -> bool {
        self.arm_recv_wait_with(sock, offset, || {})
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
    pub(super) conns: Spinlock<Vec<Arc<VsockConn>>, SockLockClass>,
    /// Bound, not-yet-listening local identities.
    pub(super) bindings: Spinlock<Vec<Arc<BindReservation>>, SockLockClass>,
    /// Bound listeners: (owner, local_port) → accept backlog of pending peers.
    /// None is VMADDR_CID_ANY.
    pub(super) listeners: Spinlock<Vec<Arc<Listener>>, SockLockClass>,
    /// Ephemeral local-port allocator (1024..).
    pub(super) ephem_next: core::sync::atomic::AtomicU32,
}

/// A bound listener + its accept backlog of inbound OP_REQUESTs that
/// haven't been accept()ed yet. # C: O(1)
pub struct Listener {
    pub owner: Option<VsockOwner>,
    pub local_port: u32,
    pub backlog: Spinlock<VecDeque<Arc<VsockConn>>, SockLockClass>,
    pub backlog_cap: AtomicUsize,
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    poll_subs: Spinlock<Option<Weak<vfs::PollSubscribers>>, SockLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
}

impl Listener {
    /// Build an unpublished listener record. # C: O(1)
    pub(super) fn new(owner: Option<VsockOwner>, port: u32,
                      bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        Self {
            owner, local_port: port,
            backlog: Spinlock::new(VecDeque::new()),
            backlog_cap: AtomicUsize::new(crate::sysctl::DEFAULT_SOMAXCONN),
            bpf_filter,
            poll_subs: Spinlock::new(None),
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new(),
        }
    }

    /// Register the owning socket's canonical readiness source. # C: O(1)
    pub fn register_poll_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(Arc::downgrade(subs));
    }

    /// Publish a readiness transition to the owning socket. # C: O(N subscribers)
    pub fn notify_poll(&self, mask: u32) {
        let source = self.poll_subs.lock().clone();
        if let Some(subs) = source.and_then(|source| source.upgrade()) {
            subs.notify_mask(mask);
        }
    }
}

impl VsockTable {
    /// Empty table (const so it backs the process-global static).
    /// # C: O(1)
    pub const fn new() -> Self {
        VsockTable {
            conns: Spinlock::new(Vec::new()),
            bindings: Spinlock::new(Vec::new()),
            listeners: Spinlock::new(Vec::new()),
            ephem_next: core::sync::atomic::AtomicU32::new(
                super::reservation::FIRST_EPHEMERAL_PORT),
        }
    }

    /// Restore one hosted table to its empty initial state. # C: O(global state)
    #[cfg(any(test, feature = "hosted"))]
    pub(crate) fn reset_for_hosted_test(&self) {
        self.close_all();
        self.listeners.lock().clear();
        self.bindings.lock().clear();
        self.ephem_next.store(super::reservation::FIRST_EPHEMERAL_PORT,
            core::sync::atomic::Ordering::Release);
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
        let listeners: Vec<Arc<Listener>> = self.listeners.lock().iter().cloned().collect();
        let mut conns = self.conns.lock();
        let closing: Vec<Arc<VsockConn>> = conns.drain(..).collect();
        drop(conns);
        for c in closing.iter() {
            if !super::fail_connect(c, crate::NetError::Enetunreach) {
                let mut tx = c.tx.lock();
                tx.local_shut = true;
                *c.st.lock() = VsockState::Closed;
                drop(tx);
                c.notify_poll(vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP);
                #[cfg(target_os = "oxide-kernel")]
                c.waiters.wake_all();
            }
        }
        for l in listeners.iter() {
            l.backlog.lock().clear();
            l.notify_poll(vfs::POLL_IN);
            #[cfg(target_os = "oxide-kernel")]
            l.accept_waiters.wake_all();
        }
    }

    /// Mark one owner's live connections closed, remove only those connection
    /// records, and prune that owner's accept backlog entries. Other transport
    /// owners must keep running across a single device remove.
    /// # C: O(N conns + N listeners + backlog)
    pub fn close_owner(&self, owner: VsockOwner) {
        let listeners: Vec<Arc<Listener>> = self.listeners.lock().iter().cloned().collect();
        let mut conns = self.conns.lock();
        let closing: Vec<Arc<VsockConn>> = conns.iter()
            .filter(|c| c.owner == owner).cloned().collect();
        conns.retain(|c| c.owner != owner);
        drop(conns);
        for c in closing.iter() {
            if !super::fail_connect(c, crate::NetError::Enetunreach) {
                let mut tx = c.tx.lock();
                tx.local_shut = true;
                *c.st.lock() = VsockState::Closed;
                drop(tx);
                c.notify_poll(vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP);
                #[cfg(target_os = "oxide-kernel")]
                c.waiters.wake_all();
            }
        }
        for l in listeners.iter() {
            l.backlog.lock().retain(|c| c.owner != owner);
            l.notify_poll(vfs::POLL_IN);
            #[cfg(target_os = "oxide-kernel")]
            l.accept_waiters.wake_all();
        }
    }

    /// Register a listener on `port`; return None when that owner/address is
    /// already owned by another listener. None owner is VMADDR_CID_ANY.
    /// # C: O(N listeners)
    pub fn add_listener(&self, owner: Option<VsockOwner>, port: u32) -> Option<Arc<Listener>> {
        let bindings = self.bindings.lock();
        let mut g = self.listeners.lock();
        if g.iter().any(|l| l.local_port == port &&
            (l.owner == owner || l.owner.is_none() || owner.is_none())) { return None; }
        if bindings.iter().any(|b| b.port == port
            && (b.owner == owner || b.owner.is_none() || owner.is_none()))
        { return None; }
        let l = Arc::new(Listener::new(owner, port,
            Arc::new(crate::bpf_filter::SocketFilter::new())));
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
        removed.notify_poll(vfs::POLL_HUP);
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

}
