// Owner-keyed VSOCK connection lookup, listener backlog, bind conflicts, and
// teardown. Individual connection state and credit accounting remain in parent.

use alloc::{collections::VecDeque, sync::{Arc, Weak}, vec::Vec};
use core::sync::atomic::AtomicUsize;
use sync::{Spinlock, Socket as SockLockClass};
use super::{BindReservation, VsockConn, VsockOwner, VsockState, VsockTransportType};

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
    pub(in super::super) conns: Spinlock<Vec<Arc<VsockConn>>, SockLockClass>,
    pub(in super::super) bindings: Spinlock<Vec<Arc<BindReservation>>, SockLockClass>,
    pub(in super::super) listeners: Spinlock<Vec<Arc<Listener>>, SockLockClass>,
    pub(in super::super) ephem_next: core::sync::atomic::AtomicU32,
}

/// A bound listener + its accept backlog of inbound OP_REQUESTs. # C: O(1)
pub struct Listener {
    pub owner: Option<VsockOwner>,
    pub local_port: u32,
    pub transport_type: VsockTransportType,
    pub backlog: Spinlock<VecDeque<Arc<VsockConn>>, SockLockClass>,
    pub backlog_cap: AtomicUsize,
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    poll_subs: Spinlock<Option<Weak<vfs::PollSubscribers>>, SockLockClass>,
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
}

impl Listener {
    /// Build an unpublished listener record. # C: O(1)
    pub(in super::super) fn new(owner: Option<VsockOwner>, port: u32, transport_type: VsockTransportType,
                      bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        Self { owner, local_port: port, transport_type, backlog: Spinlock::new(VecDeque::new()),
            backlog_cap: AtomicUsize::new(crate::sysctl::DEFAULT_SOMAXCONN), bpf_filter,
            poll_subs: Spinlock::new(None),
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new() }
    }
    /// Register the owning socket's canonical readiness source. # C: O(1)
    pub fn register_poll_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.poll_subs.lock() = Some(Arc::downgrade(subs));
    }
    /// Publish a readiness transition to the owning socket. # C: O(N subscribers)
    pub fn notify_poll(&self, mask: u32) {
        let source = self.poll_subs.lock().clone();
        if let Some(subs) = source.and_then(|source| source.upgrade()) { subs.notify_mask(mask); }
    }
}

impl VsockTable {
    /// Empty table (const so it backs the process-global static). # C: O(1)
    pub const fn new() -> Self {
        VsockTable { conns: Spinlock::new(Vec::new()), bindings: Spinlock::new(Vec::new()),
            listeners: Spinlock::new(Vec::new()), ephem_next: core::sync::atomic::AtomicU32::new(
                super::super::reservation::FIRST_EPHEMERAL_PORT) }
    }
    /// Restore one hosted table to its empty initial state. # C: O(global state)
    #[cfg(any(test, feature = "hosted"))]
    pub(crate) fn reset_for_hosted_test(&self) {
        self.close_all(); self.listeners.lock().clear(); self.bindings.lock().clear();
        self.ephem_next.store(super::super::reservation::FIRST_EPHEMERAL_PORT,
            core::sync::atomic::Ordering::Release);
    }
    /// Insert `c`; reject an existing record for the same tuple. # C: O(N conns)
    pub fn insert(&self, c: Arc<VsockConn>) -> bool {
        let mut conns = self.conns.lock();
        if conns.iter().any(|old| old.key() == c.key()) { return false; }
        conns.push(c); true
    }
    /// Look up a connection by key. # C: O(N conns)
    pub fn find(&self, k: ConnKey) -> Option<Arc<VsockConn>> {
        self.conns.lock().iter().find(|c| c.key() == k).cloned()
    }
    /// Look up the exact owner and 4-tuple used by the RX dispatcher. # C: O(N conns)
    pub fn find_for_rx(&self, owner: VsockOwner, local_cid: u64, local_port: u32,
                       peer_cid: u64, peer_port: u32) -> Option<Arc<VsockConn>> {
        self.find(ConnKey { owner, local_cid, local_port, peer_cid, peer_port })
    }
    /// Hosted compatibility cleanup; production removal is Arc-exact. # C: O(N conns)
    #[cfg(test)]
    pub fn remove(&self, k: ConnKey) { self.conns.lock().retain(|c| c.key() != k); }
    /// Remove only `c`, even if its tuple has since been reused. # C: O(N conns)
    pub fn remove_conn(&self, c: &VsockConn) -> bool {
        let mut conns = self.conns.lock(); let before = conns.len();
        conns.retain(|current| !core::ptr::eq(current.as_ref(), c)); before != conns.len()
    }
    /// Mark every live connection closed and clear the connection table. # C: O(N conns)
    pub fn close_all(&self) {
        let listeners: Vec<Arc<Listener>> = self.listeners.lock().iter().cloned().collect();
        let mut conns = self.conns.lock(); let closing: Vec<Arc<VsockConn>> = conns.drain(..).collect(); drop(conns);
        for c in closing.iter() {
            if !super::super::fail_connect(c, crate::NetError::Enetunreach) {
                let mut tx = c.tx.lock(); tx.local_shut = true; *c.st.lock() = VsockState::Closed; drop(tx);
                c.notify_poll(vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP);
                #[cfg(target_os = "oxide-kernel")]
                c.waiters.wake_all();
            }
        }
        for l in listeners.iter() { l.backlog.lock().clear(); l.notify_poll(vfs::POLL_IN);
            #[cfg(target_os = "oxide-kernel")]
            l.accept_waiters.wake_all(); }
    }
    /// Close and remove only one transport owner's connections. # C: O(N conns + N listeners + backlog)
    pub fn close_owner(&self, owner: VsockOwner) {
        let listeners: Vec<Arc<Listener>> = self.listeners.lock().iter().cloned().collect();
        let mut conns = self.conns.lock(); let closing: Vec<Arc<VsockConn>> = conns.iter().filter(|c| c.owner == owner).cloned().collect();
        conns.retain(|c| c.owner != owner); drop(conns);
        for c in closing.iter() {
            if !super::super::fail_connect(c, crate::NetError::Enetunreach) {
                let mut tx = c.tx.lock(); tx.local_shut = true; *c.st.lock() = VsockState::Closed; drop(tx);
                c.notify_poll(vfs::POLL_IN | vfs::POLL_HUP | vfs::POLL_RDHUP);
                #[cfg(target_os = "oxide-kernel")]
                c.waiters.wake_all();
            }
        }
        for l in listeners.iter() { l.backlog.lock().retain(|c| c.owner != owner); l.notify_poll(vfs::POLL_IN);
            #[cfg(target_os = "oxide-kernel")]
            l.accept_waiters.wake_all(); }
    }
    /// Register a listener unless an exact or wildcard owner already has the port. # C: O(N listeners)
    pub fn add_listener(&self, owner: Option<VsockOwner>, port: u32) -> Option<Arc<Listener>> {
        let bindings = self.bindings.lock(); let mut g = self.listeners.lock();
        if g.iter().any(|l| l.local_port == port && (l.owner == owner || l.owner.is_none() || owner.is_none())) { return None; }
        if bindings.iter().any(|b| b.port == port && (b.owner == owner || b.owner.is_none() || owner.is_none())) { return None; }
        let l = Arc::new(Listener::new(owner, port, VsockTransportType::Stream, Arc::new(crate::bpf_filter::SocketFilter::new())));
        g.push(l.clone()); Some(l)
    }
    /// Remove exactly `listener`; close only children still pending on it. # C: O(N listeners + N pending + N conns)
    pub fn remove_listener_exact(&self, listener: &Arc<Listener>) -> bool {
        let mut listeners = self.listeners.lock(); let Some(pos) = listeners.iter().position(|l| Arc::ptr_eq(l, listener)) else { return false; };
        let removed = listeners.remove(pos); let mut conns = self.conns.lock();
        let pending: Vec<Arc<VsockConn>> = removed.backlog.lock().drain(..).collect();
        conns.retain(|c| !pending.iter().any(|child| Arc::ptr_eq(c, child))); drop(conns); drop(listeners);
        for child in pending.iter() { super::super::close(child); }
        removed.notify_poll(vfs::POLL_HUP);
        #[cfg(target_os = "oxide-kernel")]
        removed.accept_waiters.wake_all();
        true
    }
    /// Address-based compatibility removal, completed by Arc identity. # C: O(N listeners + N pending + N conns)
    pub fn remove_listener(&self, owner: Option<VsockOwner>, port: u32) -> bool {
        let listener = self.listeners.lock().iter().find(|l| l.owner == owner && l.local_port == port).cloned();
        listener.map(|l| self.remove_listener_exact(&l)).unwrap_or(false)
    }
    /// True iff an exact or wildcard owner listener has `port`. # C: O(N listeners)
    pub fn is_listening(&self, owner: VsockOwner, port: u32) -> bool {
        self.listeners.lock().iter().any(|l| l.local_port == port && (l.owner == Some(owner) || l.owner.is_none()))
    }
}
