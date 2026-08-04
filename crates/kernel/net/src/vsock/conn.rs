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

use alloc::{collections::VecDeque, sync::{Arc, Weak}};
use core::sync::atomic::{AtomicBool, AtomicU64};
use sync::{Spinlock, Socket as SockLockClass};
use super::{hdr::*, BindReservation, SeqpacketRx};

mod wait;
mod identity;
// Module manifest: table owns owner-keyed connection lookup, listener backlog,
// teardown, and bind-conflict state; this file owns individual connection state.
mod table;
pub use table::{ConnKey, Listener, VsockTable};

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

/// Connection transport personality encoded in every virtio-vsock header.
/// # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VsockTransportType {
    Stream,
    Seqpacket,
}

impl VsockTransportType {
    /// Decode a supported virtio `type` header value. # C: O(1)
    pub const fn from_wire_type(typ: u16) -> Option<Self> {
        match typ {
            VIRTIO_VSOCK_TYPE_STREAM => Some(Self::Stream),
            VIRTIO_VSOCK_TYPE_SEQPACKET => Some(Self::Seqpacket),
            _ => None,
        }
    }

    /// Exact virtio `type` header value. # C: O(1)
    pub const fn wire_type(self) -> u16 {
        match self {
            Self::Stream => VIRTIO_VSOCK_TYPE_STREAM,
            Self::Seqpacket => VIRTIO_VSOCK_TYPE_SEQPACKET,
        }
    }
}

/// One connection-oriented VSOCK endpoint. Keyed in the table by owner plus
/// the 4-tuple (local_cid, local_port, peer_cid, peer_port). # C: O(1)
pub struct VsockConn {
    pub owner:      VsockOwner,
    pub local_cid:  u64,
    pub local_port: u32,
    pub peer_cid:   u64,
    pub peer_port:  u32,
    pub transport_type: VsockTransportType,
    pub st: Spinlock<VsockState, SockLockClass>,
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// Received OP_RW payload bytes, FIFO; recv() drains the front.
    pub rx: Spinlock<VecDeque<u8>, SockLockClass>,
    /// Complete-record RX state for `SOCK_SEQPACKET`. Stream connections never
    /// publish records here; they retain their byte queue above.
    pub seq_rx: Spinlock<SeqpacketRx, SockLockClass>,
    /// Canonical transmit admission, shutdown, and credit gate.
    pub tx: Spinlock<TxState, SockLockClass>,
    pub(super) emit: Spinlock<(), SockLockClass>,
    pub(super) accept_ready: AtomicBool,
    /// Linux `sock->state != SS_UNCONNECTED`: latched the moment the
    /// connection is established and never cleared, because Linux only
    /// returns `sock->state` to `SS_UNCONNECTED` from `vsock_stream_connect`'s
    /// FAILURE path and from `vsock_release`. It is what separates a
    /// connection that closed (shutdown still succeeds) from one whose
    /// connect never completed (ENOTCONN).
    pub(crate) ever_connected: AtomicBool,
    pub(crate) credit_update_pending: AtomicBool,
    /// Hosted-test one-shot tail-window credit update, per-connection so no
    /// concurrently running test can consume it (B1653).
    #[cfg(any(test, feature = "hosted"))]
    pub(crate) inject_tail_credit: AtomicBool,
    /// Socket-owned timeout retained with this outbound connection so a
    /// repeated blocking connect observes the same configured deadline.
    connect_timeout_ns: AtomicU64,
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
    /// Apply the socket-owned receive buffer policy to the advertised credit
    /// window before the connection is published. # C: O(1)
    pub fn set_local_buf_alloc(&self, bytes: u32) {
        self.tx.lock().credit.buf_alloc = bytes;
    }
    #[cfg(test)]
    pub(crate) fn hold_emission_for_test(&self) -> sync::Guard<'_, (), SockLockClass> {
        self.emit.lock()
    }

    /// New connection in `st`. # C: O(1)
    pub fn new(owner: VsockOwner, local_cid: u64, local_port: u32, peer_cid: u64, peer_port: u32,
               st: VsockState) -> Self {
        Self::new_with_filter_type(owner, local_cid, local_port, peer_cid, peer_port, st,
            VsockTransportType::Stream,
            Arc::new(crate::bpf_filter::SocketFilter::new()))
    }

    /// Build a connection sharing its owning socket's filter state. # C: O(1)
    pub fn new_with_filter(owner: VsockOwner, local_cid: u64, local_port: u32,
                           peer_cid: u64, peer_port: u32, st: VsockState,
                           bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        Self::new_with_filter_type(owner, local_cid, local_port, peer_cid, peer_port, st,
            VsockTransportType::Stream, bpf_filter)
    }

    /// Build one connection with an explicit virtio transport personality.
    /// # C: O(1)
    pub fn new_with_filter_type(owner: VsockOwner, local_cid: u64, local_port: u32,
                           peer_cid: u64, peer_port: u32, st: VsockState,
                           transport_type: VsockTransportType,
                           bpf_filter: Arc<crate::bpf_filter::SocketFilter>) -> Self {
        VsockConn {
            owner,
            local_cid, local_port, peer_cid, peer_port,
            transport_type,
            st: Spinlock::new(st),
            bpf_filter,
            rx: Spinlock::new(VecDeque::new()),
            seq_rx: Spinlock::new(SeqpacketRx::default()),
            tx: Spinlock::new(TxState {
                credit: Credit::default(), local_shut: false, peer_shut: false,
            }),
            emit: Spinlock::new(()),
            accept_ready: AtomicBool::new(false),
            ever_connected: AtomicBool::new(matches!(st, VsockState::Connected)),
            credit_update_pending: AtomicBool::new(false),
            #[cfg(any(test, feature = "hosted"))]
            inject_tail_credit: AtomicBool::new(false),
            connect_timeout_ns: AtomicU64::new(super::VSOCK_CONNECT_TIMEOUT_NS),
            connect_owner: Spinlock::new(None),
            connect_error: Spinlock::new(None),
            connect_timer: Spinlock::new(None),
            poll_subs: Spinlock::new(None),
            #[cfg(target_os = "oxide-kernel")]
            waiters: sched::live::WaitList::new(),
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
