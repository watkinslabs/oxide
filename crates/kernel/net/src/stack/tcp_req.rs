// The half-open passive connection, as its own record.
//
// Between the SYN and the acknowledgement that completes the handshake there
// is no connection: there is a REQUEST. It owns no send buffer, no receive
// buffer, no retransmit queue and no delivery telemetry, because none of those
// can hold anything until the handshake finishes. It lives in the same
// connection table as full sockets, keyed by the same 4-tuple, and is told
// apart from one by which arm of [`TcpSlot`] holds it — one table, two entry
// kinds, so a segment still finds its owner in a single lookup.
//
// What it stores is the negotiation the SYN produced, once: the sequence
// numbers, the peer's announced maximum segment size, and the option outcomes.
// Every later use reads that record — the SYN-ACK retransmit rebuilds its
// segment from it, and the child connection is opened from it. Nothing
// re-parses the SYN, so the negotiation has exactly one source.

use super::*;
use crate::syncookies::{tsopt::Decoded, Rebuild};
use crate::tcp_conn::reqsk::ReqSock;
use ::core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// One entry in the connection table. A half-open passive connection is a
/// [`TcpReq`]; everything else is a full socket.
#[derive(Clone)]
pub(crate) enum TcpSlot {
    Req(Arc<TcpReq>),
    Sock(Arc<TcpEntry>),
}

impl TcpSlot {
    /// The full socket behind this entry, if the handshake ever finished.
    /// # C: O(1)
    pub(crate) fn sock(&self) -> Option<&Arc<TcpEntry>> {
        match self { Self::Sock(entry) => Some(entry), Self::Req(_) => None }
    }

    /// The request behind this entry, while it is still half-open. # C: O(1)
    pub(crate) fn req(&self) -> Option<&Arc<TcpReq>> {
        match self { Self::Req(req) => Some(req), Self::Sock(_) => None }
    }
}

/// A half-open passive connection: the state the handshake negotiated, the
/// SYN-ACK timer's accounting, and the listener the completed child belongs to.
pub(crate) struct TcpReq {
    pub(crate) local: Endpoint,
    pub(crate) remote: Endpoint,
    /// The negotiation the SYN produced. The SYN-ACK is rebuilt from this and
    /// the child connection is opened from it; nothing else re-derives it.
    pub(crate) negotiated: Rebuild,
    /// The receive window this side's SYN-ACK announced, unscaled. A segment
    /// arriving for the request is judged against THIS, not against a window
    /// re-derived later from a connection that does not exist yet.
    pub(crate) rcv_wnd: u16,
    /// The maximum segment size this side announces, and the path MTU the
    /// route said, both as the SYN-ACK carried them.
    pub(crate) own_mss: u16,
    pub(crate) path_mtu: AtomicU32,
    /// Route metrics the child is seeded with, resolved once under the
    /// listener's mark rather than looked up again when the handshake ends.
    pub(crate) metrics: crate::route_metrics::RouteMetrics,
    /// The fast-open option every SYN-ACK for this request carries, including
    /// the retransmissions — a client that asked for a cookie and lost the
    /// answer must get the same one back.
    pub(crate) fastopen_opt: Option<crate::tcp_conn::fastopen::Cookie>,
    /// What the network header of the opening packet carried, retained for the
    /// accepted socket's `IP_PKTOPTIONS`.
    pub(crate) rcv_iif: u32,
    pub(crate) rcv_ttl: u8,
    pub(crate) rcv_tos: u8,
    /// `TCP_SAVE_SYN`: the opening packet, kept only where the listener asked.
    pub(crate) syn_bytes: Option<Vec<u8>>,
    pub(crate) listener: alloc::sync::Weak<TcpListenEntry>,
    pub(crate) bind: Arc<TcpBindReservation>,
    /// `SO_MARK` the request was admitted under. The child takes THIS, not
    /// whatever the listening socket's mark became while the handshake ran:
    /// an accepted connection's mark is the one its request answered with.
    pub(crate) mark: i32,
    pub(crate) iface: NetIfaceId,
    pub(crate) ipv6: bool,
    /// Retransmit and deferral accounting for this request.
    pub(crate) rsk: StackBhLock<ReqSock>,
    pub(crate) syn_backlog_reserved: AtomicBool,
    /// Still in the listener's young population: no timer firing yet.
    pub(crate) syn_backlog_young_reserved: AtomicBool,
    pub(crate) timer: super::tcp_timer::ReqTimer,
}

impl TcpReq {
    /// Record what a processed SYN negotiated, so the request can answer for
    /// it without the connection that produced it. # C: O(saved SYN)
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_negotiated(conn: &TcpConn, local: Endpoint, window: u16,
        listener: &Arc<TcpListenEntry>, iface: NetIfaceId, ipv6: bool, mark: i32,
        metrics: crate::route_metrics::RouteMetrics, syn_bytes: Option<Vec<u8>>) -> Self
    {
        let (iif, ttl, tos) = (conn.rcv_iif, conn.rcv_ttl, conn.rcv_tos);
        Self {
            local,
            remote: conn.remote,
            negotiated: Rebuild {
                isn: conn.snd_una,
                peer_isn: conn.rcv_nxt.wrapping_sub(1),
                mss: conn.peer_mss,
                opts: Decoded {
                    tstamp_ok: conn.ts_enabled,
                    sack_ok: conn.sack_ok,
                    wscale: conn.wscale_ok.then_some(conn.rcv_wscale),
                    ecn_ok: conn.ecn_enabled,
                },
                ts_recent: conn.ts_recent,
                ts_off: conn.ts_off,
                window,
            },
            rcv_wnd: conn.current_rcv_window(),
            own_mss: conn.own_mss,
            path_mtu: AtomicU32::new(conn.path_mtu),
            metrics,
            fastopen_opt: conn.fastopen_opt,
            rcv_iif: iif, rcv_ttl: ttl, rcv_tos: tos,
            syn_bytes,
            listener: Arc::downgrade(listener),
            bind: listener.bind.clone(),
            mark, iface, ipv6,
            rsk: StackBhLock::new(conn.rsk),
            syn_backlog_reserved: AtomicBool::new(true),
            syn_backlog_young_reserved: AtomicBool::new(true),
            timer: super::tcp_timer::ReqTimer::new(),
        }
    }

    /// # C: O(1)
    pub(crate) fn key(&self) -> TcpKey {
        TcpKey { local_ip: self.local.ip, local_port: self.local.port,
                 remote_ip: self.remote.ip, remote_port: self.remote.port }
    }

    /// # C: O(1)
    pub(crate) fn net_ns(&self) -> u64 { self.bind.net_ns() }

    /// # C: O(1)
    pub(crate) fn bound_iface(&self) -> Option<NetIfaceId> { self.bind.bound_iface() }

    /// The listening socket this request will be handed to. # C: O(1)
    pub(crate) fn listener(&self) -> Option<Arc<TcpListenEntry>> { self.listener.upgrade() }

    /// The sequence number this side's SYN-ACK carried. # C: O(1)
    pub(crate) fn isn(&self) -> u32 { self.negotiated.isn }

    /// One past the SYN-ACK, which is what the completing acknowledgement
    /// must name. # C: O(1)
    pub(crate) fn snd_nxt(&self) -> u32 { self.negotiated.isn.wrapping_add(1) }

    /// The peer's initial sequence, from which this request's receive window
    /// starts one further on. # C: O(1)
    pub(crate) fn peer_isn(&self) -> u32 { self.negotiated.peer_isn }

    /// The connection this request negotiated, materialised in the state the
    /// SYN-ACK left. Both the retransmit and the child are built from it, so
    /// there is one reconstruction rather than two. # C: O(1)
    pub(crate) fn open_conn(&self) -> alloc::boxed::Box<TcpConn> {
        let mut conn = alloc::boxed::Box::new(TcpConn::new_listener(self.local));
        conn.own_mss = self.own_mss;
        conn.path_mtu = self.path_mtu.load(Ordering::Acquire);
        conn.apply_route_metrics(self.metrics);
        conn.rcv_iif = self.rcv_iif;
        conn.rcv_ttl = self.rcv_ttl;
        conn.rcv_tos = self.rcv_tos;
        conn.open_from_cookie(self.remote.ip, self.remote.port, &self.negotiated);
        conn
    }

    /// Rebuild the SYN-ACK this request is owed. The first transmission and
    /// every retransmission come through here, so a peer that lost the answer
    /// gets the same negotiation back. # C: O(options)
    pub(crate) fn synack(&self) -> Vec<u8> {
        let mut conn = self.open_conn();
        conn.fastopen_opt = self.fastopen_opt;
        let mut flag_bits = crate::tcp_hdr::flags::SYN | crate::tcp_hdr::flags::ACK;
        if self.negotiated.opts.ecn_ok { flag_bits |= crate::tcp_hdr::flags::ECE; }
        conn.build_syn_with_opts_at(self.isn(), flag_bits)
    }

    /// Release this request's SYN-RECV reservation once. # C: O(1)
    pub(crate) fn release_syn_backlog(&self) {
        self.release_syn_backlog_young();
        if self.syn_backlog_reserved.swap(false, Ordering::AcqRel) {
            if let Some(listener) = self.listener() {
                listener.syn_backlog_used.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }

    /// Move this request out of the listener's young population once. # C: O(1)
    pub(crate) fn release_syn_backlog_young(&self) {
        if self.syn_backlog_young_reserved.swap(false, Ordering::AcqRel) {
            if let Some(listener) = self.listener() {
                listener.syn_backlog_young.fetch_sub(1, Ordering::AcqRel);
            }
        }
    }
}
