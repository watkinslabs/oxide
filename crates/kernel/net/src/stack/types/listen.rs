// The listening-socket record. Its own file: the connection, bind and
// listener types together crossed the per-file cutoff.

use super::*;

pub struct TcpListenEntry {
    /// Listening socket identity inherited by passive children.
    pub owner: Arc<crate::SocketOwner>,
    pub accept_q: Spinlock<VecDeque<Arc<TcpEntry>>, StackLockClass>,
    pub bind: Arc<TcpBindReservation>,
    /// Live listening-socket filter; passive children snapshot this state.
    pub bpf_filter: Arc<crate::bpf_filter::SocketFilter>,
    /// Live listening-socket IPv4 PMTU mode; each passive child snapshots it.
    pub ip_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
    /// Live listening-socket IPv6 PMTU mode; each passive child snapshots it.
    pub ipv6_mtu_discover: Arc<::core::sync::atomic::AtomicI32>,
    /// Live listening-socket `IPV6_MTU`; passive children snapshot this cell.
    pub ipv6_frag_size: Arc<::core::sync::atomic::AtomicI32>,
    /// Canonical `IPPROTO_IPV6` state inherited by passive TCP children.
    pub ipv6_opts: Arc<crate::sock_opts::sol_ipv6::Ipv6Opts>,
    /// Live listening-socket `SO_MAX_PACING_RATE`; passive children inherit it.
    pub max_pacing_rate: Arc<::core::sync::atomic::AtomicU64>,
    /// Live listening-socket hop-limit minimums; each passive child shares them.
    pub min_hop: Arc<crate::min_hop::MinHop>,
    /// Live listening-socket `SO_MARK`. A request admitted here takes the
    /// listening socket's mark, and the child that request becomes carries it
    /// as its own — which is what puts the SYN-ACK and everything after it on
    /// the route the listener's mark selects.
    pub mark: Arc<::core::sync::atomic::AtomicI32>,
    /// F192: backlog cap (listen(2), clamped by live `somaxconn`).
    pub backlog: ::core::sync::atomic::AtomicUsize,
    /// Half-open plus completed children not yet removed by accept.
    pub syn_backlog_used: ::core::sync::atomic::AtomicUsize,
    /// Requests that have not yet experienced their first timeout.
    pub syn_backlog_young: ::core::sync::atomic::AtomicUsize,
    pub accept_backlog_used: ::core::sync::atomic::AtomicUsize,
    /// `TCP_DEFER_ACCEPT` as the retransmit count the option stores — the
    /// number of request-timer firings a completed handshake is held at the
    /// request stage for. The option block is the source of truth; this is the
    /// applied copy the delivery path reads, in the same unit, so what
    /// `getsockopt` reports and what the deferral waits cannot disagree.
    pub defer_accept: ::core::sync::atomic::AtomicU8,
    /// `TCP_SYNCNT` as the SYN-ACK retransmit ceiling this listener's requests
    /// run under. `0` = the stack's own.
    pub synack_retries: ::core::sync::atomic::AtomicU8,
    /// The listening socket's own fast-open accept-queue state — the bound,
    /// this listener's keys, and the live occupancy the bound governs. Shared
    /// with the socket rather than copied: `TCP_FASTOPEN` may be written while
    /// the socket listens, and the occupancy the delivery path charges must be
    /// the same object `listen` sized.
    pub fastopen: Arc<crate::tcp_fastopen::FastOpenQueue>,
    /// `TCP_FASTOPEN_NO_COOKIE` as the delivery path reads it. The option
    /// block is the source of truth; this is the applied copy, in the same
    /// unit, reloaded whenever the option is written.
    pub fastopen_no_cookie: ::core::sync::atomic::AtomicBool,
    /// Listener close linearizes child admission and accept publication here.
    pub closed: ::core::sync::atomic::AtomicBool,
    pub local: Endpoint,
    /// F160: blocking-accept waiters.
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
    /// F181a: per-fd epoll subscribers (POLL_IN on accept_q growth).
    pub poll_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, StackLockClass>,
    /// SO_REUSEPORT group reached from the listen table on the delivery path.
    /// Published by listen-time join; the owning socket's cell holds membership.
    pub reuseport_group: crate::reuseport::ReuseportSlot,
}
