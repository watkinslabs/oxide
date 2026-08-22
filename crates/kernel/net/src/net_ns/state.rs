extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, Ordering};

use network_namespace::NetworkNamespaceRef;
use sync::{Socket as SockLockClass, Spinlock};

use crate::{LoopbackDev, UnixRegistry};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ipv4ConfDev { All, Default, Lo, Eth0 }

impl Ipv4ConfDev {
    const COUNT: usize = 4;
    const fn index(self) -> usize {
        match self { Self::All => 0, Self::Default => 1, Self::Lo => 2, Self::Eth0 => 3 }
    }
    const fn from_index(index: usize) -> Option<Self> {
        match index { 0 => Some(Self::All), 1 => Some(Self::Default),
            2 => Some(Self::Lo), 3 => Some(Self::Eth0), _ => None }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Ipv4ConfKey {
    AcceptLocal, AcceptRedirects, AcceptSourceRoute, ArpAccept, ArpAnnounce,
    ArpFilter, ArpIgnore, ArpNotify, BootpRelay, DisablePolicy, DisableXfrm,
    DropGratuitousArp, DropUnicastInL2Multicast, ForceIgmpVersion, Forwarding,
    IgnoreRoutesWithLinkdown, LogMartians, PromoteSecondaries, ProxyArp,
    ProxyArpPvlan, RouteLocalnet, RpFilter, SecureRedirects, SendRedirects,
    SharedMedia, SrcValidMark,
}

impl Ipv4ConfKey {
    const COUNT: usize = 26;
    const fn index(self) -> usize {
        match self {
            Self::AcceptLocal => 0, Self::AcceptRedirects => 1,
            Self::AcceptSourceRoute => 2, Self::ArpAccept => 3,
            Self::ArpAnnounce => 4, Self::ArpFilter => 5, Self::ArpIgnore => 6,
            Self::ArpNotify => 7, Self::BootpRelay => 8, Self::DisablePolicy => 9,
            Self::DisableXfrm => 10, Self::DropGratuitousArp => 11,
            Self::DropUnicastInL2Multicast => 12, Self::ForceIgmpVersion => 13,
            Self::Forwarding => 14, Self::IgnoreRoutesWithLinkdown => 15,
            Self::LogMartians => 16, Self::PromoteSecondaries => 17,
            Self::ProxyArp => 18, Self::ProxyArpPvlan => 19,
            Self::RouteLocalnet => 20, Self::RpFilter => 21,
            Self::SecureRedirects => 22, Self::SendRedirects => 23,
            Self::SharedMedia => 24, Self::SrcValidMark => 25,
        }
    }
    const fn from_index(index: usize) -> Option<Self> {
        Some(match index {
            0 => Self::AcceptLocal, 1 => Self::AcceptRedirects,
            2 => Self::AcceptSourceRoute, 3 => Self::ArpAccept,
            4 => Self::ArpAnnounce, 5 => Self::ArpFilter, 6 => Self::ArpIgnore,
            7 => Self::ArpNotify, 8 => Self::BootpRelay, 9 => Self::DisablePolicy,
            10 => Self::DisableXfrm, 11 => Self::DropGratuitousArp,
            12 => Self::DropUnicastInL2Multicast, 13 => Self::ForceIgmpVersion,
            14 => Self::Forwarding, 15 => Self::IgnoreRoutesWithLinkdown,
            16 => Self::LogMartians, 17 => Self::PromoteSecondaries,
            18 => Self::ProxyArp, 19 => Self::ProxyArpPvlan,
            20 => Self::RouteLocalnet, 21 => Self::RpFilter,
            22 => Self::SecureRedirects, 23 => Self::SendRedirects,
            24 => Self::SharedMedia, 25 => Self::SrcValidMark, _ => return None,
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NetSysctlKey {
    Somaxconn, OptmemMax, TcpSyncookies, TcpTwReuse, TcpFinTimeout,
    TcpKeepaliveTime, IcmpEchoIgnoreAll, Ipv6DisableAll, Ipv6DisableDefault,
    /// `net.ipv4.ip_nonlocal_bind` / `net.ipv6.ip_nonlocal_bind` — the
    /// namespace-wide half of the nonlocal-bind screen `crate::bind_screen`
    /// applies; the per-socket half is `IP_FREEBIND` / `IP_TRANSPARENT`.
    Ipv4NonlocalBind, Ipv6NonlocalBind,
    /// `net.ipv4.tcp_fastopen` — the enable bits both halves of fast open are
    /// judged against (`crate::tcp_fastopen`), not a boolean.
    TcpFastopen,
    /// `net.ipv4.tcp_fastopen_blackhole_timeout_sec` — how long active fast
    /// open pauses after a path is found to eat a SYN carrying data
    /// (`crate::tcp_fastopen::Blackhole`). Zero turns the pause off.
    TcpFastopenBlackholeTimeout,
    /// `net.ipv4.tcp_wmem` / `net.ipv4.tcp_rmem` — a three-value window per
    /// namespace, not a scalar: `Min` is the floor the transport may moderate
    /// down to, `Default` is what a new TCP socket starts with, `Max` is the
    /// autotuning ceiling.
    TcpWmem(BufWindow), TcpRmem(BufWindow),
    Ipv4Conf(Ipv4ConfDev, Ipv4ConfKey),
    /// `net.ipv6.conf.all.forwarding` — IPv6 transit admission is independent
    /// from the IPv4 router-mode knob.
    Ipv6Forwarding,
    /// `net.ipv6.auto_flowlabels` — the namespace policy a socket that never
    /// named one of its own inherits, and the one that can force or forbid
    /// generation outright (`crate::sock_opts::sol_ipv6::autolabel`).
    Ipv6AutoFlowLabels,
    /// `net.ipv4.igmp_max_msf` — how many sources one IPv4 multicast source
    /// filter may name (`crate::sock_opts::msfilter`).
    Ipv4IgmpMaxMsf,
    /// `net.ipv4.tcp_max_syn_backlog` — NOT the size of the SYN queue, which
    /// the listen backlog bounds. It bounds only the reserve a listener keeps
    /// for peers already proven reachable (`crate::listen_queue`).
    TcpMaxSynBacklog,
    /// `net.ipv4.tcp_abort_on_overflow` — whether a completed handshake the
    /// accept queue has no room for is reset at once or held for a retry
    /// (`crate::listen_queue::AcceptOverflow`).
    TcpAbortOnOverflow,
    /// `net.ipv4.tcp_nometrics_save` — a closing connection tells the
    /// per-destination cache nothing (`crate::tcp_metrics`).
    TcpNoMetricsSave,
    /// `net.ipv4.tcp_no_ssthresh_metrics_save` — the cache neither stores nor
    /// believes a slow-start threshold (`crate::tcp_metrics`).
    TcpNoSsthreshMetricsSave,
    /// `net.ipv4.tcp_reordering` — the baseline duplicate-ACK degree a fresh
    /// connection carries and the metrics cache treats as unobserved.
    TcpReordering,
    /// `net.ipv6.conf.{all,default}.optimistic_dad` and `use_optimistic`.
    /// Interface registration snapshots the default pair; the all pair is an
    /// independent namespace-wide override.
    Ipv6OptimisticDadAll, Ipv6OptimisticDadDefault,
    Ipv6UseOptimisticAll, Ipv6UseOptimisticDefault,
    Ipv6UseTempaddrAll, Ipv6UseTempaddrDefault,
    Ipv6TempValidLftAll, Ipv6TempValidLftDefault,
    Ipv6TempPreferredLftAll, Ipv6TempPreferredLftDefault,
    /// `net.ipv4.tcp_invalid_ratelimit`, in milliseconds.
    TcpInvalidRatelimit,
    /// Per-namespace handshake-option admission.
    TcpTimestamps, TcpSack, TcpWindowScaling,
}

/// One slot of a three-value socket-buffer window. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BufWindow { Min, Default, Max }

impl BufWindow {
    pub const COUNT: usize = 3;
    const fn index(self) -> usize {
        match self { Self::Min => 0, Self::Default => 1, Self::Max => 2 }
    }
    const fn from_index(index: usize) -> Option<Self> {
        Some(match index { 0 => Self::Min, 1 => Self::Default, 2 => Self::Max, _ => return None })
    }
}

impl NetSysctlKey {
    const WMEM_BASE: usize = 13;
    const RMEM_BASE: usize = Self::WMEM_BASE + BufWindow::COUNT;
    const BASE_COUNT: usize = Self::RMEM_BASE + BufWindow::COUNT;
    const IPV6_FORWARDING: usize = Self::BASE_COUNT + Ipv4ConfDev::COUNT * Ipv4ConfKey::COUNT;
    const IPV6_AUTO_FLOWLABELS: usize = Self::IPV6_FORWARDING + 1;
    const IPV4_IGMP_MAX_MSF: usize = Self::IPV6_AUTO_FLOWLABELS + 1;
    const TCP_MAX_SYN_BACKLOG: usize = Self::IPV4_IGMP_MAX_MSF + 1;
    const TCP_ABORT_ON_OVERFLOW: usize = Self::TCP_MAX_SYN_BACKLOG + 1;
    const TCP_NOMETRICS_SAVE: usize = Self::TCP_ABORT_ON_OVERFLOW + 1;
    const TCP_NO_SSTHRESH_METRICS_SAVE: usize = Self::TCP_NOMETRICS_SAVE + 1;
    const TCP_REORDERING: usize = Self::TCP_NO_SSTHRESH_METRICS_SAVE + 1;
    const IPV6_OPTIMISTIC_DAD_ALL: usize = Self::TCP_REORDERING + 1;
    const IPV6_OPTIMISTIC_DAD_DEFAULT: usize = Self::IPV6_OPTIMISTIC_DAD_ALL + 1;
    const IPV6_USE_OPTIMISTIC_ALL: usize = Self::IPV6_OPTIMISTIC_DAD_DEFAULT + 1;
    const IPV6_USE_OPTIMISTIC_DEFAULT: usize = Self::IPV6_USE_OPTIMISTIC_ALL + 1;
    const IPV6_USE_TEMPADDR_ALL: usize = Self::IPV6_USE_OPTIMISTIC_DEFAULT + 1;
    const IPV6_USE_TEMPADDR_DEFAULT: usize = Self::IPV6_USE_TEMPADDR_ALL + 1;
    const IPV6_TEMP_VALID_LFT_ALL: usize = Self::IPV6_USE_TEMPADDR_DEFAULT + 1;
    const IPV6_TEMP_VALID_LFT_DEFAULT: usize = Self::IPV6_TEMP_VALID_LFT_ALL + 1;
    const IPV6_TEMP_PREFERRED_LFT_ALL: usize = Self::IPV6_TEMP_VALID_LFT_DEFAULT + 1;
    const IPV6_TEMP_PREFERRED_LFT_DEFAULT: usize = Self::IPV6_TEMP_PREFERRED_LFT_ALL + 1;
    const TCP_INVALID_RATELIMIT: usize = Self::IPV6_TEMP_PREFERRED_LFT_DEFAULT + 1;
    const TCP_TIMESTAMPS: usize = Self::TCP_INVALID_RATELIMIT + 1;
    const TCP_SACK: usize = Self::TCP_TIMESTAMPS + 1;
    const TCP_WINDOW_SCALING: usize = Self::TCP_SACK + 1;
    const COUNT: usize = Self::TCP_WINDOW_SCALING + 1;

    const fn index(self) -> usize {
        match self {
            Self::Somaxconn => 0, Self::OptmemMax => 1,
            Self::TcpSyncookies => 2, Self::TcpTwReuse => 3,
            Self::TcpFinTimeout => 4, Self::TcpKeepaliveTime => 5,
            Self::IcmpEchoIgnoreAll => 6, Self::Ipv6DisableAll => 7,
            Self::Ipv6DisableDefault => 8,
            Self::Ipv4NonlocalBind => 9, Self::Ipv6NonlocalBind => 10,
            Self::TcpFastopen => 11,
            Self::TcpFastopenBlackholeTimeout => 12,
            Self::TcpWmem(slot) => Self::WMEM_BASE + slot.index(),
            Self::TcpRmem(slot) => Self::RMEM_BASE + slot.index(),
            Self::Ipv4Conf(dev, key) => Self::BASE_COUNT
                + dev.index() * Ipv4ConfKey::COUNT + key.index(),
            Self::Ipv6Forwarding => Self::IPV6_FORWARDING,
            Self::Ipv6AutoFlowLabels => Self::IPV6_AUTO_FLOWLABELS,
            Self::Ipv4IgmpMaxMsf => Self::IPV4_IGMP_MAX_MSF,
            Self::TcpMaxSynBacklog => Self::TCP_MAX_SYN_BACKLOG,
            Self::TcpAbortOnOverflow => Self::TCP_ABORT_ON_OVERFLOW,
            Self::TcpNoMetricsSave => Self::TCP_NOMETRICS_SAVE,
            Self::TcpNoSsthreshMetricsSave => Self::TCP_NO_SSTHRESH_METRICS_SAVE,
            Self::TcpReordering => Self::TCP_REORDERING,
            Self::Ipv6OptimisticDadAll => Self::IPV6_OPTIMISTIC_DAD_ALL,
            Self::Ipv6OptimisticDadDefault => Self::IPV6_OPTIMISTIC_DAD_DEFAULT,
            Self::Ipv6UseOptimisticAll => Self::IPV6_USE_OPTIMISTIC_ALL,
            Self::Ipv6UseOptimisticDefault => Self::IPV6_USE_OPTIMISTIC_DEFAULT,
            Self::Ipv6UseTempaddrAll => Self::IPV6_USE_TEMPADDR_ALL,
            Self::Ipv6UseTempaddrDefault => Self::IPV6_USE_TEMPADDR_DEFAULT,
            Self::Ipv6TempValidLftAll => Self::IPV6_TEMP_VALID_LFT_ALL,
            Self::Ipv6TempValidLftDefault => Self::IPV6_TEMP_VALID_LFT_DEFAULT,
            Self::Ipv6TempPreferredLftAll => Self::IPV6_TEMP_PREFERRED_LFT_ALL,
            Self::Ipv6TempPreferredLftDefault => Self::IPV6_TEMP_PREFERRED_LFT_DEFAULT,
            Self::TcpInvalidRatelimit => Self::TCP_INVALID_RATELIMIT,
            Self::TcpTimestamps => Self::TCP_TIMESTAMPS,
            Self::TcpSack => Self::TCP_SACK,
            Self::TcpWindowScaling => Self::TCP_WINDOW_SCALING,
        }
    }

    pub const fn as_usize(self) -> usize { self.index() }

    pub const fn from_usize(index: usize) -> Option<Self> {
        Some(match index {
            0 => Self::Somaxconn, 1 => Self::OptmemMax,
            2 => Self::TcpSyncookies, 3 => Self::TcpTwReuse,
            4 => Self::TcpFinTimeout, 5 => Self::TcpKeepaliveTime,
            6 => Self::IcmpEchoIgnoreAll, 7 => Self::Ipv6DisableAll,
            8 => Self::Ipv6DisableDefault,
            9 => Self::Ipv4NonlocalBind, 10 => Self::Ipv6NonlocalBind,
            11 => Self::TcpFastopen,
            12 => Self::TcpFastopenBlackholeTimeout,
            _ if index < Self::RMEM_BASE => match BufWindow::from_index(index - Self::WMEM_BASE) {
                Some(slot) => Self::TcpWmem(slot), None => return None,
            },
            _ if index < Self::BASE_COUNT => match BufWindow::from_index(index - Self::RMEM_BASE) {
                Some(slot) => Self::TcpRmem(slot), None => return None,
            },
            Self::IPV6_FORWARDING => Self::Ipv6Forwarding,
            Self::IPV6_AUTO_FLOWLABELS => Self::Ipv6AutoFlowLabels,
            Self::IPV4_IGMP_MAX_MSF => Self::Ipv4IgmpMaxMsf,
            Self::TCP_MAX_SYN_BACKLOG => Self::TcpMaxSynBacklog,
            Self::TCP_ABORT_ON_OVERFLOW => Self::TcpAbortOnOverflow,
            Self::TCP_NOMETRICS_SAVE => Self::TcpNoMetricsSave,
            Self::TCP_NO_SSTHRESH_METRICS_SAVE => Self::TcpNoSsthreshMetricsSave,
            Self::TCP_REORDERING => Self::TcpReordering,
            Self::IPV6_OPTIMISTIC_DAD_ALL => Self::Ipv6OptimisticDadAll,
            Self::IPV6_OPTIMISTIC_DAD_DEFAULT => Self::Ipv6OptimisticDadDefault,
            Self::IPV6_USE_OPTIMISTIC_ALL => Self::Ipv6UseOptimisticAll,
            Self::IPV6_USE_OPTIMISTIC_DEFAULT => Self::Ipv6UseOptimisticDefault,
            Self::IPV6_USE_TEMPADDR_ALL => Self::Ipv6UseTempaddrAll,
            Self::IPV6_USE_TEMPADDR_DEFAULT => Self::Ipv6UseTempaddrDefault,
            Self::IPV6_TEMP_VALID_LFT_ALL => Self::Ipv6TempValidLftAll,
            Self::IPV6_TEMP_VALID_LFT_DEFAULT => Self::Ipv6TempValidLftDefault,
            Self::IPV6_TEMP_PREFERRED_LFT_ALL => Self::Ipv6TempPreferredLftAll,
            Self::IPV6_TEMP_PREFERRED_LFT_DEFAULT => Self::Ipv6TempPreferredLftDefault,
            Self::TCP_INVALID_RATELIMIT => Self::TcpInvalidRatelimit,
            Self::TCP_TIMESTAMPS => Self::TcpTimestamps,
            Self::TCP_SACK => Self::TcpSack,
            Self::TCP_WINDOW_SCALING => Self::TcpWindowScaling,
            _ => {
                let relative = index - Self::BASE_COUNT;
                let dev = match Ipv4ConfDev::from_index(relative / Ipv4ConfKey::COUNT) {
                    Some(value) => value, None => return None,
                };
                let key = match Ipv4ConfKey::from_index(relative % Ipv4ConfKey::COUNT) {
                    Some(value) => value, None => return None,
                };
                Self::Ipv4Conf(dev, key)
            }
        })
    }

    fn default_at(index: usize) -> i64 {
        match index {
            0 => crate::sysctl::DEFAULT_SOMAXCONN as i64,
            1 => crate::sysctl::DEFAULT_OPTMEM_MAX as i64,
            2 => 1,
            3 => 2,
            4 => 60,
            5 => 7_200,
            11 => crate::tcp_fastopen::TFO_DEFAULT as i64,
            12 => crate::tcp_fastopen::BLACKHOLE_TIMEOUT_DEFAULT,
            Self::IPV6_AUTO_FLOWLABELS =>
                crate::sock_opts::sol_ipv6::autolabel::DEFAULT_POLICY,
            Self::IPV4_IGMP_MAX_MSF => crate::sock_opts::msfilter::DEFAULT_IGMP_MAX_MSF,
            Self::TCP_MAX_SYN_BACKLOG => crate::listen_queue::DEFAULT_MAX_SYN_BACKLOG,
            Self::TCP_ABORT_ON_OVERFLOW => crate::listen_queue::DEFAULT_ABORT_ON_OVERFLOW,
            Self::TCP_NOMETRICS_SAVE | Self::TCP_NO_SSTHRESH_METRICS_SAVE => 0,
            Self::TCP_REORDERING => crate::sysctl::DEFAULT_TCP_REORDERING,
            Self::IPV6_OPTIMISTIC_DAD_ALL | Self::IPV6_OPTIMISTIC_DAD_DEFAULT
                | Self::IPV6_USE_OPTIMISTIC_ALL | Self::IPV6_USE_OPTIMISTIC_DEFAULT => 0,
            Self::IPV6_USE_TEMPADDR_ALL | Self::IPV6_USE_TEMPADDR_DEFAULT => 0,
            Self::IPV6_TEMP_VALID_LFT_ALL | Self::IPV6_TEMP_VALID_LFT_DEFAULT => 172_800,
            Self::IPV6_TEMP_PREFERRED_LFT_ALL | Self::IPV6_TEMP_PREFERRED_LFT_DEFAULT => 86_400,
            Self::TCP_INVALID_RATELIMIT =>
                crate::tcp_conn::reqsk::INVALID_RATELIMIT_DEFAULT_MS as i64,
            Self::TCP_TIMESTAMPS | Self::TCP_SACK | Self::TCP_WINDOW_SCALING => 1,
            _ if index >= Self::WMEM_BASE && index < Self::RMEM_BASE =>
                crate::sysctl::DEFAULT_TCP_WMEM[index - Self::WMEM_BASE],
            _ if index >= Self::RMEM_BASE && index < Self::BASE_COUNT =>
                crate::sysctl::DEFAULT_TCP_RMEM[index - Self::RMEM_BASE],
            _ if index >= Self::BASE_COUNT => match (index - Self::BASE_COUNT)
                % Ipv4ConfKey::COUNT
            {
                1 | 22 | 23 | 24 => 1,
                _ => 0,
            },
            _ => 0,
        }
    }
}

/// One namespace's sysctl values.
///
/// The value array is a separate heap allocation reached by pointer, not an
/// inline member, for the same reason the destination metrics cache keeps its
/// bucket array out of line: this struct is built inside `NsNet`, which is
/// itself assembled as a temporary before it is moved into its `Arc`, so
/// every inline byte here is a byte on the stack of the namespace-state
/// lookup — a path reachable from the socket destructor cascade, which is
/// already the deepest chain in the kernel. `NetSysctlKey::COUNT` is over a
/// hundred slots, so inline it was the largest single contributor to that
/// frame, and it grew every time a knob was added.
pub struct NetSysctls { values: alloc::boxed::Box<[AtomicI64]> }

impl NetSysctls {
    /// Values are pushed one at a time into a heap vector, never built as an
    /// array temporary — the temporary is what put the whole array on the
    /// stack. # C: O(COUNT)
    fn new() -> Self {
        let mut values = alloc::vec::Vec::with_capacity(NetSysctlKey::COUNT);
        for index in 0..NetSysctlKey::COUNT {
            values.push(AtomicI64::new(NetSysctlKey::default_at(index)));
        }
        Self { values: values.into_boxed_slice() }
    }

    pub(crate) fn get(&self, key: NetSysctlKey) -> i64 {
        self.values[key.index()].load(Ordering::Acquire)
    }

    pub(crate) fn set(&self, key: NetSysctlKey, value: i64) {
        self.values[key.index()].store(value, Ordering::Release);
    }
}

/// Canonical non-transport state for one live network namespace.
pub struct NsNet {
    pub unix: UnixRegistry,
    pub(crate) sysctls: NetSysctls,
    pub(crate) ports: crate::ephemeral::State,
    pub(crate) ping_group: crate::ping::GroupRange,
    /// `net.ipv4.tcp_fastopen_key` — the keys every listener in this namespace
    /// that named none of its own mints fast-open cookies from.
    pub(crate) fastopen_keys: crate::tcp_fastopen::NsKeys,
    /// The cookies this namespace's clients learned, keyed by destination.
    /// Linux `tcp_metrics_hash`: what this namespace learned about each
    /// destination's path, and the fast-open state for the same row.
    pub(crate) metrics_cache: crate::tcp_metrics::MetricsCache,
    /// The pause on active fast open after a path here ate one.
    pub(crate) fastopen_blackhole: crate::tcp_fastopen::Blackhole,
    pub(crate) loopback: Spinlock<Option<(crate::NetIfaceId, Arc<LoopbackDev>)>, SockLockClass>,
}

/// Namespace state paired with the canonical owner that keeps its ID live.
pub struct NsNetRef {
    owner: NetworkNamespaceRef,
    state: Arc<NsNet>,
}

impl NsNetRef {
    /// Clone the retained namespace owner. # C: O(1)
    pub fn owner(&self) -> NetworkNamespaceRef { Arc::clone(&self.owner) }
}

impl core::ops::Deref for NsNetRef {
    type Target = NsNet;
    /// # C: O(1)
    fn deref(&self) -> &NsNet { &self.state }
}

impl NsNet {
    /// # C: O(1)
    fn new() -> Arc<Self> {
        Arc::new(Self {
            unix: UnixRegistry::new(), sysctls: NetSysctls::new(),
            ports: crate::ephemeral::State::new(),
            ping_group: crate::ping::GroupRange::new(),
            fastopen_keys: Spinlock::new(None),
            metrics_cache: crate::tcp_metrics::MetricsCache::new(),
            fastopen_blackhole: crate::tcp_fastopen::Blackhole::new(),
            loopback: Spinlock::new(None),
        })
    }
}

pub(super) static NET_NS: Spinlock<BTreeMap<u64, Arc<NsNet>>, SockLockClass> =
    Spinlock::new(BTreeMap::new());

/// Materialize canonical state from a retained namespace owner. # C: O(log N)
pub fn materialize_state(namespace: &NetworkNamespaceRef) -> NsNetRef {
    let ns = namespace.id().as_u64();
    let mut states = NET_NS.lock();
    let state = if let Some(state) = states.get(&ns) { Arc::clone(state) }
    else {
        let state = NsNet::new();
        states.insert(ns, Arc::clone(&state));
        state
    };
    NsNetRef { owner: Arc::clone(namespace), state }
}

/// Resolve a live namespace and materialize its canonical state. Dead or
/// invented numeric IDs cannot recreate state. # C: O(log N)
pub fn try_ns_net(ns: u64) -> Option<NsNetRef> {
    let namespace = network_namespace::lookup_u64(ns)?;
    Some(materialize_state(&namespace))
}

/// Resolve or materialize state only while the numeric identity remains live.
/// Never reconstructs a namespace owner. # C: O(log N)
pub fn state_by_id(ns: u64) -> Option<NsNetRef> {
    try_ns_net(ns)
}

/// Resolve already-materialized state for a retained owner. # C: O(log N)
pub fn state_for(namespace: &NetworkNamespaceRef) -> Option<NsNetRef> {
    let state = NET_NS.lock().get(&namespace.id().as_u64()).cloned()?;
    Some(NsNetRef { owner: Arc::clone(namespace), state })
}

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub enum UnixRegRef { Global, Ns(NsNetRef) }

#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
impl core::ops::Deref for UnixRegRef {
    type Target = UnixRegistry;
    /// # C: O(1)
    fn deref(&self) -> &UnixRegistry {
        match self { Self::Global => &crate::sock::UNIX_REGISTRY, Self::Ns(state) => &state.unix }
    }
}

/// AF_UNIX registry for an explicit live net_ns. # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub fn ns_unix_registry(ns: u64) -> UnixRegRef {
    if ns == 0 { UnixRegRef::Global }
    else { UnixRegRef::Ns(state_by_id(ns).expect("live socket namespace has materialized state")) }
}

/// AF_UNIX registry selected from a retained socket namespace owner. # C: O(log N)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn unix_registry_for_addr_in(namespace: &NetworkNamespaceRef,
    addr: &crate::UnixAddr) -> UnixRegRef
{
    if addr.is_pathname() || namespace.id().as_u64() == 0 { UnixRegRef::Global }
    else {
        UnixRegRef::Ns(state_for(namespace)
            .expect("live socket namespace has materialized state"))
    }
}

/// True for filesystem-global AF_UNIX pathname addresses. # C: O(1)
pub fn unix_path_is_global(path: &str) -> bool {
    !crate::unix_sock::unix_path_is_abstract(path)
}
