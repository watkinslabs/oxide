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
    Ipv4Conf(Ipv4ConfDev, Ipv4ConfKey),
}

impl NetSysctlKey {
    const BASE_COUNT: usize = 9;
    const COUNT: usize = Self::BASE_COUNT + Ipv4ConfDev::COUNT * Ipv4ConfKey::COUNT;

    const fn index(self) -> usize {
        match self {
            Self::Somaxconn => 0, Self::OptmemMax => 1,
            Self::TcpSyncookies => 2, Self::TcpTwReuse => 3,
            Self::TcpFinTimeout => 4, Self::TcpKeepaliveTime => 5,
            Self::IcmpEchoIgnoreAll => 6, Self::Ipv6DisableAll => 7,
            Self::Ipv6DisableDefault => 8,
            Self::Ipv4Conf(dev, key) => Self::BASE_COUNT
                + dev.index() * Ipv4ConfKey::COUNT + key.index(),
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

pub struct NetSysctls { values: [AtomicI64; NetSysctlKey::COUNT] }

impl NetSysctls {
    fn new() -> Self {
        Self { values: core::array::from_fn(|index| AtomicI64::new(NetSysctlKey::default_at(index))) }
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
            ping_group: crate::ping::GroupRange::new(), loopback: Spinlock::new(None),
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

/// AF_UNIX registry for the calling task's net_ns. # C: O(log N)
#[cfg(target_os = "oxide-kernel")]
pub fn current_unix_registry() -> UnixRegRef {
    ns_unix_registry(crate::netdev::current_net_ns())
}

#[cfg(target_os = "oxide-kernel")]
pub fn unix_ns_for_addr(addr: &crate::UnixAddr) -> u64 {
    unix_ns_for_addr_in(crate::netdev::current_net_ns(), addr)
}

/// Resolve an AF_UNIX registry key from a retained socket owner. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn unix_ns_for_addr_in(net_ns: u64, addr: &crate::UnixAddr) -> u64 {
    if addr.is_pathname() { 0 } else { net_ns }
}

#[cfg(target_os = "oxide-kernel")]
pub fn unix_ns_for_path(path: &str) -> u64 {
    if unix_path_is_global(path) { 0 } else { crate::netdev::current_net_ns() }
}

/// True for filesystem-global AF_UNIX pathname addresses. # C: O(1)
pub fn unix_path_is_global(path: &str) -> bool {
    !crate::unix_sock::unix_path_is_abstract(path)
}

#[cfg(target_os = "oxide-kernel")]
pub fn unix_registry_for_addr(addr: &crate::UnixAddr) -> UnixRegRef {
    ns_unix_registry(unix_ns_for_addr(addr))
}

#[cfg(target_os = "oxide-kernel")]
pub fn unix_registry_for_path(path: &str) -> UnixRegRef {
    ns_unix_registry(unix_ns_for_path(path))
}
