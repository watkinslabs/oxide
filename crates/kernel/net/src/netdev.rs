// Module manifest: ingress owns generation admission; tx_dispatch owns
// queued/direct hardware serialization; registration owns publication;
// packet_filter/packet_metadata own driver packet contracts; ipv6_conf owns
// per-interface IPv6 policy; mcast_report and registry_state own registry
// synchronization state; stats owns sysfs counter projection.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sync::{Spinlock, Socket as SocketLockClass};

use crate::addr::NetIfaceId;

#[path = "netdev/ingress.rs"]
mod ingress;
#[path = "netdev/tx_band.rs"]
pub mod tx_band;
#[path = "netdev/tx_dispatch.rs"]
pub(crate) mod tx_dispatch;
#[path = "netdev/registration.rs"]
mod registration;
#[path = "netdev/packet_filter.rs"]
mod packet_filter;
#[path = "netdev/packet_metadata.rs"]
mod packet_metadata;
#[path = "netdev/flags.rs"]
pub mod iff;
#[path = "netdev/error.rs"]
mod error;
#[path = "netdev/registry_views.rs"]
mod registry_views;
#[path = "netdev/device.rs"]
mod device;
#[path = "netdev/rx_queue.rs"]
pub mod rx_queue;
#[path = "netdev/ipv6_conf.rs"]
mod ipv6_conf;
#[path = "netdev/mcast_report.rs"]
mod mcast_report;
#[path = "netdev/registry_state.rs"]
mod registry_state;
#[path = "netdev/stats.rs"]
mod stats;
pub use ingress::{EgressLease, IngressLease};
pub(crate) use ingress::ControlEffectLease;
pub(crate) use ingress::{IfaceTeardown, IfaceUnregisterClaim};
pub(crate) use ingress::IngressGate;
pub use registration::IfaceRegistration;
pub use packet_filter::{PACKET_LINK_ADDRESS_MAX, PacketLinkAddress, PacketRxMode};
pub use packet_metadata::{PacketChecksum, PacketRxMetadata, PacketVirtioMetadata, PacketVlan};
pub(crate) use packet_filter::PacketDeviceFilter;
pub use error::{NetError, NetResult};
pub use device::{NetDev, WanSettings};
pub use rx_queue::{HdsConfig, QueueCaps, RxQueue, RxQueues};
pub use ipv6_conf::{Ipv6ConfKey, Ipv6DevConf};
pub(crate) use mcast_report::McastReportState;
pub(crate) use registry_state::{IfaceRegistryLock, RegistryInner};
pub use stats::STAT_FIELDS;

type NetdevChangeHook = fn(&str, Option<&Arc<drv::Device>>);
static NETDEV_CHANGE_HOOK: Spinlock<Option<NetdevChangeHook>, SocketLockClass> = Spinlock::new(None);

/// Install the netdev publication hook used by sysfs to invalidate the exact
/// class and parent-device dentries. # C: O(1)
pub fn set_change_hook(f: NetdevChangeHook) { *NETDEV_CHANGE_HOOK.lock() = Some(f); }

/// Notify the sysfs projection after a live interface changes. # C: O(1)
pub(crate) fn notify_changed(name: &str, parent: Option<&Arc<drv::Device>>) {
    let hook = *NETDEV_CHANGE_HOOK.lock();
    if let Some(f) = hook { f(name, parent); }
}

/// Per-iface running counters for `/proc/net/dev` and ethtool.
#[derive(Copy, Clone, Debug, Default)]
pub struct NetStats {
    pub rx_packets: u64,
    pub rx_bytes:   u64,
    pub rx_errors:  u64,
    pub rx_dropped: u64,
    pub tx_packets: u64,
    pub tx_bytes:   u64,
    pub tx_errors:  u64,
    pub tx_dropped: u64,
}

/// Linux `struct ifmap` resource coordinates owned by a network device.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IfaceMap {
    pub mem_start: u64,
    pub mem_end: u64,
    pub base_addr: u16,
    pub irq: u8,
    pub dma: u8,
    pub port: u8,
}

/// Atomic interface snapshot for procfs/netlink-style readers. Name,
/// MTU, flags, and counters are captured while the registry entry is
/// live, so readers do not need a second lookup that can race removal.
#[derive(Clone, Debug)]
pub struct IfaceSnapshot {
    pub id:    NetIfaceId,
    /// Linux-visible interface index, allocated independently in every
    /// network namespace. `id` remains the process-global internal handle.
    pub ifindex: u32,
    pub name:  String,
    pub mtu:   u32,
    pub flags: u32,
    pub stats: NetStats,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NamespaceDropAction { Destroy, MoveToInitial }

pub struct IfaceEntry {
    pub id:   NetIfaceId,
    /// Canonical Linux ifindex within `ns`. Unlike `id`, this is reused by
    /// different network namespaces (in particular, each `lo` is index 1).
    pub ifindex: u32,
    /// Network namespace id (CLONE_NEWNET). 0 = init NS. Tasks see
    /// only entries matching their own net_ns.
    pub ns:   u64,
    pub dev:  Arc<dyn NetDev>,
    /// Model device that physically owns this interface. The interface
    /// registry retains this exact object so sysfs follows the same live
    /// parent chain as the driver model instead of rediscovering it by name.
    pub parent: Option<Arc<drv::Device>>,
    /// Canonical Linux interface name. Device identity and registry naming
    /// are separate: drivers provide the initial name, while the registry
    /// owns namespace-scoped rename semantics.
    pub name: String,
    /// Driver-owned carrier, the reference's `__LINK_STATE_NOCARRIER` in
    /// `dev->state`. It is deliberately NOT a bit in `flags`: `IFF_RUNNING`
    /// and `IFF_LOWER_UP` are derived from it at read time by `dev_get_flags`,
    /// and userspace can neither see nor write the underlying state. Kept in
    /// the flags word it was cleared by an ordinary administrative write, so a
    /// link reported no carrier the moment anyone brought it up — and a manager
    /// that has just brought a device up and is told it has no carrier refuses
    /// to activate it: "device has no carrier".
    pub carrier: AtomicBool,
    /// Real, mutable IFF_* flags. Set at registration from the device
    /// kind; mutated by RTM_SETLINK; read by RTM_GETLINK. Not a
    /// reply-time fabrication.
    pub flags: AtomicU32,
    /// Orders multicast state transitions and their state-change reports.
    pub(crate) mcast_report: Arc<McastReportState>,
    pub(crate) packet_filter: Arc<PacketDeviceFilter>,
    /// Canonical per-interface IPv4 neighbour owner. It is created with the
    /// interface generation and disappears when that generation is removed.
    pub(crate) arp: Arc<crate::arp::ArpCache>,
    /// IPv6 half of the same neighbour table.
    pub(crate) ndp: Arc<crate::neigh::NeighCache<crate::Ipv6Addr>>,
    pub(crate) ipv6_conf: Arc<Ipv6DevConf>,
    ingress: Arc<IngressGate>,
    /// This device's receive queues. Held by `Arc` because a memory-provider
    /// binding outlives the registry row: a provider bound to a queue keeps
    /// the queue alive until it unbinds, so an unregistering device can never
    /// strand one.
    pub(crate) rx_queues: Arc<super::netdev::RxQueues>,
}

/// Process-global iface table. `register_netdev` pushes; `iface`
/// looks up by id. `up_ifaces` snapshots for boot-trace dumps.
pub struct IfaceRegistry {
    pub(crate) inner: IfaceRegistryLock,
}

impl IfaceRegistry {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: IfaceRegistryLock::new(RegistryInner::new()) }
    }

    /// Hosted cleanup for a registry not owned by a `NetStack`.
    /// # C: O(N)
    #[cfg(not(target_os = "oxide-kernel"))]
    pub fn unregister(&self, id: NetIfaceId) -> Option<Arc<dyn NetDev>> {
        let gate = {
            let g = self.inner.lock();
            let entry = g.entries.iter().find(|entry| entry.id == id)?;
            if !entry.ingress.ready() { return None; }
            if !entry.ingress.close() { return None; }
            entry.ingress.clone()
        };
        gate.wait();
        let (dev, old_name, parent, rxq) = {
            let mut g = self.inner.lock();
            let pos = g.entries.iter().position(|entry| entry.id == id
                && Arc::ptr_eq(&entry.ingress, &gate) && gate.drained())?;
            let entry = g.entries.remove(pos);
            (entry.dev, entry.name, entry.parent, entry.rx_queues)
        };
        // Off the registry lock: a provider learning its queue is gone runs
        // its own teardown, which must not re-enter the registry.
        rx_queue::uninstall_all(&rxq);
        notify_changed(&old_name, parent.as_ref());
        gate.finish();
        Some(dev)
    }

    /// Current IFF_* flags for `id` (init NS). # C: O(N)
    pub fn iface_flags(&self, id: NetIfaceId) -> Option<u32> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ingress.live() && e.ingress.ready())
            // REPORTED flags, so every reader gets one answer. This is the
            // accessor the reference funnels callers through (`dev_get_flags`):
            // carrier lives outside the stored word and `IFF_RUNNING` /
            // `IFF_LOWER_UP` are computed here. Returning the raw word made two
            // ways to read flags that could disagree, and the link dump took
            // the raw one — so a device with carrier still reported NO-CARRIER.
            .map(|e| iff::dev_get_flags(e.flags.load(Ordering::Acquire),
                                        e.carrier.load(Ordering::Acquire)))
    }

    /// Driver-reported carrier for one interface — the reference's
    /// `netif_carrier_ok`. # C: O(N)
    pub fn iface_carrier(&self, id: NetIfaceId) -> Option<bool> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ingress.live() && e.ingress.ready())
            .map(|e| e.carrier.load(Ordering::Acquire))
    }

    fn guard_matches(&self, rtnl: &crate::RtnlGuard<'_>) -> bool {
        core::ptr::eq(self, &rtnl.stack().ifaces)
    }

    /// Lookup control-ready interface in captured namespace. # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub fn control_ready_in_ns(&self, rtnl: &crate::RtnlGuard<'_>, id: NetIfaceId, ns: u64)
        -> Option<Arc<dyn NetDev>>
    {
        if !self.guard_matches(rtnl) { return None; }
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns
            && e.ingress.live() && e.ingress.ready())
            .map(|e| e.dev.clone())
    }

    /// Control-ready namespace generation under matching stack RTNL. # C: O(N)
    pub fn control_generation_in_ns(&self, rtnl: &crate::RtnlGuard<'_>,
                                    id: NetIfaceId, ns: u64) -> Option<u64> {
        if !self.guard_matches(rtnl) { return None; }
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns
            && e.ingress.live() && e.ingress.ready())
            .map(|e| e.ingress.generation)
    }

    /// Interface control generation for the RECEIVE path, without RTNL.
    ///
    /// The RTNL-taking variant above uses the guard only as a discipline token
    /// (`guard_matches`); the data itself is protected by `self.inner`. RX runs
    /// in softirq, where RTNL must not be taken at all -- Linux reads device
    /// state on the receive side under RCU, never under `rtnl_lock()`, for
    /// exactly this reason. Same read, same lock, no token.
    /// # Ctx: any, including softirq
    /// # C: O(N)
    pub fn control_generation_in_ns_rx(&self, id: NetIfaceId, ns: u64) -> Option<u64> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns
            && e.ingress.live() && e.ingress.ready())
            .map(|e| e.ingress.generation)
    }

    /// Lookup control-ready interface name in captured namespace. # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub fn control_ready_name_in_ns(&self, rtnl: &crate::RtnlGuard<'_>, name: &str, ns: u64)
        -> Option<(NetIfaceId, Arc<dyn NetDev>)>
    {
        self.control_ready_name_generation_in_ns(rtnl, name, ns)
            .map(|(id, dev, _)| (id, dev))
    }

    /// Lookup control-ready interface name and namespace generation. # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub fn control_ready_name_generation_in_ns(&self, rtnl: &crate::RtnlGuard<'_>,
                                                name: &str, ns: u64)
        -> Option<(NetIfaceId, Arc<dyn NetDev>, u64)>
    {
        if !self.guard_matches(rtnl) { return None; }
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.name == name && e.ns == ns
            && e.ingress.live() && e.ingress.ready())
            .map(|e| (e.id, e.dev.clone(), e.ingress.generation))
    }

    /// Rename one live interface under the matching RTNL and namespace. # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub fn rename_in_ns(&self, rtnl: &crate::RtnlGuard<'_>, id: NetIfaceId, ns: u64,
                        name: &str) -> Result<String, syscall::errno::Errno> {
        if !self.guard_matches(rtnl) { return Err(syscall::errno::Errno::Enodev); }
        let mut g = self.inner.lock();
        if g.entries.iter().any(|e| e.name == name && e.ns == ns && e.id != id
            && e.ingress.live() && e.ingress.ready()) {
            return Err(syscall::errno::Errno::Eexist);
        }
        let entry = g.entries.iter_mut().find(|e| e.id == id && e.ns == ns
            && e.ingress.live() && e.ingress.ready())
            .ok_or(syscall::errno::Errno::Enodev)?;
        let old = core::mem::replace(&mut entry.name, String::from(name));
        Ok(old)
    }

    /// Apply namespace-qualified Linux ifinfomsg flag mutation. # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub fn set_iface_flags_in_ns(&self, rtnl: &crate::RtnlGuard<'_>, id: NetIfaceId, ns: u64,
                                 new: u32, change: u32) -> Option<u32> {
        if !self.guard_matches(rtnl) { return None; }
        // A caller may not write the volatile bits. They describe the device
        // and its driver's carrier, not an administrative request, and the
        // reference never takes them from userspace — `__dev_change_flags`
        // preserves `IFF_VOLATILE` from the device. Without this an ordinary
        // "bring the link up" cleared `IFF_RUNNING`, so the link reported no
        // carrier the instant anyone administered it.
        let change = change & !iff::IFF_VOLATILE;
        let rx_change = change & (iff::IFF_PROMISC | iff::IFF_ALLMULTI);
        let (notify, admin_transition, next) = {
            let g = self.inner.lock();
            let e = g.entries.iter().find(|e| e.id == id && e.ns == ns
                && e.ingress.live() && e.ingress.ready())?;
            let cur = e.flags.load(Ordering::Acquire);
            let mut next = (cur & !change) | (new & change);
            let admin_transition = (change & iff::IFF_UP != 0
                && (cur ^ next) & iff::IFF_UP != 0)
                .then(|| (e.dev.clone(), next & iff::IFF_UP != 0));
            let notify = if rx_change != 0 {
                let mode = e.packet_filter.update_admin(new, rx_change);
                if mode.promiscuous { next |= iff::IFF_PROMISC; }
                else { next &= !iff::IFF_PROMISC; }
                if mode.all_multicast { next |= iff::IFF_ALLMULTI; }
                else { next &= !iff::IFF_ALLMULTI; }
                Some((e.dev.clone(), mode))
            } else { None };
            e.flags.store(next, Ordering::Release);
            (notify, admin_transition, next)
        };
        // Match Linux `dev_change_flags`: run the ndo_open/ndo_stop edge
        // under RTNL but outside the interface registry lock. Driver startup
        // can take DMA/IRQ locks and must never nest beneath this index.
        if let Some((dev, up)) = admin_transition { dev.admin_up_changed(up); }
        if let Some((dev, mode)) = notify { dev.packet_rx_mode_changed(&mode); }
        Some(next)
    }

    /// Apply a driver carrier transition under the matching RTNL. The caller
    /// owns the later link notification, after it has captured the new flags.
    /// # C: O(N)
    /// # Lk: matching stack RTNL held by `rtnl`
    pub fn set_iface_carrier_in_ns(&self, rtnl: &crate::RtnlGuard<'_>, id: NetIfaceId, ns: u64,
                                   up: bool) -> Option<bool> {
        if !self.guard_matches(rtnl) { return None; }
        let g = self.inner.lock();
        let entry = g.entries.iter().find(|entry| entry.id == id && entry.ns == ns
            && entry.ingress.live() && entry.ingress.ready())?;
        let was = entry.carrier.swap(up, Ordering::AcqRel);
        Some(was != up)
    }

    /// Look up a registered iface by id, restricted to the given
    /// net namespace. `ns=0` is the init NS.
    /// # C: O(N)
    pub fn lookup_in_ns(&self, id: NetIfaceId, ns: u64) -> Option<Arc<dyn NetDev>> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns
            && e.ingress.live() && e.ingress.ready())
            .map(|e| Arc::clone(&e.dev))
    }

    /// Canonical IPv4 neighbour cache for one live interface generation.
    /// # C: O(N)
    pub fn arp_cache_in_ns(&self, id: NetIfaceId, ns: u64) -> Option<Arc<crate::arp::ArpCache>> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns
            && e.ingress.live() && e.ingress.ready()).map(|e| e.arp.clone())
    }

    /// The IPv6 half of one interface's neighbour table. One state machine
    /// serves both families, so this is the type the IPv4 half uses.
    /// # C: O(N)
    pub fn ndp_cache_for(&self, id: NetIfaceId)
        -> Option<Arc<crate::neigh::NeighCache<crate::Ipv6Addr>>>
    {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ingress.live()).map(|e| e.ndp.clone())
    }

    /// Resolve one Linux-visible interface index in its owning namespace.
    /// Internal device ownership always continues to use `NetIfaceId`.
    /// # C: O(N)
    pub fn lookup_ifindex_in_ns(&self, ifindex: u32, ns: u64)
        -> Option<(NetIfaceId, Arc<dyn NetDev>)> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.ifindex == ifindex && e.ns == ns
            && e.ingress.live() && e.ingress.ready())
            .map(|e| (e.id, Arc::clone(&e.dev)))
    }

    /// Return the Linux-visible interface index for an internal handle in
    /// the supplied network namespace. # C: O(N)
    pub fn ifindex_in_ns(&self, id: NetIfaceId, ns: u64) -> Option<u32> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns
            && e.ingress.live() && e.ingress.ready()).map(|e| e.ifindex)
    }

    /// Return an interface's current namespace-local index without requiring
    /// the caller to know its namespace. Control notifications retain an
    /// interface generation across namespace teardown and use this only as a
    /// post-teardown fallback. # C: O(N)
    pub fn ifindex(&self, id: NetIfaceId) -> Option<u32> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ingress.live())
            .map(|e| e.ifindex)
    }

    /// Return the canonical registry-owned name for one live interface. # C: O(N)
    pub fn name_in_ns(&self, id: NetIfaceId, ns: u64) -> Option<String> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns
            && e.ingress.live() && e.ingress.ready()).map(|e| e.name.clone())
    }

    /// Network namespace that canonically owns `id`. # C: O(N)
    pub fn namespace(&self, id: NetIfaceId) -> Option<u64> {
        let g = self.inner.lock();
        g.entries.iter().find(|entry| entry.id == id
            && entry.ingress.live() && entry.ingress.ready())
            .map(|entry| entry.ns)
    }

    #[cfg(test)]
    pub(crate) fn registered(&self, id: NetIfaceId) -> bool {
        self.inner.lock().entries.iter().any(|entry| entry.id == id)
    }

    /// Interface-owned multicast transition ordering in one namespace. # C: O(N)
    pub(crate) fn mcast_report_in_ns(&self, id: NetIfaceId, ns: u64)
        -> Option<Arc<McastReportState>> {
        let g = self.inner.lock();
        g.entries.iter().find(|entry| entry.id == id && entry.ns == ns
            && entry.ingress.live() && entry.ingress.ready())
            .map(|entry| entry.mcast_report.clone())
    }

    /// Init-NS lookup compatibility shim — pre-F101 callers default
    /// to ns=0 until they're updated to pass the calling task's NS.
    /// # C: O(N)
    pub fn lookup(&self, id: NetIfaceId) -> Option<Arc<dyn NetDev>> {
        self.lookup_in_ns(id, 0)
    }

    /// Look up by stable name within the given namespace.
    /// # C: O(N)
    pub fn lookup_name_in_ns(&self, name: &str, ns: u64) -> Option<(NetIfaceId, Arc<dyn NetDev>)> {
        let g = self.inner.lock();
        g.entries.iter()
            .find(|e| e.name == name && e.ns == ns
                && e.ingress.live() && e.ingress.ready())
            .map(|e| (e.id, Arc::clone(&e.dev)))
    }

    /// Init-NS name lookup compatibility shim.
    /// # C: O(N)
    pub fn lookup_name(&self, name: &str) -> Option<(NetIfaceId, Arc<dyn NetDev>)> {
        self.lookup_name_in_ns(name, 0)
    }
}

/// The running task's network namespace id (CLONE_NEWNET; 0 = init ns).
/// rtnetlink dumps filter by this so a container's `ip` only sees its own
/// ifaces/addrs/routes (Linux `sock_net(skb->sk)`). Host/test builds have no
/// scheduler → init ns (0). # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn current_net_ns() -> u64 {
    sched::live::current().and_then(|task| task.network_namespace_id())
        .map(network_namespace::NetworkNamespaceId::as_u64).unwrap_or(0)
}
/// Host/test stub: init ns. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn current_net_ns() -> u64 { 0 }

#[cfg(test)]
#[path = "netdev_tests.rs"]
mod tests;
