// Module manifest: ingress owns generation admission; tx_dispatch owns
// queued/direct hardware serialization; registration owns publication;
// packet_filter/packet_metadata own driver packet contracts.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU8, AtomicU32, Ordering};

use sync::{Spinlock, Socket as SocketLockClass};

use crate::addr::NetIfaceId;

#[path = "netdev/ingress.rs"]
mod ingress;
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
pub use ingress::{EgressLease, IngressLease};
pub(crate) use ingress::ControlEffectLease;
pub(crate) use ingress::{IfaceTeardown, IfaceUnregisterClaim};
use ingress::IngressGate;
pub use registration::IfaceRegistration;
pub use packet_filter::{PACKET_LINK_ADDRESS_MAX, PacketLinkAddress, PacketRxMode};
pub use packet_metadata::{PacketChecksum, PacketRxMetadata, PacketVirtioMetadata, PacketVlan};
pub(crate) use packet_filter::PacketDeviceFilter;
pub use error::{NetError, NetResult};
pub use device::NetDev;

type NetdevRemoveHook = fn(&str);
static NETDEV_REMOVE_HOOK: Spinlock<Option<NetdevRemoveHook>, SocketLockClass> = Spinlock::new(None);

/// Install the netdev remove hook used by sysfs to drop stale class dentries. # C: O(1)
pub fn set_remove_hook(f: NetdevRemoveHook) { *NETDEV_REMOVE_HOOK.lock() = Some(f); }

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
    pub name:  String,
    pub mtu:   u32,
    pub flags: u32,
    pub stats: NetStats,
}

/// Linux `/sys/class/net/<if>/statistics/` field names, in the order
/// `net/core/net-sysfs.c` registers them. Every name resolves to a
/// u64 decimal. `sysfs` reads this for both `readdir` and per-field
/// `lookup`. Names match Linux exactly.
pub const STAT_FIELDS: &[&str] = &[
    "rx_packets", "tx_packets", "rx_bytes", "tx_bytes",
    "rx_errors", "tx_errors", "rx_dropped", "tx_dropped",
    "multicast", "collisions",
    "rx_length_errors", "rx_over_errors", "rx_crc_errors",
    "rx_frame_errors", "rx_fifo_errors", "rx_missed_errors",
    "tx_aborted_errors", "tx_carrier_errors", "tx_fifo_errors",
    "tx_heartbeat_errors", "tx_window_errors",
    "rx_compressed", "tx_compressed", "rx_nohandler",
];

impl NetStats {
    /// Value of one `/sys/class/net/<if>/statistics/` field. Returns
    /// `None` for a name not in `STAT_FIELDS` (ENOENT). Fields with no
    /// backing counter yet (error-detail / compressed / multicast /
    /// collisions) report 0 — matching a NIC with no such events, the
    /// real Linux value for those, not a fabrication.
    /// # C: O(1)
    pub fn field(&self, name: &str) -> Option<u64> {
        Some(match name {
            "rx_packets" => self.rx_packets,
            "tx_packets" => self.tx_packets,
            "rx_bytes"   => self.rx_bytes,
            "tx_bytes"   => self.tx_bytes,
            "rx_errors"  => self.rx_errors,
            "tx_errors"  => self.tx_errors,
            "rx_dropped" => self.rx_dropped,
            "tx_dropped" => self.tx_dropped,
            n if STAT_FIELDS.contains(&n) => 0,
            _ => return None,
        })
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NamespaceDropAction { Destroy, MoveToInitial }

/// Registered iface — the registry assigns the `NetIfaceId`.
pub(crate) struct McastReportState {
    state: AtomicU8,
}

impl McastReportState {
    const LIVE: u8 = 1 << 0;
    const V4: u8 = 1 << 1;
    const V6: u8 = 1 << 2;

    fn new() -> Self { Self { state: AtomicU8::new(Self::LIVE) } }
    pub(crate) fn live(&self) -> bool {
        self.state.load(Ordering::Acquire) & Self::LIVE != 0
    }
    pub(crate) fn retire(&self) {
        self.state.fetch_and(!Self::LIVE, Ordering::AcqRel);
        while self.state.load(Ordering::Acquire) & (Self::V4 | Self::V6) != 0 {
            core::hint::spin_loop();
        }
    }
    pub(crate) fn try_v4(&self) -> bool { self.try_drive(Self::V4) }
    pub(crate) fn release_v4(&self) { self.state.fetch_and(!Self::V4, Ordering::Release); }
    pub(crate) fn try_v6(&self) -> bool { self.try_drive(Self::V6) }
    pub(crate) fn release_v6(&self) { self.state.fetch_and(!Self::V6, Ordering::Release); }

    fn try_drive(&self, bit: u8) -> bool {
        let mut state = self.state.load(Ordering::Acquire);
        loop {
            if state & Self::LIVE == 0 || state & bit != 0 { return false; }
            match self.state.compare_exchange_weak(state, state | bit,
                Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(next) => state = next,
            }
        }
    }
}

pub struct IfaceEntry {
    pub id:   NetIfaceId,
    /// Network namespace id (CLONE_NEWNET). 0 = init NS. Tasks see
    /// only entries matching their own net_ns.
    pub ns:   u64,
    pub dev:  Arc<dyn NetDev>,
    /// Canonical Linux interface name. Device identity and registry naming
    /// are separate: drivers provide the initial name, while the registry
    /// owns namespace-scoped rename semantics.
    pub name: String,
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
    ingress: Arc<IngressGate>,
}

/// Process-global iface table. `register_netdev` pushes; `iface`
/// looks up by id. `up_ifaces` snapshots for boot-trace dumps.
pub struct IfaceRegistry {
    pub(crate) inner: Spinlock<RegistryInner, SocketLockClass>,
}

pub(crate) struct RegistryInner {
    next: u32,
    pub(crate) entries: Vec<IfaceEntry>,
}

impl IfaceRegistry {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(RegistryInner { next: 1, entries: Vec::new() }) }
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
        let (dev, old_name) = {
            let mut g = self.inner.lock();
            let pos = g.entries.iter().position(|entry| entry.id == id
                && Arc::ptr_eq(&entry.ingress, &gate) && gate.drained())?;
            let entry = g.entries.remove(pos);
            (entry.dev, entry.name)
        };
        let hook = *NETDEV_REMOVE_HOOK.lock();
        if let Some(f) = hook { f(&old_name); }
        gate.finish();
        Some(dev)
    }

    /// Current IFF_* flags for `id` (init NS). # C: O(N)
    pub fn iface_flags(&self, id: NetIfaceId) -> Option<u32> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ingress.live() && e.ingress.ready())
            .map(|e| e.flags.load(Ordering::Acquire))
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
        let rx_change = change & (iff::IFF_PROMISC | iff::IFF_ALLMULTI);
        let (notify, next) = {
            let g = self.inner.lock();
            let e = g.entries.iter().find(|e| e.id == id && e.ns == ns
                && e.ingress.live() && e.ingress.ready())?;
            let cur = e.flags.load(Ordering::Acquire);
            let mut next = (cur & !change) | (new & change);
            let notify = if rx_change != 0 {
                let mode = e.packet_filter.update_admin(new, rx_change);
                if mode.promiscuous { next |= iff::IFF_PROMISC; }
                else { next &= !iff::IFF_PROMISC; }
                if mode.all_multicast { next |= iff::IFF_ALLMULTI; }
                else { next &= !iff::IFF_ALLMULTI; }
                Some((e.dev.clone(), mode))
            } else { None };
            e.flags.store(next, Ordering::Release);
            (notify, next)
        };
        if let Some((dev, mode)) = notify { dev.packet_rx_mode_changed(&mode); }
        Some(next)
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

    /// Interface-owned multicast transition ordering. # C: O(N)
    pub(crate) fn mcast_report(&self, id: NetIfaceId)
        -> Option<Arc<McastReportState>> {
        let g = self.inner.lock();
        g.entries.iter().find(|entry| entry.id == id
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
