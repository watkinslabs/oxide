// `NetDev` trait per `25§3` + iface registry. Drivers (loopback,
// virtio-net, etc.) implement `NetDev`; the kernel's network init
// path calls `register_netdev` once per device. Everything above
// the driver layer references devices by `NetIfaceId`.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, Socket as SocketLockClass};

use crate::addr::{MacAddr, NetIfaceId};
use crate::pkt::{Pkt, DEFAULT_HEADROOM};

/// `IFF_*` interface flags per `linux/if.h`. Real, mutable per-iface
/// admin/operational state — RTM_SETLINK flips them, RTM_GETLINK reports
/// them (no hardcoded reply-time values). # C: O(1)
pub mod iff {
    pub const IFF_UP:        u32 = 0x0001;
    pub const IFF_BROADCAST: u32 = 0x0002;
    pub const IFF_LOOPBACK:  u32 = 0x0008;
    pub const IFF_RUNNING:   u32 = 0x0040;
    pub const IFF_MULTICAST: u32 = 0x1000;
}

/// `25§3` `KR<()>` analogue for the net subsystem.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum NetError {
    Eagain,
    Eio,
    Einval,
    Enobufs,
    Enomem,
    Eaddrnotavail,
    Eaddrinuse,
    Enodev,
    Enetunreach,
    Eafnosupport,
    Enotconn,
    Erange,
    Econnrefused,
    Enoent,
    /// F168: blocking op interrupted by a signal (EINTR).
    Eintr,
}

pub type NetResult<T> = core::result::Result<T, NetError>;

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

/// `25§3` driver trait.
pub trait NetDev: Send + Sync {
    /// Stable interface name (`lo`, `eth0`, …).
    fn name(&self) -> &str;
    /// Hardware MAC. Loopback returns ZERO.
    fn mac(&self)  -> MacAddr;
    /// Maximum L2 payload size in bytes (1500 default; 65535 for lo).
    fn mtu(&self)  -> u32;
    /// Hand a packet to the device for transmit. May complete
    /// synchronously (loopback / hosted tests) or schedule a
    /// driver-IRQ tx-completion callback (real NICs); v1 hosted
    /// surface is sync.
    fn xmit(&self, pkt: Pkt) -> NetResult<()>;
    /// F135: transmit a complete L2 frame verbatim (caller has
    /// already prepended its own Ethernet header). AF_PACKET
    /// SOCK_RAW sendto and bpf write() take this path. Default
    /// re-wraps as a Pkt and falls back to `xmit`, which is wrong
    /// for drivers that prepend their own header — those must
    /// override.
    /// # C: O(len)
    fn xmit_raw(&self, frame: &[u8]) -> NetResult<()> {
        let mut pkt = Pkt::new_with_headroom(DEFAULT_HEADROOM, frame.len());
        let slot = pkt.put(frame.len()).map_err(|_| NetError::Erange)?;
        slot.copy_from_slice(frame);
        self.xmit(pkt)
    }
    /// Snapshot the per-iface running counters. Default returns
    /// zeros for devices that don't track them yet.
    /// # C: O(1)
    fn stats(&self) -> NetStats { NetStats::default() }
}

/// Registered iface — the registry assigns the `NetIfaceId`.
pub struct IfaceEntry {
    pub id:   NetIfaceId,
    /// Network namespace id (CLONE_NEWNET). 0 = init NS. Tasks see
    /// only entries matching their own net_ns.
    pub ns:   u64,
    pub dev:  Arc<dyn NetDev>,
    /// Real, mutable IFF_* flags. Set at registration from the device
    /// kind; mutated by RTM_SETLINK; read by RTM_GETLINK. Not a
    /// reply-time fabrication.
    pub flags: AtomicU32,
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

    /// Register `dev` in the init namespace (ns=0). For per-NS
    /// registration use `register_in_ns`.
    /// # C: O(1)
    pub fn register(&self, dev: Arc<dyn NetDev>) -> NetIfaceId {
        self.register_in_ns(dev, 0)
    }

    /// Register `dev` in the given net namespace.
    /// # C: O(1)
    pub fn register_in_ns(&self, dev: Arc<dyn NetDev>, ns: u64) -> NetIfaceId {
        let mut g = self.inner.lock();
        let id = NetIfaceId::from_raw(g.next);
        g.next += 1;
        // Initial flags per device kind. lo: loopback, up, running. Other
        // devices (virtio-net etc.): broadcast+multicast capable, up+running
        // (the kernel registers them operational). These are real and
        // RTM_SETLINK-mutable, not hardcoded at reply time.
        let init_flags = if dev.name() == "lo" {
            iff::IFF_UP | iff::IFF_RUNNING | iff::IFF_LOOPBACK
        } else {
            iff::IFF_UP | iff::IFF_RUNNING | iff::IFF_BROADCAST | iff::IFF_MULTICAST
        };
        g.entries.push(IfaceEntry { id, ns, dev, flags: AtomicU32::new(init_flags) });
        id
    }

    /// Unregister an interface from its namespace. Returns the removed
    /// device so callers that need to quiesce it can still hold a reference.
    /// # C: O(N)
    pub fn unregister(&self, id: NetIfaceId) -> Option<Arc<dyn NetDev>> {
        let mut g = self.inner.lock();
        let pos = g.entries.iter().position(|e| e.id == id)?;
        Some(g.entries.remove(pos).dev)
    }

    /// Current IFF_* flags for `id` (init NS). # C: O(N)
    pub fn iface_flags(&self, id: NetIfaceId) -> Option<u32> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id).map(|e| e.flags.load(Ordering::Acquire))
    }

    /// Apply an RTM_SETLINK flag change: `flags = (flags & !change) |
    /// (new & change)`. Returns the post-change flags, or None if no
    /// such iface. Linux ifinfomsg semantics. # C: O(N)
    pub fn set_iface_flags(&self, id: NetIfaceId, new: u32, change: u32) -> Option<u32> {
        let g = self.inner.lock();
        let e = g.entries.iter().find(|e| e.id == id)?;
        let cur = e.flags.load(Ordering::Acquire);
        let next = (cur & !change) | (new & change);
        e.flags.store(next, Ordering::Release);
        Some(next)
    }

    /// Look up a registered iface by id, restricted to the given
    /// net namespace. `ns=0` is the init NS.
    /// # C: O(N)
    pub fn lookup_in_ns(&self, id: NetIfaceId, ns: u64) -> Option<Arc<dyn NetDev>> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id && e.ns == ns).map(|e| Arc::clone(&e.dev))
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
            .find(|e| e.dev.name() == name && e.ns == ns)
            .map(|e| (e.id, Arc::clone(&e.dev)))
    }

    /// Init-NS name lookup compatibility shim.
    /// # C: O(N)
    pub fn lookup_name(&self, name: &str) -> Option<(NetIfaceId, Arc<dyn NetDev>)> {
        self.lookup_name_in_ns(name, 0)
    }

    /// Snapshot (id, name, mtu) triples in the given namespace.
    /// # C: O(N)
    pub fn snapshot_in_ns(&self, ns: u64) -> Vec<(NetIfaceId, String, u32)> {
        let g = self.inner.lock();
        g.entries.iter()
            .filter(|e| e.ns == ns)
            .map(|e| (e.id, String::from(e.dev.name()), e.dev.mtu()))
            .collect()
    }

    /// Init-NS snapshot compatibility shim.
    /// # C: O(N)
    pub fn snapshot(&self) -> Vec<(NetIfaceId, String, u32)> {
        self.snapshot_in_ns(0)
    }

    /// Full-device snapshot (id, Arc<dyn NetDev>) for RTM_GETLINK dumps in
    /// network namespace `ns` (a netns sees only its own ifaces — Linux
    /// `for_each_netdev` over `net->dev_index_head`). # C: O(N)
    pub fn snapshot_devs_in_ns(&self, ns: u64) -> Vec<(NetIfaceId, Arc<dyn NetDev>)> {
        let g = self.inner.lock();
        g.entries.iter()
            .filter(|e| e.ns == ns)
            .map(|e| (e.id, e.dev.clone()))
            .collect()
    }

    /// Init-NS device snapshot (compat shim). # C: O(N)
    pub fn snapshot_devs(&self) -> Vec<(NetIfaceId, Arc<dyn NetDev>)> {
        self.snapshot_devs_in_ns(0)
    }
}

/// The running task's network namespace id (CLONE_NEWNET; 0 = init ns).
/// rtnetlink dumps filter by this so a container's `ip` only sees its own
/// ifaces/addrs/routes (Linux `sock_net(skb->sk)`). Host/test builds have no
/// scheduler → init ns (0). # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn current_net_ns() -> u64 {
    use core::sync::atomic::Ordering;
    sched::live::current().map(|t| t.net_ns.load(Ordering::Acquire)).unwrap_or(0)
}
/// Host/test stub: init ns. # C: O(1)
#[cfg(not(target_os = "oxide-kernel"))]
pub fn current_net_ns() -> u64 { 0 }

#[cfg(test)]
mod tests {
    use super::*;
    use sync::TaskList;

    struct DummyDev { name: &'static str, mtu: u32 }
    impl NetDev for DummyDev {
        fn name(&self) -> &str { self.name }
        fn mac(&self) -> MacAddr { MacAddr::ZERO }
        fn mtu(&self) -> u32 { self.mtu }
        fn xmit(&self, _pkt: Pkt) -> NetResult<()> { Ok(()) }
    }

    #[test]
    fn register_assigns_increasing_ids() {
        let r = IfaceRegistry::new();
        let a = r.register(Arc::new(DummyDev { name: "lo", mtu: 65535 }));
        let b = r.register(Arc::new(DummyDev { name: "eth0", mtu: 1500 }));
        assert_ne!(a, b);
        assert!(r.lookup(a).is_some());
        assert_eq!(r.lookup_name("lo").unwrap().0, a);
        assert_eq!(r.lookup_name("eth0").unwrap().0, b);
    }

    #[test]
    fn lookup_missing_returns_none() {
        let r = IfaceRegistry::new();
        assert!(r.lookup(NetIfaceId::from_raw(99)).is_none());
        assert!(r.lookup_name("nope").is_none());
    }

    #[test]
    fn snapshot_lists_all() {
        let r = IfaceRegistry::new();
        r.register(Arc::new(DummyDev { name: "lo", mtu: 65535 }));
        r.register(Arc::new(DummyDev { name: "eth0", mtu: 1500 }));
        let s = r.snapshot();
        assert_eq!(s.len(), 2);
        assert!(s.iter().any(|t| t.1 == "lo"));
        assert!(s.iter().any(|t| t.1 == "eth0"));
    }

    #[test]
    fn netstats_field_maps_known_counters() {
        let st = NetStats {
            rx_packets: 7, rx_bytes: 700, rx_errors: 1, rx_dropped: 2,
            tx_packets: 9, tx_bytes: 900, tx_errors: 4, tx_dropped: 3,
        };
        assert_eq!(st.field("rx_packets"), Some(7));
        assert_eq!(st.field("tx_packets"), Some(9));
        assert_eq!(st.field("rx_bytes"),   Some(700));
        assert_eq!(st.field("tx_bytes"),   Some(900));
        assert_eq!(st.field("rx_errors"),  Some(1));
        assert_eq!(st.field("tx_errors"),  Some(4));
        assert_eq!(st.field("rx_dropped"), Some(2));
        assert_eq!(st.field("tx_dropped"), Some(3));
    }

    #[test]
    fn netstats_field_unbacked_is_zero_known_is_none() {
        let st = NetStats::default();
        // In STAT_FIELDS but no backing counter → 0.
        assert_eq!(st.field("multicast"),      Some(0));
        assert_eq!(st.field("collisions"),     Some(0));
        assert_eq!(st.field("rx_over_errors"), Some(0));
        assert_eq!(st.field("rx_nohandler"),   Some(0));
        // Not a Linux statistics field → None (ENOENT).
        assert_eq!(st.field("bogus"), None);
        assert_eq!(st.field(""),      None);
    }

    #[test]
    fn stat_fields_match_linux_names_and_count() {
        // Sanity: the canonical first eight are present and ordered as
        // net-sysfs.c registers them.
        assert_eq!(STAT_FIELDS[0], "rx_packets");
        assert_eq!(STAT_FIELDS[1], "tx_packets");
        assert!(STAT_FIELDS.contains(&"collisions"));
        assert!(STAT_FIELDS.contains(&"rx_nohandler"));
        assert_eq!(STAT_FIELDS.len(), 24);
    }

    /// Suppress the unused-import lint when the cfg(test) block is
    /// the only consumer of TaskList (currently isn't, but the
    /// future Spinlock-class swap path will be).
    #[allow(dead_code)]
    fn _lock_class_marker() -> TaskList { TaskList }
}
