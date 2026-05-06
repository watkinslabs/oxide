// `NetDev` trait per `25§3` + iface registry. Drivers (loopback,
// virtio-net, etc.) implement `NetDev`; the kernel's network init
// path calls `register_netdev` once per device. Everything above
// the driver layer references devices by `NetIfaceId`.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::string::String;

use sync::{Spinlock, Socket as SocketLockClass};

use crate::addr::{MacAddr, NetIfaceId};
use crate::pkt::Pkt;

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
    Enetunreach,
    Eafnosupport,
    Enotconn,
    Erange,
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
    /// Snapshot the per-iface running counters. Default returns
    /// zeros for devices that don't track them yet.
    /// # C: O(1)
    fn stats(&self) -> NetStats { NetStats::default() }
}

/// Registered iface — the registry assigns the `NetIfaceId`.
pub struct IfaceEntry {
    pub id:   NetIfaceId,
    pub dev:  Arc<dyn NetDev>,
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

    /// Register `dev` and return its newly-assigned id. Names are
    /// not enforced unique here; caller is responsible for picking
    /// a stable name (per `25§3`'s `name()` contract).
    /// # C: O(1)
    pub fn register(&self, dev: Arc<dyn NetDev>) -> NetIfaceId {
        let mut g = self.inner.lock();
        let id = NetIfaceId::from_raw(g.next);
        g.next += 1;
        g.entries.push(IfaceEntry { id, dev });
        id
    }

    /// Look up a registered iface by id.
    /// # C: O(N)
    pub fn lookup(&self, id: NetIfaceId) -> Option<Arc<dyn NetDev>> {
        let g = self.inner.lock();
        g.entries.iter().find(|e| e.id == id).map(|e| Arc::clone(&e.dev))
    }

    /// Look up by stable name (`"lo"`, `"eth0"`, …).
    /// # C: O(N)
    pub fn lookup_name(&self, name: &str) -> Option<(NetIfaceId, Arc<dyn NetDev>)> {
        let g = self.inner.lock();
        g.entries.iter()
            .find(|e| e.dev.name() == name)
            .map(|e| (e.id, Arc::clone(&e.dev)))
    }

    /// Snapshot (id, name, mtu) triples for trace dumps.
    /// # C: O(N)
    pub fn snapshot(&self) -> Vec<(NetIfaceId, String, u32)> {
        let g = self.inner.lock();
        g.entries.iter()
            .map(|e| (e.id, String::from(e.dev.name()), e.dev.mtu()))
            .collect()
    }
}

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

    /// Suppress the unused-import lint when the cfg(test) block is
    /// the only consumer of TaskList (currently isn't, but the
    /// future Spinlock-class swap path will be).
    #[allow(dead_code)]
    fn _lock_class_marker() -> TaskList { TaskList }
}
