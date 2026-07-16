extern crate alloc;

use alloc::vec::Vec;

use super::{AF_INET, RT_SCOPE_HOST};

/// Linux `struct ifa_cacheinfo`: preferred/valid lifetimes and timestamps.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IfaCacheInfo {
    pub preferred: u32,
    pub valid:     u32,
    pub cstamp:    u32,
    pub tstamp:    u32,
}

impl IfaCacheInfo {
    pub const SIZE: usize = 16;
    pub const PERMANENT: Self = Self {
        preferred: u32::MAX,
        valid:     u32::MAX,
        cstamp:    0,
        tstamp:    0,
    };

    /// # C: O(1)
    pub fn write_to(&self, buf: &mut [u8]) {
        buf[0..4].copy_from_slice(&self.preferred.to_ne_bytes());
        buf[4..8].copy_from_slice(&self.valid.to_ne_bytes());
        buf[8..12].copy_from_slice(&self.cstamp.to_ne_bytes());
        buf[12..16].copy_from_slice(&self.tstamp.to_ne_bytes());
    }
}

/// One entry in the kernel's iface->address table.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct IfaceAddr {
    pub ns:        u64,
    pub ifindex:   u32,
    pub family:    u8,
    pub addr:      [u8; 4],
    pub peer:      Option<[u8; 4]>,
    pub prefixlen: u8,
    pub scope:     u8,
    pub flags:     u32,
    pub cacheinfo: IfaCacheInfo,
}

/// # C: O(1)
pub fn cache_to_net(row: IfaCacheInfo) -> net::iface_addr::Ipv4AddrCacheInfo {
    net::iface_addr::Ipv4AddrCacheInfo {
        preferred: row.preferred,
        valid: row.valid,
        cstamp: row.cstamp,
        tstamp: row.tstamp,
    }
}

fn cache_from_net(row: net::iface_addr::Ipv4AddrCacheInfo) -> IfaCacheInfo {
    IfaCacheInfo {
        preferred: row.preferred,
        valid: row.valid,
        cstamp: row.cstamp,
        tstamp: row.tstamp,
    }
}

fn addr_to_net(row: IfaceAddr) -> net::iface_addr::Ipv4IfaceAddr {
    net::iface_addr::Ipv4IfaceAddr {
        ns: row.ns,
        iface: net::NetIfaceId::from_raw(row.ifindex),
        addr: net::Ipv4Addr::from_u32(u32::from_be_bytes(row.addr)),
        peer: row.peer.map(|peer| net::Ipv4Addr::from_u32(u32::from_be_bytes(peer))),
        prefixlen: row.prefixlen,
        mask: if row.prefixlen == 0 { 0 } else { !0u32 << (32 - row.prefixlen.min(32)) },
        broadcast: None,
        scope: row.scope,
        flags: row.flags,
        cacheinfo: cache_to_net(row.cacheinfo),
    }
}

fn addr_from_net(row: net::iface_addr::Ipv4IfaceAddr) -> IfaceAddr {
    IfaceAddr {
        ns: row.ns,
        ifindex: row.iface.raw(),
        family: AF_INET,
        addr: row.addr.octets(),
        peer: row.peer.map(net::Ipv4Addr::octets),
        prefixlen: row.prefixlen,
        scope: row.scope,
        flags: row.flags,
        cacheinfo: cache_from_net(row.cacheinfo),
    }
}

/// Insert or replace by ns+ifindex+addr+prefixlen. # C: O(N)
pub fn addr_insert(row: IfaceAddr) {
    net::iface_addr::insert(addr_to_net(row));
}

/// Remove rows matching ns+ifindex+addr+prefixlen. # C: O(N)
pub fn addr_remove(ns: u64, ifindex: u32, addr: [u8; 4], prefixlen: u8) -> usize {
    net::iface_addr::remove(
        ns,
        net::NetIfaceId::from_raw(ifindex),
        net::Ipv4Addr::from_u32(u32::from_be_bytes(addr)),
        prefixlen,
    )
}

/// Snapshot address rows in network namespace `ns`. # C: O(N)
pub fn addr_snapshot_ns(ns: u64) -> Vec<IfaceAddr> {
    net::iface_addr::snapshot_ns(ns).into_iter().map(addr_from_net).collect()
}

/// Full snapshot of all address rows. # C: O(N)
pub fn addr_snapshot() -> Vec<IfaceAddr> {
    net::iface_addr::snapshot().into_iter().map(addr_from_net).collect()
}

/// Boot-time seed of the default v1 addresses. # C: O(1)
pub fn seed_defaults(eth0_ifindex: Option<u32>, lo_ifindex: Option<u32>) {
    if let Some(idx) = lo_ifindex {
        addr_insert(IfaceAddr {
            ns: 0,
            ifindex: idx,
            family: AF_INET,
            addr: [127, 0, 0, 1],
            peer: None,
            prefixlen: 8,
            scope: RT_SCOPE_HOST,
            flags: net::iface_addr::IFA_F_PERMANENT,
            cacheinfo: IfaCacheInfo::PERMANENT,
        });
    }
    let _ = eth0_ifindex;
}
