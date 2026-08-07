extern crate alloc;

use alloc::vec::Vec;

use super::RT_SCOPE_HOST;

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

/// # C: O(1)
pub fn cache_to_net(row: IfaCacheInfo) -> net::iface_addr::Ipv4AddrCacheInfo {
    net::iface_addr::Ipv4AddrCacheInfo {
        preferred: row.preferred,
        valid: row.valid,
        cstamp: row.cstamp,
        tstamp: row.tstamp,
    }
}

pub(crate) fn cache_from_net(row: net::iface_addr::Ipv4AddrCacheInfo) -> IfaCacheInfo {
    IfaCacheInfo {
        preferred: row.preferred,
        valid: row.valid,
        cstamp: row.cstamp,
        tstamp: row.tstamp,
    }
}

/// Insert or replace by ns+ifindex+addr+prefixlen. # C: O(N)
pub fn addr_insert(row: net::iface_addr::Ipv4IfaceAddr) {
    net::iface_addr::insert(row);
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
pub fn addr_snapshot_ns(ns: u64) -> Vec<net::iface_addr::Ipv4IfaceAddr> {
    net::iface_addr::snapshot_ns(ns)
}

/// Full snapshot of all address rows. # C: O(N)
pub fn addr_snapshot() -> Vec<net::iface_addr::Ipv4IfaceAddr> {
    net::iface_addr::snapshot()
}

/// Boot-time seed of the default v1 addresses. # C: O(1)
pub fn seed_defaults(eth0_ifindex: Option<u32>, lo_ifindex: Option<u32>) {
    if let Some(idx) = lo_ifindex {
        addr_insert(net::iface_addr::Ipv4IfaceAddr {
            ns: 0,
            iface: net::NetIfaceId::from_raw(idx),
            addr: net::Ipv4Addr::new(127, 0, 0, 1),
            peer: None,
            mask: 0xff00_0000,
            broadcast: None,
            prefixlen: 8,
            scope: RT_SCOPE_HOST,
            flags: net::iface_addr::IFA_F_PERMANENT,
            proto: net::iface_addr::IFAPROT_KERNEL_LO,
            rt_priority: 0,
            cacheinfo: net::iface_addr::Ipv4AddrCacheInfo::PERMANENT,
        });
    }
    let _ = eth0_ifindex;
}
