extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sync::{Spinlock, Socket as LockClass};

use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};

pub const MCAST_EXCLUDE: u32 = 0;
pub const MCAST_INCLUDE: u32 = 1;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FilterMode { Exclude, Include }

impl FilterMode {
    /// # C: O(1)
    pub fn from_u32(v: u32) -> NetResult<Self> {
        match v {
            MCAST_EXCLUDE => Ok(Self::Exclude),
            MCAST_INCLUDE => Ok(Self::Include),
            _ => Err(NetError::Einval),
        }
    }

    /// # C: O(1)
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Exclude => MCAST_EXCLUDE,
            Self::Include => MCAST_INCLUDE,
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct Key {
    port: u16,
    iface: u32,
    group: Ipv4Addr,
}

#[derive(Clone, Debug)]
pub struct SourceFilter {
    pub mode: FilterMode,
    pub sources: Vec<Ipv4Addr>,
}

static FILTERS: Spinlock<BTreeMap<Key, SourceFilter>, LockClass> = Spinlock::new(BTreeMap::new());

fn key(port: u16, iface: NetIfaceId, group: Ipv4Addr) -> Key {
    Key { port, iface: iface.raw(), group }
}

fn uniq_push(v: &mut Vec<Ipv4Addr>, src: Ipv4Addr) {
    if !v.contains(&src) { v.push(src); }
}

/// # C: O(N log N)
pub fn set(port: u16, iface: NetIfaceId, group: Ipv4Addr, mode: FilterMode, sources: &[Ipv4Addr]) {
    let mut dedup = Vec::new();
    for s in sources { uniq_push(&mut dedup, *s); }
    FILTERS.lock().insert(key(port, iface, group), SourceFilter { mode, sources: dedup });
}

/// # C: O(log N)
pub fn get(port: u16, iface: NetIfaceId, group: Ipv4Addr) -> SourceFilter {
    FILTERS.lock().get(&key(port, iface, group)).cloned()
        .unwrap_or(SourceFilter { mode: FilterMode::Exclude, sources: Vec::new() })
}

/// # C: O(log N + S)
pub fn add_source(port: u16, iface: NetIfaceId, group: Ipv4Addr, src: Ipv4Addr) {
    let mut g = FILTERS.lock();
    let f = g.entry(key(port, iface, group)).or_insert(SourceFilter {
        mode: FilterMode::Include,
        sources: Vec::new(),
    });
    f.mode = FilterMode::Include;
    uniq_push(&mut f.sources, src);
}

/// # C: O(log N + S)
pub fn drop_source(port: u16, iface: NetIfaceId, group: Ipv4Addr, src: Ipv4Addr) {
    let mut g = FILTERS.lock();
    if let Some(f) = g.get_mut(&key(port, iface, group)) {
        f.sources.retain(|s| *s != src);
        if f.sources.is_empty() { g.remove(&key(port, iface, group)); }
    }
}

/// # C: O(log N + S)
pub fn block_source(port: u16, iface: NetIfaceId, group: Ipv4Addr, src: Ipv4Addr) {
    let mut g = FILTERS.lock();
    let f = g.entry(key(port, iface, group)).or_insert(SourceFilter {
        mode: FilterMode::Exclude,
        sources: Vec::new(),
    });
    f.mode = FilterMode::Exclude;
    uniq_push(&mut f.sources, src);
}

/// # C: O(log N + S)
pub fn unblock_source(port: u16, iface: NetIfaceId, group: Ipv4Addr, src: Ipv4Addr) {
    let mut g = FILTERS.lock();
    if let Some(f) = g.get_mut(&key(port, iface, group)) {
        f.sources.retain(|s| *s != src);
        if f.sources.is_empty() { g.remove(&key(port, iface, group)); }
    }
}

/// # C: O(log N)
pub fn clear_group(port: u16, iface: NetIfaceId, group: Ipv4Addr) {
    FILTERS.lock().remove(&key(port, iface, group));
}

/// # C: O(N)
pub fn clear_port(port: u16) {
    FILTERS.lock().retain(|k, _| k.port != port);
}

/// # C: O(log N + S)
pub fn accept(port: u16, iface: NetIfaceId, group: Ipv4Addr, src: Ipv4Addr) -> bool {
    let f = get(port, iface, group);
    let listed = f.sources.contains(&src);
    match f.mode {
        FilterMode::Include => listed,
        FilterMode::Exclude => !listed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn include_and_exclude_modes_gate_sources() {
        let iface = NetIfaceId::from_raw(7001);
        let group = Ipv4Addr::new(239, 1, 2, 3);
        let allowed = Ipv4Addr::new(10, 0, 0, 1);
        let denied = Ipv4Addr::new(10, 0, 0, 2);

        set(47001, iface, group, FilterMode::Include, &[allowed]);
        assert!(accept(47001, iface, group, allowed));
        assert!(!accept(47001, iface, group, denied));

        block_source(47002, iface, group, denied);
        assert!(accept(47002, iface, group, allowed));
        assert!(!accept(47002, iface, group, denied));
    }
}
