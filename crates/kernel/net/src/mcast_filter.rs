extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sync::{Spinlock, Socket as LockClass};

use crate::addr::{Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};
use crate::stack::NetStack;

#[path = "mcast_socket_gate.rs"]
mod socket_gate;
pub(crate) use socket_gate::{SocketMcastGate, SocketMcastLease};

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
        match self { Self::Exclude => MCAST_EXCLUDE, Self::Include => MCAST_INCLUDE }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SourceOp { Join, Leave, Block, Unblock }

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct V4Key { iface: u32, group: Ipv4Addr }

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct V6Key { iface: u32, group: Ipv6Addr }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceFilter { pub mode: FilterMode, pub sources: Vec<Ipv4Addr> }

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceFilter6 { pub mode: FilterMode, pub sources: Vec<Ipv6Addr> }

#[derive(Clone, Debug)]
struct V4Membership { net_ns: u64, generation: u64, report_src: Ipv4Addr, filter: SourceFilter }

#[derive(Clone, Debug)]
struct V6Membership { net_ns: u64, generation: u64, report_src: Ipv6Addr, filter: SourceFilter6 }

struct Inner {
    v4: BTreeMap<V4Key, V4Membership>,
    v6: BTreeMap<V6Key, V6Membership>,
}

fn publish_v4(inner: &mut Inner, stack: &NetStack, rtnl: &crate::RtnlGuard<'_>,
              report_owner: &network_namespace::NetworkNamespaceRef,
              net_ns: u64, owner: usize,
              iface: NetIfaceId, group: Ipv4Addr, report_src: Ipv4Addr,
              next: Option<V4Membership>) -> NetResult<Option<crate::mcast_state::V4ReportWork>> {
    let key = v4_key(iface, group);
    let expected_generation = next.as_ref().or_else(|| inner.v4.get(&key))
        .map(|membership| membership.generation).ok_or(NetError::Eaddrnotavail)?;
    let prior = match &next { Some(value) => inner.v4.insert(key, value.clone()),
        None => inner.v4.remove(&key) };
    let result = stack.set_ipv4_multicast_rtnl(rtnl, report_owner, net_ns, expected_generation, owner,
        iface, group, report_src,
        next.as_ref().map(|value| &value.filter));
    if let Err(error) = result {
        match prior { Some(value) => { inner.v4.insert(key, value); } None => { inner.v4.remove(&key); } }
        return Err(error);
    }
    result
}

fn publish_v6(inner: &mut Inner, stack: &NetStack, rtnl: &crate::RtnlGuard<'_>,
              report_owner: &network_namespace::NetworkNamespaceRef,
              net_ns: u64, owner: usize,
              iface: NetIfaceId, group: Ipv6Addr, report_src: Ipv6Addr,
              next: Option<V6Membership>) -> NetResult<Option<crate::mcast_state::V6ReportWork>> {
    let key = v6_key(iface, group);
    let expected_generation = next.as_ref().or_else(|| inner.v6.get(&key))
        .map(|membership| membership.generation).ok_or(NetError::Eaddrnotavail)?;
    let prior = match &next { Some(value) => inner.v6.insert(key, value.clone()),
        None => inner.v6.remove(&key) };
    let result = stack.set_ipv6_multicast_rtnl(rtnl, report_owner, net_ns, expected_generation, owner,
        iface, group, report_src,
        next.as_ref().map(|value| &value.filter));
    if let Err(error) = result {
        match prior { Some(value) => { inner.v6.insert(key, value); } None => { inner.v6.remove(&key); } }
        return Err(error);
    }
    result
}


/// Canonical socket-owned multicast state, valid before and after bind.
pub struct SocketMcast { inner: Spinlock<Inner, LockClass> }

impl SocketMcast {
    /// Empty socket multicast state. # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(Inner { v4: BTreeMap::new(), v6: BTreeMap::new() }) }
    }

    /// Join or leave one IPv4 group and its interface-level refcount atomically. # C: O(N)
    pub fn change_v4(&self, stack: &NetStack, iface: NetIfaceId, group: Ipv4Addr,
                     report_src: Ipv4Addr, join: bool) -> NetResult<()> {
        self.change_v4_in(stack, 0, iface, group, report_src, join)
    }

    /// Join or leave one IPv4 group in an explicit network namespace. # C: O(N)
    pub fn change_v4_in(&self, stack: &NetStack, net_ns: u64, iface: NetIfaceId,
                        group: Ipv4Addr, report_src: Ipv4Addr, join: bool) -> NetResult<()> {
        let key = v4_key(iface, group);
        let report_owner = namespace_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = stack.rtnl_lock();
        let mut inner = self.inner.lock();
        let work = if join {
            if inner.v4.contains_key(&key) { return Err(NetError::Eaddrinuse); }
            let generation = stack.multicast_generation_in(&rtnl, net_ns, iface)?;
            let membership = V4Membership {
                net_ns, generation, report_src,
                filter: SourceFilter { mode: FilterMode::Exclude, sources: Vec::new() },
            };
            publish_v4(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                report_src, Some(membership))?
        } else {
            let membership = inner.v4.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
            if membership.net_ns != net_ns { return Err(NetError::Enodev); }
            publish_v4(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                membership.report_src, None)?
        };
        drop(inner);
        drop(rtnl);
        stack.finish_v4_multicast(work);
        Ok(())
    }

    /// Apply one IPv4 source-membership operation. # C: O(N + S)
    pub fn source_v4(&self, stack: &NetStack, iface: NetIfaceId, group: Ipv4Addr,
                     report_src: Ipv4Addr, source: Ipv4Addr, op: SourceOp) -> NetResult<()> {
        self.source_v4_in(stack, 0, iface, group, report_src, source, op)
    }

    /// Apply one IPv4 source operation in an explicit network namespace. # C: O(N + S)
    pub fn source_v4_in(&self, stack: &NetStack, net_ns: u64, iface: NetIfaceId,
                        group: Ipv4Addr, report_src: Ipv4Addr, source: Ipv4Addr,
                        op: SourceOp) -> NetResult<()> {
        let key = v4_key(iface, group);
        let report_owner = namespace_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = stack.rtnl_lock();
        let mut inner = self.inner.lock();
        let work = match op {
            SourceOp::Join => {
                let mut next = match inner.v4.get(&key) {
                    Some(current) if current.filter.mode != FilterMode::Include => return Err(NetError::Eaddrinuse),
                    Some(current) => current.clone(),
                    None => V4Membership {
                        net_ns, generation: stack.multicast_generation_in(&rtnl, net_ns, iface)?,
                        report_src, filter: SourceFilter { mode: FilterMode::Include, sources: Vec::new() },
                    },
                };
                if next.net_ns != net_ns { return Err(NetError::Enodev); }
                if next.filter.sources.contains(&source) { return Err(NetError::Eaddrinuse); }
                next.filter.sources.push(source);
                publish_v4(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                    next.report_src, Some(next))?
            }
            SourceOp::Leave => {
                let mut next = inner.v4.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
                if next.net_ns != net_ns { return Err(NetError::Enodev); }
                if next.filter.mode != FilterMode::Include { return Err(NetError::Einval); }
                let index = next.filter.sources.iter().position(|addr| *addr == source)
                    .ok_or(NetError::Eaddrnotavail)?;
                next.filter.sources.remove(index);
                let report_src = next.report_src;
                let next = if next.filter.sources.is_empty() { None } else { Some(next) };
                publish_v4(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                    report_src, next)?
            }
            SourceOp::Block | SourceOp::Unblock => {
                let mut next = inner.v4.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
                if next.net_ns != net_ns { return Err(NetError::Enodev); }
                if next.filter.mode != FilterMode::Exclude { return Err(NetError::Einval); }
                let found = next.filter.sources.iter().position(|addr| *addr == source);
                if op == SourceOp::Block {
                    if found.is_some() { return Err(NetError::Eaddrinuse); }
                    next.filter.sources.push(source);
                } else {
                    let index = found.ok_or(NetError::Eaddrnotavail)?;
                    next.filter.sources.remove(index);
                }
                publish_v4(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                    next.report_src, Some(next))?
            }
        };
        drop(inner);
        drop(rtnl);
        stack.finish_v4_multicast(work);
        Ok(())
    }

    /// Replace one IPv4 full-state filter, joining the group if needed. # C: O(N + S)
    pub fn set_v4(&self, stack: &NetStack, iface: NetIfaceId, group: Ipv4Addr,
                  report_src: Ipv4Addr, mode: FilterMode, sources: &[Ipv4Addr]) -> NetResult<()> {
        self.set_v4_in(stack, 0, iface, group, report_src, mode, sources)
    }

    /// Replace one IPv4 filter in an explicit network namespace. # C: O(N + S)
    pub fn set_v4_in(&self, stack: &NetStack, net_ns: u64, iface: NetIfaceId,
                     group: Ipv4Addr, report_src: Ipv4Addr, mode: FilterMode,
                     sources: &[Ipv4Addr]) -> NetResult<()> {
        let key = v4_key(iface, group);
        let mut dedup = Vec::new();
        for source in sources { if !dedup.contains(source) { dedup.push(*source); } }
        let report_owner = namespace_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = stack.rtnl_lock();
        let mut inner = self.inner.lock();
        let work = if mode == FilterMode::Include && dedup.is_empty() {
            let membership = inner.v4.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
            if membership.net_ns != net_ns { return Err(NetError::Enodev); }
            publish_v4(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                membership.report_src, None)?
        } else {
            let generation = match inner.v4.get(&key) {
                Some(current) => current.generation,
                None => stack.multicast_generation_in(&rtnl, net_ns, iface)?,
            };
            let next = V4Membership {
                net_ns, generation,
                report_src: inner.v4.get(&key).map(|current| current.report_src).unwrap_or(report_src),
                filter: SourceFilter { mode, sources: dedup },
            };
            if inner.v4.get(&key).is_some_and(|current| current.net_ns != net_ns) {
                return Err(NetError::Enodev);
            }
            publish_v4(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                next.report_src, Some(next))?
        };
        drop(inner);
        drop(rtnl);
        stack.finish_v4_multicast(work);
        Ok(())
    }

    /// Join or leave one IPv6 group and interface-level refcount atomically. # C: O(N)
    pub fn change_v6(&self, stack: &NetStack, iface: NetIfaceId, group: Ipv6Addr,
                     report_src: Ipv6Addr, join: bool) -> NetResult<()> {
        self.change_v6_in(stack, 0, iface, group, report_src, join)
    }

    /// Join or leave one IPv6 group in an explicit network namespace. # C: O(N)
    pub fn change_v6_in(&self, stack: &NetStack, net_ns: u64, iface: NetIfaceId,
                        group: Ipv6Addr, report_src: Ipv6Addr, join: bool) -> NetResult<()> {
        let key = v6_key(iface, group);
        let report_owner = namespace_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = stack.rtnl_lock();
        let mut inner = self.inner.lock();
        let work = if join {
            if inner.v6.contains_key(&key) { return Err(NetError::Eaddrinuse); }
            let generation = stack.multicast_generation_in(&rtnl, net_ns, iface)?;
            let membership = V6Membership {
                net_ns, generation, report_src,
                filter: SourceFilter6 { mode: FilterMode::Exclude, sources: Vec::new() },
            };
            publish_v6(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                report_src, Some(membership))?
        } else {
            let membership = inner.v6.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
            if membership.net_ns != net_ns { return Err(NetError::Enodev); }
            publish_v6(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                membership.report_src, None)?
        };
        drop(inner); drop(rtnl);
        stack.finish_v6_multicast(work);
        Ok(())
    }

    /// Apply one IPv6 source-membership operation. # C: O(N + S)
    pub fn source_v6(&self, stack: &NetStack, iface: NetIfaceId, group: Ipv6Addr,
                     report_src: Ipv6Addr, source: Ipv6Addr, op: SourceOp) -> NetResult<()> {
        self.source_v6_in(stack, 0, iface, group, report_src, source, op)
    }

    /// Apply one IPv6 source operation in an explicit network namespace. # C: O(N + S)
    pub fn source_v6_in(&self, stack: &NetStack, net_ns: u64, iface: NetIfaceId,
                        group: Ipv6Addr, report_src: Ipv6Addr, source: Ipv6Addr,
                        op: SourceOp) -> NetResult<()> {
        let key = v6_key(iface, group);
        let report_owner = namespace_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = stack.rtnl_lock();
        let mut inner = self.inner.lock();
        let work = match op {
            SourceOp::Join => {
                let mut next = match inner.v6.get(&key) {
                    Some(current) if current.filter.mode != FilterMode::Include => return Err(NetError::Eaddrinuse),
                    Some(current) => current.clone(),
                    None => V6Membership {
                        net_ns, generation: stack.multicast_generation_in(&rtnl, net_ns, iface)?,
                        report_src, filter: SourceFilter6 { mode: FilterMode::Include, sources: Vec::new() },
                    },
                };
                if next.net_ns != net_ns { return Err(NetError::Enodev); }
                if next.filter.sources.contains(&source) { return Err(NetError::Eaddrinuse); }
                next.filter.sources.push(source);
                publish_v6(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                    next.report_src, Some(next))?
            }
            SourceOp::Leave => {
                let mut next = inner.v6.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
                if next.net_ns != net_ns { return Err(NetError::Enodev); }
                if next.filter.mode != FilterMode::Include { return Err(NetError::Einval); }
                let index = next.filter.sources.iter().position(|addr| *addr == source)
                    .ok_or(NetError::Eaddrnotavail)?;
                next.filter.sources.remove(index);
                let report_src = next.report_src;
                let next = if next.filter.sources.is_empty() { None } else { Some(next) };
                publish_v6(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                    report_src, next)?
            }
            SourceOp::Block | SourceOp::Unblock => {
                let mut next = inner.v6.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
                if next.net_ns != net_ns { return Err(NetError::Enodev); }
                if next.filter.mode != FilterMode::Exclude { return Err(NetError::Einval); }
                let found = next.filter.sources.iter().position(|addr| *addr == source);
                if op == SourceOp::Block {
                    if found.is_some() { return Err(NetError::Eaddrinuse); }
                    next.filter.sources.push(source);
                } else {
                    let index = found.ok_or(NetError::Eaddrnotavail)?;
                    next.filter.sources.remove(index);
                }
                publish_v6(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                    next.report_src, Some(next))?
            }
        };
        drop(inner); drop(rtnl);
        stack.finish_v6_multicast(work);
        Ok(())
    }

    /// Replace one IPv6 full-state filter, joining the group if needed. # C: O(N + S)
    pub fn set_v6(&self, stack: &NetStack, iface: NetIfaceId, group: Ipv6Addr,
                  report_src: Ipv6Addr, mode: FilterMode, sources: &[Ipv6Addr]) -> NetResult<()> {
        self.set_v6_in(stack, 0, iface, group, report_src, mode, sources)
    }

    /// Replace one IPv6 filter in an explicit network namespace. # C: O(N + S)
    pub fn set_v6_in(&self, stack: &NetStack, net_ns: u64, iface: NetIfaceId,
                     group: Ipv6Addr, report_src: Ipv6Addr, mode: FilterMode,
                     sources: &[Ipv6Addr]) -> NetResult<()> {
        let key = v6_key(iface, group);
        let mut dedup = Vec::new();
        for source in sources { if !dedup.contains(source) { dedup.push(*source); } }
        let report_owner = namespace_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = stack.rtnl_lock();
        let mut inner = self.inner.lock();
        let work = if mode == FilterMode::Include && dedup.is_empty() {
            let membership = inner.v6.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
            if membership.net_ns != net_ns { return Err(NetError::Enodev); }
            publish_v6(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                membership.report_src, None)?
        } else {
            if inner.v6.get(&key).is_some_and(|current| current.net_ns != net_ns) {
                return Err(NetError::Enodev);
            }
            let generation = match inner.v6.get(&key) {
                Some(current) => current.generation,
                None => stack.multicast_generation_in(&rtnl, net_ns, iface)?,
            };
            let next = V6Membership {
                net_ns, generation,
                report_src: inner.v6.get(&key).map(|current| current.report_src).unwrap_or(report_src),
                filter: SourceFilter6 { mode, sources: dedup },
            };
            publish_v6(&mut inner, stack, &rtnl, &report_owner, net_ns, self.owner_key(), iface, group,
                next.report_src, Some(next))?
        };
        drop(inner); drop(rtnl);
        stack.finish_v6_multicast(work);
        Ok(())
    }

    /// Test IPv4 membership and source filter in one lock snapshot. # C: O(log N + S)
    pub fn accept_v4(&self, iface: NetIfaceId, group: Ipv4Addr, src: Ipv4Addr) -> bool {
        let inner = self.inner.lock();
        let Some(membership) = inner.v4.get(&v4_key(iface, group)) else { return false };
        let listed = membership.filter.sources.contains(&src);
        match membership.filter.mode { FilterMode::Include => listed, FilterMode::Exclude => !listed }
    }

    /// Test exact IPv6 membership. # C: O(log N)
    pub fn accept_v6(&self, iface: NetIfaceId, group: Ipv6Addr, src: Ipv6Addr) -> bool {
        let inner = self.inner.lock();
        let Some(membership) = inner.v6.get(&v6_key(iface, group)) else { return false };
        let listed = membership.filter.sources.contains(&src);
        match membership.filter.mode { FilterMode::Include => listed, FilterMode::Exclude => !listed }
    }

    /// Snapshot one IPv4 source filter for getsockopt. # C: O(log N + S)
    pub fn get_v4(&self, iface: NetIfaceId, group: Ipv4Addr) -> NetResult<SourceFilter> {
        self.inner.lock().v4.get(&v4_key(iface, group)).map(|membership| membership.filter.clone())
            .ok_or(NetError::Eaddrnotavail)
    }

    /// Snapshot one IPv6 source filter for getsockopt. # C: O(log N + S)
    pub fn get_v6(&self, iface: NetIfaceId, group: Ipv6Addr) -> NetResult<SourceFilter6> {
        self.inner.lock().v6.get(&v6_key(iface, group)).map(|membership| membership.filter.clone())
            .ok_or(NetError::Eaddrnotavail)
    }

    /// No IPv4/IPv6 group membership at all — the RTNL-taking half of
    /// `release` would be a pure lock round-trip with nothing to publish.
    /// Lets a deferred-release caller (B1409 `sock_rtnl_defer`) skip
    /// queueing an `Arc<SocketMcast>` clone for the common case (a socket
    /// that never joined a multicast group). # C: O(1)
    pub fn is_empty(&self) -> bool {
        let inner = self.inner.lock();
        inner.v4.is_empty() && inner.v6.is_empty()
    }

    /// Release every socket membership while preserving other sockets' refs. # C: O(N groups)
    pub fn release(&self, stack: &NetStack) {
        let mut inner = self.inner.lock();
        let v4 = core::mem::take(&mut inner.v4);
        let v6 = core::mem::take(&mut inner.v6);
        drop(inner);
        let v4: Vec<_> = v4.into_iter().map(|(key, membership)| {
            let owner = namespace_owner(membership.net_ns); (key, membership, owner)
        }).collect();
        let v6: Vec<_> = v6.into_iter().map(|(key, membership)| {
            let owner = namespace_owner(membership.net_ns); (key, membership, owner)
        }).collect();
        let rtnl = stack.rtnl_lock();
        let mut v4_work = Vec::new();
        let mut v6_work = Vec::new();
        for (key, membership, owner) in v4 {
            v4_work.push(stack.release_ipv4_multicast_rtnl(&rtnl, owner.as_ref(), membership.net_ns,
                membership.generation, self.owner_key(), NetIfaceId::from_raw(key.iface), key.group));
        }
        for (key, membership, owner) in v6 {
            v6_work.push(stack.release_ipv6_multicast_rtnl(&rtnl, owner.as_ref(), membership.net_ns,
                membership.generation, self.owner_key(), NetIfaceId::from_raw(key.iface), key.group));
        }
        drop(rtnl);
        for work in v4_work { stack.finish_v4_multicast(work); }
        for work in v6_work { stack.finish_v6_multicast(work); }
    }

    fn owner_key(&self) -> usize { self as *const Self as usize }
}

impl Default for SocketMcast { fn default() -> Self { Self::new() } }

fn v4_key(iface: NetIfaceId, group: Ipv4Addr) -> V4Key { V4Key { iface: iface.raw(), group } }
fn v6_key(iface: NetIfaceId, group: Ipv6Addr) -> V6Key { V6Key { iface: iface.raw(), group } }

fn namespace_owner(net_ns: u64) -> Option<network_namespace::NetworkNamespaceRef> {
    if net_ns == 0 { Some(network_namespace::initial()) } else { network_namespace::lookup_u64(net_ns) }
}


/// Resolve IPv6 multicast interface precedence for an ipv6_mreq. # C: O(N routes)
pub fn resolve_v6_iface(stack: &NetStack, net_ns: u64, requested: u32, bound: u32,
                        mcast: u32, group: Ipv6Addr) -> NetResult<NetIfaceId> {
    let raw = if requested != 0 { requested } else if bound != 0 { bound } else if mcast != 0 { mcast }
        else { stack.routes6.lookup_in(net_ns, group).map(|route| route.iface.raw()).unwrap_or(0) };
    if raw == 0 { return Err(NetError::Enodev); }
    let iface = NetIfaceId::from_raw(raw);
    stack.ifaces.lookup_in_ns(iface, net_ns).map(|_| iface).ok_or(NetError::Enodev)
}

#[cfg(test)]
#[path = "mcast_filter_tests.rs"]
mod tests;
