extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sync::{Spinlock, Socket as LockClass};

use crate::addr::{Ipv4Addr, Ipv6Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};
use crate::stack::NetStack;

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
struct V4Membership { net_ns: u64, report_src: Ipv4Addr, filter: SourceFilter }

#[derive(Clone, Debug)]
struct V6Membership { report_src: Ipv6Addr, filter: SourceFilter6 }

struct Inner {
    v4: BTreeMap<V4Key, V4Membership>,
    v6: BTreeMap<V6Key, V6Membership>,
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
        let mut inner = self.inner.lock();
        if join {
            if inner.v4.contains_key(&key) { return Err(NetError::Eaddrinuse); }
            let membership = V4Membership {
                net_ns, report_src, filter: SourceFilter { mode: FilterMode::Exclude, sources: Vec::new() },
            };
            stack.set_ipv4_multicast_in(net_ns, self.owner_key(), iface, group, report_src, Some(&membership.filter))?;
            inner.v4.insert(key, membership);
        } else {
            let membership = inner.v4.get(&key).ok_or(NetError::Eaddrnotavail)?;
            if membership.net_ns != net_ns { return Err(NetError::Enodev); }
            stack.set_ipv4_multicast_in(net_ns, self.owner_key(), iface, group, membership.report_src, None)?;
            inner.v4.remove(&key);
        }
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
        let mut inner = self.inner.lock();
        match op {
            SourceOp::Join => {
                let mut next = match inner.v4.get(&key) {
                    Some(current) if current.filter.mode != FilterMode::Include => return Err(NetError::Eaddrinuse),
                    Some(current) => current.clone(),
                    None => V4Membership {
                        net_ns, report_src, filter: SourceFilter { mode: FilterMode::Include, sources: Vec::new() },
                    },
                };
                if next.net_ns != net_ns { return Err(NetError::Enodev); }
                if next.filter.sources.contains(&source) { return Err(NetError::Eaddrinuse); }
                next.filter.sources.push(source);
                stack.set_ipv4_multicast_in(net_ns, self.owner_key(), iface, group, next.report_src, Some(&next.filter))?;
                inner.v4.insert(key, next);
            }
            SourceOp::Leave => {
                let mut next = inner.v4.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
                if next.net_ns != net_ns { return Err(NetError::Enodev); }
                if next.filter.mode != FilterMode::Include { return Err(NetError::Einval); }
                let index = next.filter.sources.iter().position(|addr| *addr == source)
                    .ok_or(NetError::Eaddrnotavail)?;
                next.filter.sources.remove(index);
                let policy = if next.filter.sources.is_empty() { None } else { Some(&next.filter) };
                stack.set_ipv4_multicast_in(net_ns, self.owner_key(), iface, group, next.report_src, policy)?;
                if policy.is_none() { inner.v4.remove(&key); } else { inner.v4.insert(key, next); }
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
                stack.set_ipv4_multicast_in(net_ns, self.owner_key(), iface, group, next.report_src, Some(&next.filter))?;
                inner.v4.insert(key, next);
            }
        }
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
        let mut inner = self.inner.lock();
        if mode == FilterMode::Include && dedup.is_empty() {
            let membership = inner.v4.get(&key).ok_or(NetError::Eaddrnotavail)?;
            if membership.net_ns != net_ns { return Err(NetError::Enodev); }
            stack.set_ipv4_multicast_in(net_ns, self.owner_key(), iface, group, membership.report_src, None)?;
            inner.v4.remove(&key);
        } else {
            let next = V4Membership {
                net_ns,
                report_src: inner.v4.get(&key).map(|current| current.report_src).unwrap_or(report_src),
                filter: SourceFilter { mode, sources: dedup },
            };
            if inner.v4.get(&key).is_some_and(|current| current.net_ns != net_ns) {
                return Err(NetError::Enodev);
            }
            stack.set_ipv4_multicast_in(net_ns, self.owner_key(), iface, group, next.report_src, Some(&next.filter))?;
            inner.v4.insert(key, next);
        }
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
        let mut inner = self.inner.lock();
        if join {
            if inner.v6.contains_key(&key) { return Err(NetError::Eaddrinuse); }
            let membership = V6Membership {
                report_src, filter: SourceFilter6 { mode: FilterMode::Exclude, sources: Vec::new() },
            };
            stack.set_ipv6_multicast_in(net_ns, self.owner_key(), iface, group, report_src, Some(&membership.filter))?;
            inner.v6.insert(key, membership);
        } else {
            let membership = inner.v6.get(&key).ok_or(NetError::Eaddrnotavail)?;
            stack.set_ipv6_multicast_in(net_ns, self.owner_key(), iface, group, membership.report_src, None)?;
            inner.v6.remove(&key);
        }
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
        let mut inner = self.inner.lock();
        match op {
            SourceOp::Join => {
                let mut next = match inner.v6.get(&key) {
                    Some(current) if current.filter.mode != FilterMode::Include => return Err(NetError::Eaddrinuse),
                    Some(current) => current.clone(),
                    None => V6Membership {
                        report_src, filter: SourceFilter6 { mode: FilterMode::Include, sources: Vec::new() },
                    },
                };
                if next.filter.sources.contains(&source) { return Err(NetError::Eaddrinuse); }
                next.filter.sources.push(source);
                stack.set_ipv6_multicast_in(net_ns, self.owner_key(), iface, group, next.report_src, Some(&next.filter))?;
                inner.v6.insert(key, next);
            }
            SourceOp::Leave => {
                let mut next = inner.v6.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
                if next.filter.mode != FilterMode::Include { return Err(NetError::Einval); }
                let index = next.filter.sources.iter().position(|addr| *addr == source)
                    .ok_or(NetError::Eaddrnotavail)?;
                next.filter.sources.remove(index);
                let policy = if next.filter.sources.is_empty() { None } else { Some(&next.filter) };
                stack.set_ipv6_multicast_in(net_ns, self.owner_key(), iface, group, next.report_src, policy)?;
                if policy.is_none() { inner.v6.remove(&key); } else { inner.v6.insert(key, next); }
            }
            SourceOp::Block | SourceOp::Unblock => {
                let mut next = inner.v6.get(&key).cloned().ok_or(NetError::Eaddrnotavail)?;
                if next.filter.mode != FilterMode::Exclude { return Err(NetError::Einval); }
                let found = next.filter.sources.iter().position(|addr| *addr == source);
                if op == SourceOp::Block {
                    if found.is_some() { return Err(NetError::Eaddrinuse); }
                    next.filter.sources.push(source);
                } else {
                    let index = found.ok_or(NetError::Eaddrnotavail)?;
                    next.filter.sources.remove(index);
                }
                stack.set_ipv6_multicast_in(net_ns, self.owner_key(), iface, group, next.report_src, Some(&next.filter))?;
                inner.v6.insert(key, next);
            }
        }
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
        let mut inner = self.inner.lock();
        if mode == FilterMode::Include && dedup.is_empty() {
            let membership = inner.v6.get(&key).ok_or(NetError::Eaddrnotavail)?;
            stack.set_ipv6_multicast_in(net_ns, self.owner_key(), iface, group, membership.report_src, None)?;
            inner.v6.remove(&key);
        } else {
            let next = V6Membership {
                report_src: inner.v6.get(&key).map(|current| current.report_src).unwrap_or(report_src),
                filter: SourceFilter6 { mode, sources: dedup },
            };
            stack.set_ipv6_multicast_in(net_ns, self.owner_key(), iface, group, next.report_src, Some(&next.filter))?;
            inner.v6.insert(key, next);
        }
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

    /// Release every socket membership while preserving other sockets' refs. # C: O(N groups)
    pub fn release(&self, stack: &NetStack) {
        let mut inner = self.inner.lock();
        let v4 = core::mem::take(&mut inner.v4);
        let v6 = core::mem::take(&mut inner.v6);
        drop(inner);
        for (key, membership) in v4 {
            stack.release_ipv4_multicast_in(membership.net_ns, self.owner_key(),
                NetIfaceId::from_raw(key.iface), key.group, membership.report_src);
        }
        for (key, membership) in v6 {
            stack.release_ipv6_multicast(self.owner_key(), NetIfaceId::from_raw(key.iface),
                key.group, membership.report_src);
        }
    }

    fn owner_key(&self) -> usize { self as *const Self as usize }
}

impl Default for SocketMcast { fn default() -> Self { Self::new() } }

fn v4_key(iface: NetIfaceId, group: Ipv4Addr) -> V4Key { V4Key { iface: iface.raw(), group } }
fn v6_key(iface: NetIfaceId, group: Ipv6Addr) -> V6Key { V6Key { iface: iface.raw(), group } }


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
mod tests {
    use super::*;

    #[test]
    fn unjoined_and_source_filters_gate_delivery() {
        let state = SocketMcast::new();
        let stack = NetStack::new();
        let (iface, _) = stack.register_loopback();
        let group = Ipv4Addr::new(239, 1, 2, 3);
        let allowed = Ipv4Addr::new(10, 0, 0, 1);
        let denied = Ipv4Addr::new(10, 0, 0, 2);
        assert!(!state.accept_v4(iface, group, allowed));
        state.set_v4(&stack, iface, group, Ipv4Addr::LOOPBACK, FilterMode::Include, &[allowed]).unwrap();
        assert!(state.accept_v4(iface, group, allowed));
        assert!(!state.accept_v4(iface, group, denied));
    }

    #[test]
    fn failed_source_operations_do_not_mutate_filter() {
        let state = SocketMcast::new();
        let stack = NetStack::new();
        let (iface, _) = stack.register_loopback();
        let group = Ipv4Addr::new(239, 1, 2, 4);
        let source = Ipv4Addr::new(10, 0, 0, 1);
        state.change_v4(&stack, iface, group, Ipv4Addr::LOOPBACK, true).unwrap();
        let before = state.get_v4(iface, group).unwrap();
        assert_eq!(state.source_v4(&stack, iface, group, Ipv4Addr::LOOPBACK,
            source, SourceOp::Join), Err(NetError::Eaddrinuse));
        assert_eq!(state.get_v4(iface, group).unwrap(), before);
        assert_eq!(state.source_v4(&stack, iface, group, Ipv4Addr::LOOPBACK,
            source, SourceOp::Unblock), Err(NetError::Eaddrnotavail));
        assert_eq!(state.get_v4(iface, group).unwrap(), before);
    }

    #[test]
    fn include_empty_removes_membership_and_interface_reference() {
        let state = SocketMcast::new();
        let stack = NetStack::new();
        let (iface, lo) = stack.register_loopback();
        let group = Ipv4Addr::new(232, 1, 2, 5);
        let source = Ipv4Addr::new(10, 0, 0, 2);
        state.set_v4(&stack, iface, group, Ipv4Addr::LOOPBACK,
            FilterMode::Include, &[source]).unwrap();
        let _ = lo.rx_pop().expect("source join report");
        state.set_v4(&stack, iface, group, Ipv4Addr::LOOPBACK,
            FilterMode::Include, &[]).unwrap();
        let leave = lo.rx_pop().expect("include-empty leave report");
        let header_len = usize::from(leave.data()[0] & 0x0f) * 4;
        let body = &leave.data()[header_len..];
        assert_eq!(body[8], crate::igmp::IGMP_V3_RECORD_BLOCK_OLD_SOURCES);
        assert_eq!(u16::from_be_bytes([body[10], body[11]]), 1);
        assert_eq!(&body[16..20], &source.octets());
        assert!(!state.accept_v4(iface, group, source));
        assert!(stack.v4_mcast.lock().get(&iface).is_some_and(|groups| {
            groups.iter().any(|entry| entry.group == group && entry.is_empty()
                && matches!(entry.change.as_ref().map(|change| &change.report),
                    Some(crate::mcast_state::V4Report::Tomb)))
        }));
        stack.retry_multicast_reports(crate::mcast_state::REPORT_INTERVAL_NS);
        let _ = lo.rx_pop().expect("include-empty leave retry");
        assert!(!stack.v4_mcast.lock().get(&iface).is_some_and(|groups| {
            groups.iter().any(|entry| entry.group == group)
        }));
    }

    #[test]
    fn release_clears_socket_before_interface_reporting() {
        let state = SocketMcast::new();
        let stack = NetStack::new();
        let (iface, lo) = stack.register_loopback();
        let group = Ipv4Addr::new(239, 1, 2, 6);
        state.change_v4(&stack, iface, group, Ipv4Addr::LOOPBACK, true).unwrap();
        let _ = lo.rx_pop().expect("join report");
        state.release(&stack);
        assert!(!state.accept_v4(iface, group, Ipv4Addr::new(10, 0, 0, 3)));
        assert!(lo.rx_pop().is_some());
    }

    #[test]
    fn v4_membership_and_release_use_captured_namespace() {
        let state = SocketMcast::new();
        let stack = NetStack::new();
        let (local, lo) = stack.register_loopback_in(61);
        let (foreign, _) = stack.register_loopback_in(62);
        let group = Ipv4Addr::new(239, 1, 2, 7);
        assert_eq!(state.change_v4_in(&stack, 61, foreign, group, Ipv4Addr::LOOPBACK, true),
            Err(NetError::Enodev));
        state.change_v4_in(&stack, 61, local, group, Ipv4Addr::LOOPBACK, true).unwrap();
        let _ = lo.rx_pop().expect("namespace join report");
        state.release(&stack);
        assert!(lo.rx_pop().is_some());
        assert!(!state.accept_v4(local, group, Ipv4Addr::new(10, 0, 0, 3)));
    }

    #[test]
    fn v6_zero_ifindex_uses_bound_mcast_then_route() {
        use crate::route6::Route6Entry;
        let stack = NetStack::new();
        let (route_iface, _) = stack.register_loopback();
        let (selected_iface, _) = stack.register_loopback();
        let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x1234]);
        stack.routes6.add(Route6Entry {
            dst: Ipv6Addr::ANY, prefix_len: 0, iface: route_iface, gateway: None, src_hint: None,
        });
        assert_eq!(resolve_v6_iface(&stack, 0, 0, 0, 0, group), Ok(route_iface));
        assert_eq!(resolve_v6_iface(&stack, 0, 0, 0, selected_iface.raw(), group), Ok(selected_iface));
        assert_eq!(resolve_v6_iface(&stack, 0, 0, selected_iface.raw(), route_iface.raw(), group), Ok(selected_iface));
        assert_eq!(resolve_v6_iface(&stack, 0, route_iface.raw(), selected_iface.raw(), 0, group), Ok(route_iface));
    }

    #[test]
    fn v6_resolution_rejects_foreign_iface_and_uses_namespace_route() {
        use crate::route6::Route6Entry;
        let stack = NetStack::new();
        let (a, _) = stack.register_loopback_in(51);
        let (b, _) = stack.register_loopback_in(52);
        let group = Ipv6Addr::from_segments([0xff02,0,0,0,0,0,0,0x4321]);
        stack.routes6.add_in(51, Route6Entry {
            dst: Ipv6Addr::ANY, prefix_len: 0, iface: a, gateway: None, src_hint: None,
        });
        assert_eq!(resolve_v6_iface(&stack, 51, 0, 0, 0, group), Ok(a));
        assert_eq!(resolve_v6_iface(&stack, 51, b.raw(), 0, 0, group), Err(NetError::Enodev));
    }
}
