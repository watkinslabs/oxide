// IPv6 multicast membership on one socket: join, leave, source filter and
// full-filter replacement. Split out of `mcast_filter` at the per-file size
// cutoff; the IPv4 twin of every function here lives in the parent.

use alloc::vec::Vec;

use crate::addr::{Ipv6Addr, NetIfaceId};
use crate::netdev::{NetError, NetResult};
use crate::stack::NetStack;

use super::{FilterMode, SocketMcast, SourceFilter6, SourceOp, V6Membership, namespace_owner,
    publish_v6, v6_key};

impl SocketMcast {
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
}
