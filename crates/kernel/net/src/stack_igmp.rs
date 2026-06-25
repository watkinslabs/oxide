use crate::addr::{IpProto, Ipv4Addr, NetIfaceId};
use crate::igmp::{IgmpQuery, IGMP_TYPE_LEAVE, IGMP_TYPE_V2_REPORT, IPV4_ALL_HOSTS, IPV4_ALL_ROUTERS};
use crate::netdev::{NetError, NetResult};
use crate::stack::NetStack;

impl NetStack {
    fn v4_src_on_iface(&self, iface: NetIfaceId) -> Option<Ipv4Addr> {
        self.routes.snapshot().into_iter()
            .find(|r| r.iface == iface)
            .and_then(|r| r.src_hint)
    }

    fn emit_igmp(&self, iface: NetIfaceId, src: Ipv4Addr, dst: Ipv4Addr, typ: u8, group: Ipv4Addr)
        -> NetResult<()>
    {
        let dev = self.ifaces.lookup(iface).ok_or(NetError::Enetunreach)?;
        let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
        let body = crate::igmp::build_igmp_msg(typ, group);
        self.xmit_ipv4_l4_on_iface_opts(iface, dev, src, dst, IpProto::Igmp, &body, 0, 1, id)
    }

    /// Join an IPv4 multicast group and emit an IGMPv2 membership report.
    /// # C: O(N groups + routes)
    pub fn join_ipv4_multicast(&self, iface: NetIfaceId, group: Ipv4Addr, src: Ipv4Addr)
        -> NetResult<()>
    {
        if !group.is_multicast() { return Err(NetError::Einval); }
        let src = if src.is_unspecified() { self.v4_src_on_iface(iface).unwrap_or(src) } else { src };
        let fresh = {
            let mut g = self.v4_mcast.lock();
            let groups = g.entry(iface).or_default();
            if groups.iter().any(|(m, _)| *m == group) { false } else { groups.push((group, src)); true }
        };
        if fresh && group != IPV4_ALL_HOSTS {
            self.emit_igmp(iface, src, group, IGMP_TYPE_V2_REPORT, group)?;
        }
        Ok(())
    }

    /// Leave an IPv4 multicast group and emit an IGMPv2 leave when tracked.
    /// # C: O(N groups)
    pub fn leave_ipv4_multicast(&self, iface: NetIfaceId, group: Ipv4Addr, src: Ipv4Addr)
        -> NetResult<()>
    {
        let mut report_src = if src.is_unspecified() { self.v4_src_on_iface(iface).unwrap_or(src) } else { src };
        let removed = {
            let mut g = self.v4_mcast.lock();
            if let Some(groups) = g.get_mut(&iface) {
                let before = groups.len();
                groups.retain(|(m, s)| {
                    if *m == group {
                        report_src = *s;
                        false
                    } else { true }
                });
                before != groups.len()
            } else { false }
        };
        if removed && group != IPV4_ALL_HOSTS {
            self.emit_igmp(iface, report_src, IPV4_ALL_ROUTERS, IGMP_TYPE_LEAVE, group)?;
        }
        Ok(())
    }

    /// Handle IGMP general/group-specific queries. # C: O(N groups)
    pub(crate) fn handle_igmp(&self, iface: NetIfaceId, _src: Ipv4Addr, _dst: Ipv4Addr, payload: &[u8])
        -> NetResult<()>
    {
        let q = match IgmpQuery::parse(payload) { Ok(q) => q, Err(_) => return Ok(()) };
        let groups = {
            let g = self.v4_mcast.lock();
            g.get(&iface).cloned().unwrap_or_default()
        };
        for (group, src) in groups {
            if group == IPV4_ALL_HOSTS { continue; }
            if !q.group.is_unspecified() && q.group != group { continue; }
            self.emit_igmp(iface, src, group, IGMP_TYPE_V2_REPORT, group)?;
        }
        Ok(())
    }
}
