use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::igmp::{
    IgmpQuery, IGMP_V3_RECORD_MODE_IS_EXCLUDE, IGMP_V3_RECORD_MODE_IS_INCLUDE,
    IPV4_ALL_HOSTS, IPV4_ALL_ROUTERS, IPV4_IGMPV3_ROUTERS,
};
use crate::mcast_filter::{FilterMode, SourceFilter};
use crate::mcast_state::{V4Change, V4IfaceGroup, V4ReportWork};
use crate::netdev::{NetError, NetResult};
use crate::stack::NetStack;
const IGMP_TYPE_V1_REPORT: u8 = 0x12;
fn report_owner(net_ns: u64) -> Option<network_namespace::NetworkNamespaceRef> {
    if net_ns == 0 { Some(network_namespace::initial()) }
    else { network_namespace::lookup_u64(net_ns) }
}
impl NetStack {
    pub(crate) fn multicast_generation_in(&self, _rtnl: &crate::RtnlGuard<'_>,
                                           net_ns: u64, iface: NetIfaceId) -> NetResult<u64> {
        let generation = self.ifaces.control_generation_in_ns(_rtnl, iface, net_ns)
            .ok_or(NetError::Enodev)?;
        if self.ifaces.mcast_report_in_ns(iface, net_ns).is_none() { return Err(NetError::Enodev); }
        Ok(generation)
    }
    /// Multicast generation for the RECEIVE path, without taking RTNL.
    ///
    /// IGMP and MLD query responses run inline in the NetRx softirq. Taking
    /// RTNL there is illegal once RTNL is the sleeping mutex Linux makes it,
    /// and it was never needed: the generation read is protected by the
    /// interface table's own lock, and RTNL was only ever a discipline token.
    /// # Ctx: any, including softirq
    /// # C: O(N)
    pub(crate) fn multicast_generation_rx(&self, net_ns: u64, iface: NetIfaceId)
        -> NetResult<u64>
    {
        let generation = self.ifaces.control_generation_in_ns_rx(iface, net_ns)
            .ok_or(NetError::Enodev)?;
        if self.ifaces.mcast_report_in_ns(iface, net_ns).is_none() { return Err(NetError::Enodev); }
        Ok(generation)
    }
    pub(crate) fn finish_v4_multicast(&self, work: Option<V4ReportWork>) {
        let Some(work) = work else { return };
        self.drive_v4_reports(work);
    }
    fn v4_src_on_iface(&self, net_ns: u64, iface: NetIfaceId) -> Option<Ipv4Addr> {
        self.routes.snapshot_in(net_ns).into_iter().find(|r| r.iface == iface).and_then(|r| r.src_hint)
    }
    fn emit_v4_policy(&self, net_ns: u64, iface: NetIfaceId, src: Ipv4Addr, record_include: u8,
                      record_exclude: u8, group: Ipv4Addr, filter: &SourceFilter) -> NetResult<()> {
        let record = match filter.mode { FilterMode::Include => record_include, FilterMode::Exclude => record_exclude };
        self.emit_igmpv3(net_ns, iface, src, &[(record, group, filter.sources.as_slice())])
    }
    fn emit_v4_change(&self, net_ns: u64, iface: NetIfaceId, iface_generation: u64,
                      src: Ipv4Addr, group: Ipv4Addr,
                      change: &V4Change) -> NetResult<()> {
        if change.records.is_empty() { return Ok(()); }
        let version = self.v4_mcast.lock().get(&iface).and_then(|groups| groups.iter()
            .find(|state| state.iface_generation() == iface_generation)).map(|state|
                state.report_version(crate::stack::net_now_ns())).unwrap_or(3);
        if version < 3 {
            return match &change.report {
                crate::mcast_state::V4Report::Active(_) => self.emit_igmp_legacy(
                    net_ns, iface, src, group, if version == 1 { IGMP_TYPE_V1_REPORT }
                        else { crate::igmp::IGMP_TYPE_V2_REPORT }, group,
                ),
                crate::mcast_state::V4Report::Tomb if version == 2 => self.emit_igmp_legacy(
                    net_ns, iface, src, IPV4_ALL_ROUTERS, crate::igmp::IGMP_TYPE_LEAVE, group,
                ),
                crate::mcast_state::V4Report::Tomb => Ok(()),
            };
        }
        let records: alloc::vec::Vec<_> = change.records.iter()
            .map(|record| (record.record_type, group, record.sources.as_slice())).collect();
        self.emit_igmpv3(net_ns, iface, src, &records)
    }
    fn advance_v4_change(&self, iface: NetIfaceId, iface_generation: u64,
                         group: Ipv4Addr, generation: u64,
                         attempted: &crate::mcast_state::V4Change,
                         delivered: bool, now_ns: u64) -> bool {
        let mut all = self.v4_mcast.lock();
        let Some(groups) = all.get_mut(&iface) else { return false };
        let Some(index) = groups.iter().position(|state| state.iface_generation() == iface_generation
            && state.group == group) else { return false };
        if groups[index].generation != generation {
            groups[index].reconcile_superseded(attempted, delivered, now_ns);
            return true;
        }
        let complete = groups[index].change.as_mut()
            .is_some_and(|change| change.attempted(delivered, now_ns));
        if complete {
            groups[index].change = None;
            if groups[index].is_empty() && !groups[index].compatibility_active(now_ns) {
                groups.remove(index);
            }
        }
        if groups.is_empty() { all.remove(&iface); }
        true
    }
    fn transmit_v4_change(&self, net_ns: u64, iface: NetIfaceId, iface_generation: u64,
                          src: Ipv4Addr,
                          group: Ipv4Addr, generation: u64,
                          change: &crate::mcast_state::V4Change, now_ns: u64) {
        let current = self.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
            .any(|state| state.iface_generation() == iface_generation && state.group == group
                && state.generation == generation
                && state.change.is_some()));
        if !current { return; }
        let delivered = self.emit_v4_change(net_ns, iface, iface_generation, src, group, change).is_ok();
        self.advance_v4_change(iface, iface_generation, group, generation, change, delivered, now_ns);
    }
    fn transmit_v4_query(&self, net_ns: u64, iface: NetIfaceId, iface_generation: u64,
                         now_ns: u64) -> bool {
        let pending = {
            let mut all = self.v4_mcast.lock();
            let Some(groups) = all.get_mut(&iface) else { return false };
            let Some(state) = groups.iter_mut().find(|state| state.iface_generation() == iface_generation
                && state.queries.first().is_some_and(|query| query.deadline_ns <= now_ns))
                else { return false };
            let query = state.queries.remove(0);
            if query.generation != state.generation { return true; }
            (state.report_src, state.group, state.aggregate(), query)
        };
        let (src, group, aggregate, query) = pending;
        if query.version < 3 {
            let typ = if query.version == 1 { IGMP_TYPE_V1_REPORT }
                else { crate::igmp::IGMP_TYPE_V2_REPORT };
            let _ = self.emit_igmp_legacy(net_ns, iface, src, group, typ, group);
        } else if query.sources.is_empty() {
            let _ = self.emit_v4_policy(net_ns, iface, src, IGMP_V3_RECORD_MODE_IS_INCLUDE,
                IGMP_V3_RECORD_MODE_IS_EXCLUDE, group, &aggregate);
        } else {
            let mut wanted = alloc::vec::Vec::new();
            for queried in query.sources {
                let listed = aggregate.sources.contains(&queried);
                let accepted = match aggregate.mode { FilterMode::Include => listed, FilterMode::Exclude => !listed };
                if accepted && !wanted.contains(&queried) { wanted.push(queried); }
            }
            if !wanted.is_empty() { let _ = self.emit_igmpv3(net_ns, iface, src,
                &[(IGMP_V3_RECORD_MODE_IS_INCLUDE, group, wanted.as_slice())]); }
        }
        true
    }
    fn drive_v4_reports(&self, work: V4ReportWork) {
        let V4ReportWork { owner, iface, iface_generation, driver, now_ns } = work;
        let net_ns = owner.id().as_u64();
        if !driver.live() { return; }
        if !driver.try_v4() { return; }
        loop {
            let drive_now = now_ns.max(crate::stack::net_now_ns());
            if !driver.live() { driver.release_v4(); return; }
            let pending = self.v4_mcast.lock().get(&iface).and_then(|groups| groups.iter()
                .filter(|state| state.iface_generation() == iface_generation)
                .find_map(|state| state.change.as_ref().filter(|change| change.due(drive_now))
                    .map(|change| (state.group, state.report_src, state.generation, change.clone()))));
            let Some((group, src, generation, change)) = pending else {
                if self.transmit_v4_query(net_ns, iface, iface_generation, drive_now) { continue; }
                driver.release_v4();
                let due = self.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
                    .any(|state| state.iface_generation() == iface_generation
                        && (state.change.as_ref().is_some_and(|change|
                            change.due(now_ns.max(crate::stack::net_now_ns())))
                            || state.queries.first().is_some_and(|query|
                                query.deadline_ns <= now_ns.max(crate::stack::net_now_ns())))));
                if !due || !driver.try_v4() { return; }
                continue;
            };
            if !driver.live() { driver.release_v4(); return; }
            self.transmit_v4_change(net_ns, iface, iface_generation, src, group,
                generation, &change, drive_now);
        }
    }
    fn discard_v4_change(&self, iface: NetIfaceId, iface_generation: u64,
                         group: Ipv4Addr, generation: u64) {
        let mut all = self.v4_mcast.lock();
        let Some(groups) = all.get_mut(&iface) else { return };
        let Some(index) = groups.iter().position(|state| state.iface_generation() == iface_generation
            && state.group == group) else { return };
        if groups[index].generation != generation { return; }
        groups[index].change = None;
        if groups[index].is_empty() { groups.remove(index); }
        if groups.is_empty() { all.remove(&iface); }
    }
    /// Publish one socket's full filter and emit the resulting interface state. # C: O(N * S)
    pub(crate) fn set_ipv4_multicast(&self, owner: usize, iface: NetIfaceId, group: Ipv4Addr,
                                     src: Ipv4Addr, filter: Option<&SourceFilter>) -> NetResult<()> {
        self.set_ipv4_multicast_in(0, owner, iface, group, src, filter)
    }
    /// Publish socket IGMP policy in one network namespace. # C: O(N * S)
    pub(crate) fn set_ipv4_multicast_in(&self, net_ns: u64, owner: usize,
                                        iface: NetIfaceId, group: Ipv4Addr,
                                        src: Ipv4Addr, filter: Option<&SourceFilter>) -> NetResult<()> {
        let report_owner = report_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = self.rtnl_lock();
        let generation = self.multicast_generation_in(&rtnl, net_ns, iface)?;
        let work = self.set_ipv4_multicast_rtnl(&rtnl, &report_owner, net_ns, generation, owner, iface,
            group, src, filter)?;
        drop(rtnl);
        self.finish_v4_multicast(work);
        Ok(())
    }
    pub(crate) fn set_ipv4_multicast_rtnl(&self, _rtnl: &crate::RtnlGuard<'_>,
                                          report_owner: &network_namespace::NetworkNamespaceRef,
                                          net_ns: u64,
                                          expected_generation: u64, owner: usize,
                                          iface: NetIfaceId, group: Ipv4Addr, src: Ipv4Addr,
                                          filter: Option<&SourceFilter>)
        -> NetResult<Option<V4ReportWork>>
    {
        if !group.is_multicast() { return Err(NetError::Einval); }
        if report_owner.id().as_u64() != net_ns { return Err(NetError::Enodev); }
        let generation = self.multicast_generation_in(_rtnl, net_ns, iface)?;
        if generation != expected_generation { return Err(NetError::Enodev); }
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let src = if src.is_unspecified() { self.v4_src_on_iface(net_ns, iface).unwrap_or(src) } else { src };
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v4_mcast.lock();
            if filter.is_none() && !all.get(&iface).is_some_and(|groups| {
                groups.iter().any(|state| state.iface_generation() == generation
                    && state.group == group)
            }) { return Err(NetError::Eaddrnotavail); }
            let groups = if filter.is_some() { all.entry(iface).or_default() }
                else { all.get_mut(&iface).ok_or(NetError::Eaddrnotavail)? };
            let index = groups.iter().position(|state| state.iface_generation() == generation
                && state.group == group);
            let index = match index {
                Some(index) => index,
                None => { groups.push(V4IfaceGroup::inherited(groups, generation, group, src)); groups.len() - 1 }
            };
            let prior = if groups[index].generation == 0 && groups[index].is_empty() { None }
                else { Some(groups[index].aggregate()) };
            match filter {
                Some(next) => { groups[index].members.insert(owner, next.clone()); }
                None if groups[index].members.remove(&owner).is_none() => return Err(NetError::Eaddrnotavail),
                None => {}
            }
            let after = groups[index].aggregate();
            if prior.as_ref().is_some_and(|before| *before == after) { None } else {
                let report_src = groups[index].report_src;
                let (generation, _) = groups[index].stage(prior.as_ref(), now_ns);
                Some((report_src, generation))
            }
        };
        let Some((_report_src, generation)) = staged else { return Ok(None) };
        if group == IPV4_ALL_HOSTS {
            self.discard_v4_change(iface, expected_generation, group, generation);
            return Ok(None);
        }
        Ok(Some(V4ReportWork { owner: report_owner.clone(), iface, iface_generation: expected_generation,
            driver: report, now_ns }))
    }
    /// Remove one dead socket's policy and retain only a compact failed report. # C: O(N)
    pub(crate) fn release_ipv4_multicast(&self, owner: usize, iface: NetIfaceId,
                                         group: Ipv4Addr, _src: Ipv4Addr) {
        self.release_ipv4_multicast_in(0, owner, iface, group, _src)
    }
    /// Remove dead socket policy in one network namespace. # C: O(N)
    pub(crate) fn release_ipv4_multicast_in(&self, net_ns: u64, owner: usize,
                                            iface: NetIfaceId, group: Ipv4Addr,
                                            _src: Ipv4Addr) {
        let Some(report_owner) = report_owner(net_ns) else { return };
        let rtnl = self.rtnl_lock();
        let Ok(generation) = self.multicast_generation_in(&rtnl, net_ns, iface) else { return };
        let work = self.release_ipv4_multicast_rtnl(&rtnl, Some(&report_owner), net_ns, generation,
            owner, iface, group);
        drop(rtnl);
        self.finish_v4_multicast(work);
    }
    pub(crate) fn release_ipv4_multicast_rtnl(&self, rtnl: &crate::RtnlGuard<'_>,
                                               report_owner: Option<&network_namespace::NetworkNamespaceRef>,
                                               net_ns: u64,
                                               expected_generation: u64, owner: usize,
                                               iface: NetIfaceId, group: Ipv4Addr)
        -> Option<V4ReportWork>
    {
        if self.multicast_generation_in(rtnl, net_ns, iface).ok() != Some(expected_generation) {
            return None;
        }
        if report_owner.is_some_and(|owner| owner.id().as_u64() != net_ns) { return None; }
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns);
        let now_ns = crate::stack::net_now_ns();
        let snapshot = {
            let mut all = self.v4_mcast.lock();
            let Some(groups) = all.get_mut(&iface) else { return None };
            let Some(state) = groups.iter_mut().find(|state| state.iface_generation() == expected_generation
                && state.group == group) else { return None };
            let prior = state.aggregate();
            if state.members.remove(&owner).is_none() { return None; }
            if state.aggregate() == prior { None } else {
                let (generation, _) = state.stage(Some(&prior), now_ns);
                Some(generation)
            }
        };
        let Some(generation) = snapshot else { return None };
        if group == IPV4_ALL_HOSTS {
            self.discard_v4_change(iface, expected_generation, group, generation); return None;
        }
        let report = report.filter(|report| report.live())?;
        Some(V4ReportWork { owner: report_owner?.clone(), iface, iface_generation: expected_generation,
            driver: report, now_ns })
    }
    fn emit_igmpv3(&self, net_ns: u64, iface: NetIfaceId, src: Ipv4Addr,
                   records: &[(u8, Ipv4Addr, &[Ipv4Addr])]) -> NetResult<()> {
        let body = crate::igmp::build_igmpv3_records(records);
        self.emit_igmp_body(net_ns, iface, src, IPV4_IGMPV3_ROUTERS, &body)
    }
    fn emit_igmp_legacy(&self, net_ns: u64, iface: NetIfaceId, src: Ipv4Addr, dst: Ipv4Addr,
                        typ: u8, group: Ipv4Addr) -> NetResult<()> {
        let body = crate::igmp::build_igmp_msg(typ, group);
        self.emit_igmp_body(net_ns, iface, src, dst, &body)
    }
    fn emit_igmp_body(&self, net_ns: u64, iface: NetIfaceId, src: Ipv4Addr, dst: Ipv4Addr,
                      body: &[u8]) -> NetResult<()> {
        let dev = self.ifaces.acquire_egress_in_ns(iface, net_ns).ok_or(NetError::Enetunreach)?;
        let id = { let mut s = self.next_ip_id.lock(); *s = s.wrapping_add(1); *s };
        let header_len = 24usize;
        let total = header_len + body.len();
        if total > dev.mtu() as usize || total > u16::MAX as usize { return Err(NetError::Enobufs); }
        let mut packet = crate::Pkt::with_capacity(header_len, total);
        packet.put(body.len()).map_err(|_| NetError::Enobufs)?.copy_from_slice(body);
        let header = packet.push(header_len).map_err(|_| NetError::Enobufs)?;
        header[0] = 0x46;
        header[1] = 0;
        header[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        header[4..6].copy_from_slice(&id.to_be_bytes());
        header[6..8].copy_from_slice(&0u16.to_be_bytes());
        header[8] = 1;
        header[9] = 2;
        header[10..12].copy_from_slice(&0u16.to_be_bytes());
        header[12..16].copy_from_slice(&src.octets());
        header[16..20].copy_from_slice(&dst.octets());
        header[20..24].copy_from_slice(&[0x94, 0x04, 0, 0]);
        let checksum = crate::ipv4::ip_checksum(header);
        header[10..12].copy_from_slice(&checksum.to_be_bytes());
        packet.proto = crate::addr::eth_p::IPV4;
        packet.iface = Some(iface);
        if !crate::netfilter_hook::nf_output(&packet, crate::netfilter_hook::NFPROTO_IPV4) { return Ok(()); }
        dev.xmit(packet)
    }
    /// Join an IPv4 multicast group and emit a state-change report. # C: O(N groups + routes)
    pub fn join_ipv4_multicast(&self, iface: NetIfaceId, group: Ipv4Addr, src: Ipv4Addr) -> NetResult<()> {
        self.join_ipv4_multicast_in(0, iface, group, src)
    }
    /// Join an IPv4 multicast group in one network namespace. # C: O(N groups + routes)
    pub fn join_ipv4_multicast_in(&self, net_ns: u64, iface: NetIfaceId,
                                  group: Ipv4Addr, src: Ipv4Addr) -> NetResult<()> {
        let owner = report_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = self.rtnl_lock();
        if !group.is_multicast() { return Err(NetError::Einval); }
        let iface_generation = self.multicast_generation_in(&rtnl, net_ns, iface)?;
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let src = if src.is_unspecified() { self.v4_src_on_iface(net_ns, iface).unwrap_or(src) } else { src };
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v4_mcast.lock();
            let groups = all.entry(iface).or_default();
            let index = match groups.iter().position(|state| state.iface_generation() == iface_generation
                && state.group == group) {
                Some(index) => index,
                None => { groups.push(V4IfaceGroup::inherited(groups, iface_generation, group, src)); groups.len() - 1 }
            };
            let existed = !(groups[index].generation == 0 && groups[index].is_empty());
            let before = groups[index].aggregate();
            groups[index].asm_refs = groups[index].asm_refs.saturating_add(1);
            let after = groups[index].aggregate();
            if before == after && existed { None } else {
                let report_src = groups[index].report_src;
                let prior = if existed { Some(&before) } else { None };
                let (generation, _) = groups[index].stage(prior, now_ns);
                Some((report_src, generation))
            }
        };
        let Some((_report_src, generation)) = staged else { return Ok(()) };
        if group == IPV4_ALL_HOSTS {
            self.discard_v4_change(iface, iface_generation, group, generation); return Ok(());
        }
        let work = Some(V4ReportWork { owner, iface, iface_generation, driver: report, now_ns });
        drop(rtnl);
        self.finish_v4_multicast(work);
        Ok(())
    }
    /// Leave an IPv4 multicast group and emit a state-change report. # C: O(N groups)
    pub fn leave_ipv4_multicast(&self, iface: NetIfaceId, group: Ipv4Addr, _src: Ipv4Addr) -> NetResult<()> {
        self.leave_ipv4_multicast_in(0, iface, group, _src)
    }
    /// Leave an IPv4 multicast group in one network namespace. # C: O(N groups)
    pub fn leave_ipv4_multicast_in(&self, net_ns: u64, iface: NetIfaceId,
                                   group: Ipv4Addr, _src: Ipv4Addr) -> NetResult<()> {
        let owner = report_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = self.rtnl_lock();
        let iface_generation = self.multicast_generation_in(&rtnl, net_ns, iface)?;
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v4_mcast.lock();
            let groups = all.get_mut(&iface).ok_or(NetError::Eaddrnotavail)?;
            let state = groups.iter_mut().find(|state| state.iface_generation() == iface_generation
                && state.group == group).ok_or(NetError::Eaddrnotavail)?;
            if state.asm_refs == 0 { return Err(NetError::Eaddrnotavail); }
            let before = state.aggregate();
            state.asm_refs -= 1;
            let after = state.aggregate();
            if before == after { None } else {
                let (generation, _) = state.stage(Some(&before), now_ns);
                Some(generation)
            }
        };
        let Some(generation) = staged else { return Ok(()) };
        if group == IPV4_ALL_HOSTS {
            self.discard_v4_change(iface, iface_generation, group, generation); return Ok(());
        }
        let work = Some(V4ReportWork { owner, iface, iface_generation, driver: report, now_ns });
        drop(rtnl);
        self.finish_v4_multicast(work);
        Ok(())
    }
    /// Retry failed IGMP/MLD state-change reports. # C: O(N groups)
    pub fn retry_multicast_reports(&self, now_ns: u64) {
        let pending = {
            let all = self.v4_mcast.lock();
            let mut pending = alloc::vec::Vec::new();
            for (iface, groups) in all.iter() { for state in groups {
                if state.change.as_ref().is_some_and(|change| change.due(now_ns))
                    || state.queries.first().is_some_and(|query| query.deadline_ns <= now_ns) {
                    pending.push((*iface, state.iface_generation()));
                }
            }}
            pending
        };
        for (iface, iface_generation) in pending {
            let Some(net_ns) = self.ifaces.namespace(iface) else { continue };
            let Some(owner) = report_owner(net_ns) else { continue };
            let rtnl = self.rtnl_lock();
            if self.ifaces.control_generation_in_ns(&rtnl, iface, net_ns) != Some(iface_generation) {
                continue;
            }
            let Some(driver) = self.ifaces.mcast_report_in_ns(iface, net_ns)
                .filter(|driver| driver.live()) else { continue };
            drop(rtnl);
            self.finish_v4_multicast(Some(V4ReportWork {
                owner, iface, iface_generation, driver, now_ns,
            }));
        }
        self.retry_mld_reports(now_ns);
    }
    /// Handle IGMP general/group-specific queries. # C: O(N groups)
    pub(crate) fn handle_igmp(&self, iface: NetIfaceId, _src: Ipv4Addr, dst: Ipv4Addr,
                              payload: &[u8]) -> NetResult<()> {
        let net_ns = self.ifaces.namespace(iface).ok_or(NetError::Enodev)?;
        let owner = report_owner(net_ns).ok_or(NetError::Enodev)?;
        let q = match IgmpQuery::parse(payload) { Ok(q) => q, Err(_) => return Ok(()) };
        if !q.group.is_unspecified() && !q.group.is_multicast() { return Ok(()); }
        let version = if payload.len() >= 12 { 3 } else if q.max_resp_time == 0 { 1 } else { 2 };
        let now_ns = crate::stack::net_now_ns();
        // No RTNL here: this runs in the NetRx softirq (W1-a).
        let iface_generation = self.multicast_generation_rx(net_ns, iface)?;
        let assigned_dst = if dst.is_multicast() {
            dst == IPV4_ALL_HOSTS || self.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
                .any(|state| state.iface_generation() == iface_generation
                    && state.group == dst && !state.is_empty()))
        } else { crate::iface_addr::snapshot_ns(net_ns).iter()
            .any(|row| row.iface == iface && row.addr == dst) };
        if !assigned_dst { return Ok(()); }
        let driver = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !driver.live() { return Err(NetError::Enodev); }
        let queued_due = {
            let mut all = self.v4_mcast.lock();
            let mut queued_due = false;
            if q.group.is_unspecified() && version < 3 {
                let groups = all.entry(iface).or_default();
                if !groups.iter().any(|state| state.iface_generation() == iface_generation) {
                    groups.push(V4IfaceGroup::new(iface_generation, Ipv4Addr::ANY, Ipv4Addr::ANY));
                }
            }
            if let Some(groups) = all.get_mut(&iface) {
                if q.group.is_unspecified() { if let Some(state) = groups.iter()
                    .find(|state| state.iface_generation() == iface_generation) {
                    state.observe_general_query(q.qrv, q.qqic, q.max_resp_ns(), version, now_ns);
                }}
                for state in groups.iter_mut().filter(|state| state.iface_generation() == iface_generation) {
                    if state.is_empty() || state.group == IPV4_ALL_HOSTS { continue; }
                    if !q.group.is_unspecified() && q.group != state.group { continue; }
                    state.queue_query(version, &q.sources, q.max_resp_ns(), now_ns,
                        crate::mcast_state::query_random());
                    queued_due |= state.queries.first().is_some_and(|query| query.deadline_ns <= now_ns);
                }
            }
            queued_due
        };
        if queued_due { self.finish_v4_multicast(Some(V4ReportWork {
            owner, iface, iface_generation, driver, now_ns,
        })); }
        Ok(())
    }
}
