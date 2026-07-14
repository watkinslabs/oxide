use crate::addr::{Ipv4Addr, NetIfaceId};
use crate::igmp::{
    IgmpQuery, IGMP_V3_RECORD_MODE_IS_EXCLUDE, IGMP_V3_RECORD_MODE_IS_INCLUDE,
    IPV4_ALL_HOSTS, IPV4_ALL_ROUTERS, IPV4_IGMPV3_ROUTERS,
};
use crate::mcast_filter::{FilterMode, SourceFilter};
use crate::mcast_state::{V4Change, V4IfaceGroup};
use crate::netdev::{NetError, NetResult};
use crate::stack::NetStack;

const IGMP_TYPE_V1_REPORT: u8 = 0x12;

fn report_owner(net_ns: u64) -> Option<network_namespace::NetworkNamespaceRef> {
    if net_ns == 0 { Some(network_namespace::initial()) }
    else { network_namespace::lookup_u64(net_ns) }
}

impl NetStack {
    fn v4_src_on_iface(&self, net_ns: u64, iface: NetIfaceId) -> Option<Ipv4Addr> {
        self.routes.snapshot_in(net_ns).into_iter().find(|r| r.iface == iface).and_then(|r| r.src_hint)
    }

    fn emit_v4_policy(&self, net_ns: u64, iface: NetIfaceId, src: Ipv4Addr, record_include: u8,
                      record_exclude: u8, group: Ipv4Addr, filter: &SourceFilter) -> NetResult<()> {
        let record = match filter.mode { FilterMode::Include => record_include, FilterMode::Exclude => record_exclude };
        self.emit_igmpv3(net_ns, iface, src, &[(record, group, filter.sources.as_slice())])
    }

    fn emit_v4_change(&self, net_ns: u64, iface: NetIfaceId, src: Ipv4Addr, group: Ipv4Addr,
                      change: &V4Change) -> NetResult<()> {
        if change.records.is_empty() { return Ok(()); }
        let version = self.v4_mcast.lock().get(&iface).and_then(|groups| groups.iter()
            .find(|state| state.group == group)).map(|state|
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

    fn advance_v4_change(&self, iface: NetIfaceId, group: Ipv4Addr, generation: u64,
                         attempted: &crate::mcast_state::V4Change,
                         delivered: bool, now_ns: u64) -> bool {
        let mut all = self.v4_mcast.lock();
        let Some(groups) = all.get_mut(&iface) else { return false };
        let Some(index) = groups.iter().position(|state| state.group == group) else { return false };
        if groups[index].generation != generation {
            groups[index].reconcile_superseded(attempted, delivered, now_ns);
            return true;
        }
        let complete = groups[index].change.as_mut()
            .is_some_and(|change| change.attempted(delivered, now_ns));
        if complete {
            groups[index].change = None;
            if groups[index].is_empty() { groups.remove(index); }
        }
        if groups.is_empty() { all.remove(&iface); }
        true
    }

    fn transmit_v4_change(&self, net_ns: u64, iface: NetIfaceId, src: Ipv4Addr,
                          group: Ipv4Addr, generation: u64,
                          change: &crate::mcast_state::V4Change, now_ns: u64) {
        let current = self.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
            .any(|state| state.group == group && state.generation == generation
                && state.change.is_some()));
        if !current { return; }
        let delivered = self.emit_v4_change(net_ns, iface, src, group, change).is_ok();
        self.advance_v4_change(iface, group, generation, change, delivered, now_ns);
    }

    fn drive_v4_reports(&self, owner: &network_namespace::NetworkNamespaceRef,
                        iface: NetIfaceId, now_ns: u64) {
        let net_ns = owner.id().as_u64();
        let Some(driver) = self.ifaces.mcast_report(iface) else {
            self.v4_mcast.lock().remove(&iface); return;
        };
        if !driver.live() { self.v4_mcast.lock().remove(&iface); return; }
        if !driver.try_v4() { return; }
        loop {
            let drive_now = now_ns.max(crate::stack::net_now_ns());
            if !driver.live() { self.v4_mcast.lock().remove(&iface); driver.release_v4(); return; }
            let pending = self.v4_mcast.lock().get(&iface).and_then(|groups| groups.iter()
                .find_map(|state| state.change.as_ref().filter(|change| change.due(drive_now))
                    .map(|change| (state.group, state.report_src, state.generation, change.clone()))));
            let Some((group, src, generation, change)) = pending else {
                driver.release_v4();
                let due = self.v4_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
                    .any(|state| state.change.as_ref().is_some_and(|change| {
                        change.due(now_ns.max(crate::stack::net_now_ns()))
                    })));
                if !due || !driver.try_v4() { return; }
                continue;
            };
            self.transmit_v4_change(net_ns, iface, src, group, generation, &change, drive_now);
        }
    }

    fn discard_v4_change(&self, iface: NetIfaceId, group: Ipv4Addr, generation: u64) {
        let mut all = self.v4_mcast.lock();
        let Some(groups) = all.get_mut(&iface) else { return };
        let Some(index) = groups.iter().position(|state| state.group == group) else { return };
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
        if !group.is_multicast() { return Err(NetError::Einval); }
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let src = if src.is_unspecified() { self.v4_src_on_iface(net_ns, iface).unwrap_or(src) } else { src };
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v4_mcast.lock();
            if filter.is_none() && !all.get(&iface).is_some_and(|groups| {
                groups.iter().any(|state| state.group == group)
            }) { return Err(NetError::Eaddrnotavail); }
            let groups = if filter.is_some() { all.entry(iface).or_default() }
                else { all.get_mut(&iface).ok_or(NetError::Eaddrnotavail)? };
            let index = groups.iter().position(|state| state.group == group);
            let index = match index {
                Some(index) => index,
                None => { groups.push(V4IfaceGroup::new(group, src)); groups.len() - 1 }
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
        if !report.live() { self.v4_mcast.lock().remove(&iface); return Err(NetError::Enodev); }
        let Some((_report_src, generation)) = staged else { return Ok(()) };
        if group == IPV4_ALL_HOSTS {
            self.discard_v4_change(iface, group, generation);
            return Ok(());
        }
        if let Some(owner) = report_owner(net_ns) { self.drive_v4_reports(&owner, iface, now_ns); }
        Ok(())
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
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns);
        let now_ns = crate::stack::net_now_ns();
        let snapshot = {
            let mut all = self.v4_mcast.lock();
            let Some(groups) = all.get_mut(&iface) else { return };
            let Some(state) = groups.iter_mut().find(|state| state.group == group) else { return };
            let prior = state.aggregate();
            if state.members.remove(&owner).is_none() { return; }
            if state.aggregate() == prior { None } else {
                let (generation, _) = state.stage(Some(&prior), now_ns);
                Some(generation)
            }
        };
        let Some(generation) = snapshot else { return };
        if group == IPV4_ALL_HOSTS { self.discard_v4_change(iface, group, generation); return; }
        if report.as_ref().is_some_and(|report| report.live()) {
            if let Some(owner) = report_owner(net_ns) { self.drive_v4_reports(&owner, iface, now_ns); }
        } else { self.v4_mcast.lock().remove(&iface); }
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
        let dev = self.ifaces.lookup_in_ns(iface, net_ns).ok_or(NetError::Enetunreach)?;
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
        if !group.is_multicast() { return Err(NetError::Einval); }
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let src = if src.is_unspecified() { self.v4_src_on_iface(net_ns, iface).unwrap_or(src) } else { src };
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v4_mcast.lock();
            let groups = all.entry(iface).or_default();
            let index = match groups.iter().position(|state| state.group == group) {
                Some(index) => index,
                None => { groups.push(V4IfaceGroup::new(group, src)); groups.len() - 1 }
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
        if !report.live() { self.v4_mcast.lock().remove(&iface); return Err(NetError::Enodev); }
        let Some((_report_src, generation)) = staged else { return Ok(()) };
        if group == IPV4_ALL_HOSTS {
            self.discard_v4_change(iface, group, generation); return Ok(());
        }
        if let Some(owner) = report_owner(net_ns) { self.drive_v4_reports(&owner, iface, now_ns); }
        Ok(())
    }

    /// Leave an IPv4 multicast group and emit a state-change report. # C: O(N groups)
    pub fn leave_ipv4_multicast(&self, iface: NetIfaceId, group: Ipv4Addr, _src: Ipv4Addr) -> NetResult<()> {
        self.leave_ipv4_multicast_in(0, iface, group, _src)
    }

    /// Leave an IPv4 multicast group in one network namespace. # C: O(N groups)
    pub fn leave_ipv4_multicast_in(&self, net_ns: u64, iface: NetIfaceId,
                                   group: Ipv4Addr, _src: Ipv4Addr) -> NetResult<()> {
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v4_mcast.lock();
            let groups = all.get_mut(&iface).ok_or(NetError::Eaddrnotavail)?;
            let state = groups.iter_mut().find(|state| state.group == group).ok_or(NetError::Eaddrnotavail)?;
            if state.asm_refs == 0 { return Err(NetError::Eaddrnotavail); }
            let before = state.aggregate();
            state.asm_refs -= 1;
            let after = state.aggregate();
            if before == after { None } else {
                let (generation, _) = state.stage(Some(&before), now_ns);
                Some(generation)
            }
        };
        if !report.live() { self.v4_mcast.lock().remove(&iface); return Err(NetError::Enodev); }
        let Some(generation) = staged else { return Ok(()) };
        if group == IPV4_ALL_HOSTS {
            self.discard_v4_change(iface, group, generation); return Ok(());
        }
        if let Some(owner) = report_owner(net_ns) { self.drive_v4_reports(&owner, iface, now_ns); }
        Ok(())
    }

    /// Retry failed IGMP/MLD state-change reports. # C: O(N groups)
    pub fn retry_multicast_reports(&self, now_ns: u64) {
        let pending = {
            let all = self.v4_mcast.lock();
            let mut pending = alloc::vec::Vec::new();
            for (iface, groups) in all.iter() { for state in groups {
                if let Some(change) = &state.change {
                    if change.due(now_ns) {
                        pending.push((*iface, state.group, state.report_src, state.generation, change.clone()));
                    }
                }
            }}
            pending
        };
        for (iface, _, _, _, _) in pending {
            let Some(net_ns) = self.ifaces.namespace(iface) else { continue };
            let Some(owner) = report_owner(net_ns) else { continue };
            self.drive_v4_reports(&owner, iface, now_ns);
        }
        self.retry_mld_reports(now_ns);
    }

    /// Handle IGMP general/group-specific queries. # C: O(N groups)
    pub(crate) fn handle_igmp(&self, iface: NetIfaceId, _src: Ipv4Addr, _dst: Ipv4Addr,
                              payload: &[u8]) -> NetResult<()> {
        let net_ns = self.ifaces.namespace(iface).ok_or(NetError::Enodev)?;
        let q = match IgmpQuery::parse(payload) { Ok(q) => q, Err(_) => return Ok(()) };
        let version = if payload.len() >= 12 { 3 } else if q.max_resp_time == 0 { 1 } else { 2 };
        let now_ns = crate::stack::net_now_ns();
        let groups = {
            let mut all = self.v4_mcast.lock();
            if let Some(groups) = all.get_mut(&iface) {
                for state in groups.iter_mut() {
                    state.observe_query(q.qrv, q.qqic, q.max_resp_ns(), version, now_ns);
                }
            }
            all.get(&iface).cloned().unwrap_or_default()
        };
        for state in groups {
            if state.is_empty() || state.group == IPV4_ALL_HOSTS { continue; }
            if !q.group.is_unspecified() && q.group != state.group { continue; }
            let aggregate = state.aggregate();
            if version < 3 {
                self.emit_igmp_legacy(net_ns, iface, state.report_src, state.group,
                    if version == 1 { IGMP_TYPE_V1_REPORT } else { crate::igmp::IGMP_TYPE_V2_REPORT },
                    state.group)?;
                continue;
            }
            if q.sources.is_empty() {
                self.emit_v4_policy(net_ns, iface, state.report_src, IGMP_V3_RECORD_MODE_IS_INCLUDE,
                    IGMP_V3_RECORD_MODE_IS_EXCLUDE, state.group, &aggregate)?;
            } else {
                let mut wanted = alloc::vec::Vec::new();
                for queried in &q.sources {
                    let listed = aggregate.sources.contains(queried);
                    let accepted = match aggregate.mode { FilterMode::Include => listed, FilterMode::Exclude => !listed };
                    if accepted && !wanted.contains(queried) { wanted.push(*queried); }
                }
                if wanted.is_empty() { continue; }
                self.emit_igmpv3(net_ns, iface, state.report_src,
                    &[(IGMP_V3_RECORD_MODE_IS_INCLUDE, state.group, wanted.as_slice())])?;
            }
        }
        Ok(())
    }
}
