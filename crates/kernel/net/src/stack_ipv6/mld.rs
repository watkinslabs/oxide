use crate::addr::Ipv6Addr;
use crate::addr::NetIfaceId;
use crate::mcast_filter::{FilterMode, SourceFilter6};
use crate::mcast_state::{V6Change, V6IfaceGroup, V6ReportWork};
use crate::netdev::{NetError, NetResult};
use crate::stack::NetStack;
fn report_owner(net_ns: u64) -> Option<network_namespace::NetworkNamespaceRef> {
    if net_ns == 0 { Some(network_namespace::initial()) }
    else { network_namespace::lookup_u64(net_ns) }
}
impl NetStack {
    pub(crate) fn finish_v6_multicast(&self, work: Option<V6ReportWork>) {
        let Some(work) = work else { return };
        self.drive_mld_reports(work);
    }
    /// Prefer the interface link-local address required for MLD reports. # C: O(N)
    pub(crate) fn mld_src_on_iface(&self, iface: NetIfaceId) -> Option<Ipv6Addr> {
        self.mld_src_on_iface_current(iface)
    }
    fn mld_src_on_iface_current(&self, iface: NetIfaceId) -> Option<Ipv6Addr> {
        let now_ns = self.ra_now_ns();
        let addrs = self.v6_addrs.lock();
        addrs.get(&iface).and_then(|entries| entries.iter()
            .filter(|entry| entry.usable_at(now_ns))
            .find(|entry| entry.addr.is_link_local() && entry.preferred_at(now_ns))
            .or_else(|| entries.iter().filter(|entry| entry.usable_at(now_ns))
                .find(|entry| entry.addr.is_link_local()))
            .map(|entry| entry.addr))
    }
    /// Enqueue current-state reports after a link-local address completes DAD. # C: O(N groups)
    pub(crate) fn mld_link_local_dad_complete(&self, iface: NetIfaceId,
                                               expected_generation: u64, addr: Ipv6Addr) {
        if !addr.is_link_local() { return; }
        let Some(lease) = self.ifaces.acquire_ingress(iface) else { return };
        if lease.generation() != expected_generation { return; }
        let now_ns = crate::stack::net_now_ns();
        if !self.v6_addrs.lock().get(&iface).is_some_and(|rows| rows.iter().any(|row|
            row.addr == addr && row.usable_at(now_ns))) { return; }
        let net_ns = lease.net_ns();
        let Some(driver) = self.ifaces.mcast_report_in_ns(iface, net_ns).filter(|driver|
            driver.live()) else { return };
        let queued = {
            let mut all = self.v6_mcast.lock();
            let Some(groups) = all.get_mut(&iface) else { return };
            let mut queued = false;
            for state in groups.iter_mut().filter(|state| state.iface_generation() == expected_generation
                && !state.is_empty() && state.group != crate::ndp::IPV6_ALL_NODES) {
                state.report_src = addr;
                state.queue_query(state.report_version(now_ns), &[], 0, now_ns, 0);
                queued = true;
            }
            queued
        };
        if queued { self.finish_v6_multicast(Some(V6ReportWork { owner: lease.namespace(), iface,
            iface_generation: expected_generation, driver, now_ns })); }
    }
    fn emit_mld_policy(&self, net_ns: u64, iface: NetIfaceId, src: Ipv6Addr, include: u8, exclude: u8,
                       group: Ipv6Addr, filter: &SourceFilter6) -> NetResult<()> {
        let record = match filter.mode { FilterMode::Include => include, FilterMode::Exclude => exclude };
        self.emit_mldv2(net_ns, iface, src, &[(record, group, filter.sources.as_slice())])
    }
    fn emit_mld_change(&self, net_ns: u64, iface: NetIfaceId, iface_generation: u64,
                       src: Ipv6Addr, group: Ipv6Addr,
                       change: &V6Change) -> NetResult<()> {
        if change.records.is_empty() { return Ok(()); }
        let version = self.v6_mcast.lock().get(&iface).and_then(|groups| groups.iter()
            .find(|state| state.iface_generation() == iface_generation)).map(|state|
                state.report_version(crate::stack::net_now_ns())).unwrap_or(2);
        if version == 1 {
            return match change.report {
                crate::mcast_state::V6Report::Active(_) => {
                    let body = crate::icmpv6::build_mldv1_report(src, group);
                    self.emit_mld_body(net_ns, iface, src, group, &body)
                }
                crate::mcast_state::V6Report::Tomb => {
                    let body = crate::icmpv6::build_mldv1_done(src, group);
                    self.emit_mld_body(net_ns, iface, src, crate::ndp::IPV6_ALL_ROUTERS, &body)
                }
            };
        }
        let records: alloc::vec::Vec<_> = change.records.iter()
            .map(|record| (record.record_type, group, record.sources.as_slice())).collect();
        self.emit_mldv2(net_ns, iface, src, &records)
    }
    fn advance_mld_change(&self, iface: NetIfaceId, iface_generation: u64,
                          group: Ipv6Addr, generation: u64,
                          attempted: &crate::mcast_state::V6Change,
                          delivered: bool, now_ns: u64) -> bool {
        let mut all = self.v6_mcast.lock();
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
    fn transmit_mld_change(&self, net_ns: u64, iface: NetIfaceId, iface_generation: u64,
                           group: Ipv6Addr, generation: u64, change: &crate::mcast_state::V6Change,
                           now_ns: u64) {
        let current = self.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
            .any(|state| state.iface_generation() == iface_generation && state.group == group
                && state.generation == generation
                && state.change.is_some()));
        if !current { return; }
        let src = self.mld_src_on_iface_current(iface).unwrap_or(Ipv6Addr::ANY);
        let delivered = self.emit_mld_change(net_ns, iface, iface_generation, src, group, change).is_ok();
        self.advance_mld_change(iface, iface_generation, group, generation, change, delivered, now_ns);
    }
    fn transmit_mld_query(&self, net_ns: u64, iface: NetIfaceId, iface_generation: u64,
                          now_ns: u64) -> bool {
        let pending = {
            let mut all = self.v6_mcast.lock();
            let Some(groups) = all.get_mut(&iface) else { return false };
            let Some(state) = groups.iter_mut().find(|state| state.iface_generation() == iface_generation
                && state.queries.first().is_some_and(|query| query.deadline_ns <= now_ns))
                else { return false };
            let query = state.queries.remove(0);
            if query.generation != state.generation { return true; }
            (state.group, state.aggregate(), query)
        };
        let (group, aggregate, query) = pending;
        let src = self.mld_src_on_iface_current(iface).unwrap_or(Ipv6Addr::ANY);
        if query.version == 1 {
            let body = crate::icmpv6::build_mldv1_report(src, group);
            let _ = self.emit_mld_body(net_ns, iface, src, group, &body);
        } else {
            let general = query.sources.is_empty();
            let (mode, sources) = if general {
                let mode = match aggregate.mode {
                    FilterMode::Include => crate::icmpv6::MLDV2_RECORD_MODE_IS_INCLUDE,
                    FilterMode::Exclude => crate::icmpv6::MLDV2_RECORD_MODE_IS_EXCLUDE,
                };
                (mode, aggregate.sources)
            } else {
                let mut wanted = alloc::vec::Vec::new();
                for queried in query.sources {
                    let listed = aggregate.sources.contains(&queried);
                    let accepted = match aggregate.mode { FilterMode::Include => listed, FilterMode::Exclude => !listed };
                    if accepted && !wanted.contains(&queried) { wanted.push(queried); }
                }
                (crate::icmpv6::MLDV2_RECORD_MODE_IS_INCLUDE, wanted)
            };
            if !sources.is_empty() || general {
                let _ = self.emit_mldv2(net_ns, iface, src, &[(mode, group, sources.as_slice())]);
            }
        }
        true
    }
    fn drive_mld_reports(&self, work: V6ReportWork) {
        let V6ReportWork { owner, iface, iface_generation, driver, now_ns } = work;
        let net_ns = owner.id().as_u64();
        if !driver.live() { return; }
        if !driver.try_v6() { return; }
        loop {
            let drive_now = now_ns.max(crate::stack::net_now_ns());
            if !driver.live() { driver.release_v6(); return; }
            let pending = self.v6_mcast.lock().get(&iface).and_then(|groups| groups.iter()
                .filter(|state| state.iface_generation() == iface_generation)
                .find_map(|state| state.change.as_ref().filter(|change| change.due(drive_now))
                    .map(|change| (state.group, state.generation, change.clone()))));
            let Some((group, generation, change)) = pending else {
                if self.transmit_mld_query(net_ns, iface, iface_generation, drive_now) { continue; }
                driver.release_v6();
                let due = self.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
                    .any(|state| state.iface_generation() == iface_generation
                        && (state.change.as_ref().is_some_and(|change|
                            change.due(now_ns.max(crate::stack::net_now_ns())))
                            || state.queries.first().is_some_and(|query|
                                query.deadline_ns <= now_ns.max(crate::stack::net_now_ns())))));
                if !due || !driver.try_v6() { return; }
                continue;
            };
            if !driver.live() { driver.release_v6(); return; }
            self.transmit_mld_change(net_ns, iface, iface_generation, group, generation,
                &change, drive_now);
        }
    }
    fn discard_mld_change(&self, iface: NetIfaceId, iface_generation: u64,
                          group: Ipv6Addr, generation: u64) {
        let mut all = self.v6_mcast.lock();
        let Some(groups) = all.get_mut(&iface) else { return };
        let Some(index) = groups.iter().position(|state| state.iface_generation() == iface_generation
            && state.group == group) else { return };
        if groups[index].generation != generation { return; }
        groups[index].change = None;
        if groups[index].is_empty() { groups.remove(index); }
        if groups.is_empty() { all.remove(&iface); }
    }
    /// Publish one socket's full MLDv2 filter and emit resulting interface state. # C: O(N * S)
    pub(crate) fn set_ipv6_multicast(&self, owner: usize, iface: NetIfaceId, group: Ipv6Addr,
                                     src: Ipv6Addr, filter: Option<&SourceFilter6>) -> NetResult<()> {
        self.set_ipv6_multicast_in(0, owner, iface, group, src, filter)
    }
    /// Publish socket MLD policy in one network namespace. # C: O(N * S)
    pub(crate) fn set_ipv6_multicast_in(&self, net_ns: u64, owner: usize,
                                        iface: NetIfaceId, group: Ipv6Addr,
                                        src: Ipv6Addr, filter: Option<&SourceFilter6>) -> NetResult<()> {
        let report_owner = report_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = self.rtnl_lock();
        let generation = self.multicast_generation_in(&rtnl, net_ns, iface)?;
        let work = self.set_ipv6_multicast_rtnl(&rtnl, &report_owner, net_ns, generation, owner, iface,
            group, src, filter)?;
        drop(rtnl);
        self.finish_v6_multicast(work);
        Ok(())
    }
    pub(crate) fn set_ipv6_multicast_rtnl(&self, rtnl: &crate::RtnlGuard<'_>,
                                          report_owner: &network_namespace::NetworkNamespaceRef,
                                          net_ns: u64,
                                          expected_generation: u64, owner: usize,
                                          iface: NetIfaceId, group: Ipv6Addr, src: Ipv6Addr,
                                          filter: Option<&SourceFilter6>)
        -> NetResult<Option<V6ReportWork>>
    {
        if !group.is_multicast() { return Err(NetError::Einval); }
        if report_owner.id().as_u64() != net_ns { return Err(NetError::Enodev); }
        let generation = self.multicast_generation_in(rtnl, net_ns, iface)?;
        if generation != expected_generation { return Err(NetError::Enodev); }
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let src = if src.is_link_local() { src }
            else { self.mld_src_on_iface_current(iface).unwrap_or(Ipv6Addr::ANY) };
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v6_mcast.lock();
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
                None => { groups.push(V6IfaceGroup::inherited(groups, generation, group, src)); groups.len() - 1 }
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
        if group == crate::ndp::IPV6_ALL_NODES {
            self.discard_mld_change(iface, expected_generation, group, generation); return Ok(None);
        }
        Ok(Some(V6ReportWork { owner: report_owner.clone(), iface, iface_generation: expected_generation,
            driver: report, now_ns }))
    }
    /// Remove dead socket policy and retain only a compact failed report. # C: O(N)
    pub(crate) fn release_ipv6_multicast(&self, owner: usize, iface: NetIfaceId,
                                         group: Ipv6Addr, _src: Ipv6Addr) {
        let Some(net_ns) = self.ifaces.namespace(iface) else { return };
        let Some(report_owner) = report_owner(net_ns) else { return };
        let rtnl = self.rtnl_lock();
        let Ok(generation) = self.multicast_generation_in(&rtnl, net_ns, iface) else { return };
        let work = self.release_ipv6_multicast_rtnl(&rtnl, Some(&report_owner), net_ns, generation,
            owner, iface, group);
        drop(rtnl);
        self.finish_v6_multicast(work);
    }
    pub(crate) fn release_ipv6_multicast_rtnl(&self, rtnl: &crate::RtnlGuard<'_>,
                                               report_owner: Option<&network_namespace::NetworkNamespaceRef>,
                                               net_ns: u64,
                                               expected_generation: u64, owner: usize,
                                               iface: NetIfaceId, group: Ipv6Addr)
        -> Option<V6ReportWork>
    {
        if self.multicast_generation_in(rtnl, net_ns, iface).ok() != Some(expected_generation) {
            return None;
        }
        if report_owner.is_some_and(|owner| owner.id().as_u64() != net_ns) { return None; }
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns);
        let now_ns = crate::stack::net_now_ns();
        let snapshot = {
            let mut all = self.v6_mcast.lock();
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
        if group == crate::ndp::IPV6_ALL_NODES {
            self.discard_mld_change(iface, expected_generation, group, generation); return None;
        }
        let report = report.filter(|report| report.live())?;
        Some(V6ReportWork { owner: report_owner?.clone(), iface, iface_generation: expected_generation,
            driver: report, now_ns })
    }
    fn emit_mldv2(&self, net_ns: u64, iface: NetIfaceId, src: Ipv6Addr,
                  records: &[(u8, Ipv6Addr, &[Ipv6Addr])]) -> NetResult<()> {
        let body = crate::icmpv6::build_mldv2_records(src, records);
        self.emit_mld_body(net_ns, iface, src, crate::icmpv6::IPV6_MLDV2_ROUTERS, &body)
    }
    fn emit_mld_body(&self, net_ns: u64, iface: NetIfaceId, src: Ipv6Addr, dst: Ipv6Addr,
                     body: &[u8]) -> NetResult<()> {
        let dev = self.ifaces.acquire_egress_in_ns(iface, net_ns).ok_or(NetError::Enetunreach)?;
        let extension_len = 8usize;
        let payload_len = extension_len + body.len();
        let total = crate::ipv6::IPV6_HDR_LEN + payload_len;
        if total > dev.mtu() as usize || payload_len > u16::MAX as usize { return Err(NetError::Enobufs); }
        let mut packet = crate::Pkt::with_capacity(crate::ipv6::IPV6_HDR_LEN, total);
        let payload = packet.put(payload_len).map_err(|_| NetError::Enobufs)?;
        payload[..8].copy_from_slice(&[58, 0, 5, 2, 0, 0, 1, 0]);
        payload[8..].copy_from_slice(body);
        let header = packet.push(crate::ipv6::IPV6_HDR_LEN).map_err(|_| NetError::Enobufs)?;
        let mut ipv6 = crate::ipv6::Ipv6Hdr::build(src, dst,
            crate::addr::IpProto::Raw, payload_len as u16);
        ipv6.next_header = 0;
        ipv6.hop_limit = 1;
        ipv6.write_to(header);
        packet.proto = crate::addr::eth_p::IPV6;
        packet.iface = Some(iface);
        if !crate::netfilter_hook::nf_output(&packet, crate::netfilter_hook::NFPROTO_IPV6) { return Ok(()); }
        dev.xmit(packet)
    }
    pub fn join_ipv6_multicast(&self, iface: NetIfaceId, group: Ipv6Addr, src: Ipv6Addr) -> NetResult<()> {
        self.join_ipv6_multicast_in(0, iface, group, src)
    }
    /// Join an IPv6 multicast group in one network namespace. # C: O(N)
    pub fn join_ipv6_multicast_in(&self, net_ns: u64, iface: NetIfaceId,
                                  group: Ipv6Addr, src: Ipv6Addr) -> NetResult<()> {
        let owner = report_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = self.rtnl_lock();
        if !group.is_multicast() { return Err(NetError::Einval); }
        let iface_generation = self.multicast_generation_in(&rtnl, net_ns, iface)?;
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let src = if src.is_link_local() { src }
            else { self.mld_src_on_iface_current(iface).unwrap_or(Ipv6Addr::ANY) };
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v6_mcast.lock();
            let groups = all.entry(iface).or_default();
            let index = match groups.iter().position(|state| state.iface_generation() == iface_generation
                && state.group == group) {
                Some(index) => index,
                None => { groups.push(V6IfaceGroup::inherited(groups, iface_generation, group, src)); groups.len() - 1 }
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
        if group == crate::ndp::IPV6_ALL_NODES {
            self.discard_mld_change(iface, iface_generation, group, generation); return Ok(());
        }
        let work = Some(V6ReportWork { owner, iface, iface_generation, driver: report, now_ns });
        drop(rtnl);
        self.finish_v6_multicast(work);
        Ok(())
    }
    pub fn leave_ipv6_multicast(&self, iface: NetIfaceId, group: Ipv6Addr, _src: Ipv6Addr) -> NetResult<()> {
        self.leave_ipv6_multicast_in(0, iface, group, _src)
    }
    /// Leave an IPv6 multicast group in one network namespace. # C: O(N)
    pub fn leave_ipv6_multicast_in(&self, net_ns: u64, iface: NetIfaceId,
                                   group: Ipv6Addr, _src: Ipv6Addr) -> NetResult<()> {
        let owner = report_owner(net_ns).ok_or(NetError::Enodev)?;
        let rtnl = self.rtnl_lock();
        let iface_generation = self.multicast_generation_in(&rtnl, net_ns, iface)?;
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v6_mcast.lock();
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
        if group == crate::ndp::IPV6_ALL_NODES {
            self.discard_mld_change(iface, iface_generation, group, generation); return Ok(());
        }
        let work = Some(V6ReportWork { owner, iface, iface_generation, driver: report, now_ns });
        drop(rtnl);
        self.finish_v6_multicast(work);
        Ok(())
    }
    pub(crate) fn retry_mld_reports(&self, now_ns: u64) {
        let pending = {
            let all = self.v6_mcast.lock();
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
            self.finish_v6_multicast(Some(V6ReportWork {
                owner, iface, iface_generation, driver, now_ns,
            }));
        }
    }
    pub fn respond_mld_query(&self, iface: NetIfaceId, dst: Ipv6Addr,
                             q: crate::icmpv6::Mldv1Query, v1: bool) -> NetResult<()> {
        let net_ns = self.ifaces.namespace(iface).ok_or(NetError::Enodev)?;
        let owner = report_owner(net_ns).ok_or(NetError::Enodev)?;
        if !q.group.is_unspecified() && !q.group.is_multicast() { return Ok(()); }
        let now_ns = crate::stack::net_now_ns();
        let version = if v1 { 1 } else { 2 };
        // No RTNL here: this runs in the NetRx softirq (W1-b).
        let iface_generation = self.multicast_generation_rx(net_ns, iface)?;
        let assigned_dst = if dst.is_multicast() {
            dst == crate::ndp::IPV6_ALL_NODES
                || self.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter().any(|state|
                    state.iface_generation() == iface_generation && state.group == dst && !state.is_empty()))
                || self.v6_addrs.lock().get(&iface).is_some_and(|rows| rows.iter().any(|row|
                    row.valid_at(now_ns) && crate::ndp::solicited_node_multicast(row.addr) == dst))
        } else { self.v6_addrs.lock().get(&iface).is_some_and(|rows| rows.iter()
            .any(|row| row.addr == dst && row.usable_at(now_ns))) };
        if !assigned_dst { return Ok(()); }
        let driver = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !driver.live() { return Err(NetError::Enodev); }
        let queued_due = {
            let mut all = self.v6_mcast.lock();
            let mut queued_due = false;
            if q.group.is_unspecified() && version == 1 {
                let groups = all.entry(iface).or_default();
                if !groups.iter().any(|state| state.iface_generation() == iface_generation) {
                    groups.push(V6IfaceGroup::new(iface_generation, Ipv6Addr::ANY, Ipv6Addr::ANY));
                }
            }
            if let Some(groups) = all.get_mut(&iface) {
                if q.group.is_unspecified() { if let Some(state) = groups.iter().find(|state|
                    state.iface_generation() == iface_generation) {
                    state.observe_general_query(q.qrv, q.qqic, q.max_resp_ns(), version, now_ns);
                }}
                for state in groups.iter_mut().filter(|state| state.iface_generation() == iface_generation) {
                    if state.is_empty() || state.group == crate::ndp::IPV6_ALL_NODES { continue; }
                    if !q.group.is_unspecified() && q.group != state.group { continue; }
                    state.queue_query(version, &q.sources, q.max_resp_ns(), now_ns,
                        crate::mcast_state::query_random());
                    queued_due |= state.queries.first().is_some_and(|query| query.deadline_ns <= now_ns);
                }
            }
            queued_due
        };
        if queued_due { self.finish_v6_multicast(Some(V6ReportWork {
            owner, iface, iface_generation, driver, now_ns,
        })); }
        Ok(())
    }
}
