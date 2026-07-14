use crate::addr::Ipv6Addr;
use crate::addr::NetIfaceId;
use crate::mcast_filter::{FilterMode, SourceFilter6};
use crate::mcast_state::{V6Change, V6IfaceGroup};
use crate::netdev::{NetError, NetResult};
use crate::stack::NetStack;

impl NetStack {
    /// Prefer the interface link-local address required for MLD reports. # C: O(N)
    pub(crate) fn mld_src_on_iface(&self, iface: NetIfaceId) -> Option<Ipv6Addr> {
        let addrs = self.v6_addrs.lock();
        addrs.get(&iface).and_then(|entries| entries.iter().find(|entry| entry.addr.is_link_local())
            .or_else(|| entries.first()).map(|entry| entry.addr))
    }

    fn emit_mld_policy(&self, iface: NetIfaceId, src: Ipv6Addr, include: u8, exclude: u8,
                       group: Ipv6Addr, filter: &SourceFilter6) -> NetResult<()> {
        let record = match filter.mode { FilterMode::Include => include, FilterMode::Exclude => exclude };
        self.emit_mldv2(iface, src, &[(record, group, filter.sources.as_slice())])
    }

    fn emit_mld_change(&self, iface: NetIfaceId, src: Ipv6Addr, group: Ipv6Addr,
                       change: &V6Change) -> NetResult<()> {
        if change.records.is_empty() { return Ok(()); }
        let version = self.v6_mcast.lock().get(&iface).and_then(|groups| groups.iter()
            .find(|state| state.group == group)).map(|state|
                state.report_version(crate::stack::net_now_ns())).unwrap_or(2);
        if version == 1 {
            return match change.report {
                crate::mcast_state::V6Report::Active(_) => {
                    let body = crate::icmpv6::build_mldv1_report(src, group);
                    self.emit_mld_body(iface, src, group, &body)
                }
                crate::mcast_state::V6Report::Tomb => {
                    let body = crate::icmpv6::build_mldv1_done(src, group);
                    self.emit_mld_body(iface, src, crate::ndp::IPV6_ALL_ROUTERS, &body)
                }
            };
        }
        let records: alloc::vec::Vec<_> = change.records.iter()
            .map(|record| (record.record_type, group, record.sources.as_slice())).collect();
        self.emit_mldv2(iface, src, &records)
    }

    fn advance_mld_change(&self, iface: NetIfaceId, group: Ipv6Addr, generation: u64,
                          attempted: &crate::mcast_state::V6Change,
                          delivered: bool, now_ns: u64) -> bool {
        let mut all = self.v6_mcast.lock();
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

    fn transmit_mld_change(&self, iface: NetIfaceId, src: Ipv6Addr, group: Ipv6Addr,
                           generation: u64, change: &crate::mcast_state::V6Change,
                           now_ns: u64) {
        let current = self.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
            .any(|state| state.group == group && state.generation == generation
                && state.change.is_some()));
        if !current { return; }
        let delivered = self.emit_mld_change(iface, src, group, change).is_ok();
        self.advance_mld_change(iface, group, generation, change, delivered, now_ns);
    }

    fn drive_mld_reports(&self, iface: NetIfaceId, now_ns: u64) {
        let Some(driver) = self.ifaces.mcast_report(iface) else {
            self.v6_mcast.lock().remove(&iface); return;
        };
        if !driver.live() { self.v6_mcast.lock().remove(&iface); return; }
        if !driver.try_v6() { return; }
        loop {
            let drive_now = now_ns.max(crate::stack::net_now_ns());
            if !driver.live() { self.v6_mcast.lock().remove(&iface); driver.release_v6(); return; }
            let pending = self.v6_mcast.lock().get(&iface).and_then(|groups| groups.iter()
                .find_map(|state| state.change.as_ref().filter(|change| change.due(drive_now))
                    .map(|change| (state.group, state.report_src, state.generation, change.clone()))));
            let Some((group, src, generation, change)) = pending else {
                driver.release_v6();
                let due = self.v6_mcast.lock().get(&iface).is_some_and(|groups| groups.iter()
                    .any(|state| state.change.as_ref().is_some_and(|change| {
                        change.due(now_ns.max(crate::stack::net_now_ns()))
                    })));
                if !due || !driver.try_v6() { return; }
                continue;
            };
            self.transmit_mld_change(iface, src, group, generation, &change, drive_now);
        }
    }

    fn discard_mld_change(&self, iface: NetIfaceId, group: Ipv6Addr, generation: u64) {
        let mut all = self.v6_mcast.lock();
        let Some(groups) = all.get_mut(&iface) else { return };
        let Some(index) = groups.iter().position(|state| state.group == group) else { return };
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
        if !group.is_multicast() { return Err(NetError::Einval); }
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let src = if src.is_unspecified() { self.mld_src_on_iface(iface).unwrap_or(src) } else { src };
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v6_mcast.lock();
            if filter.is_none() && !all.get(&iface).is_some_and(|groups| {
                groups.iter().any(|state| state.group == group)
            }) { return Err(NetError::Eaddrnotavail); }
            let groups = if filter.is_some() { all.entry(iface).or_default() }
                else { all.get_mut(&iface).ok_or(NetError::Eaddrnotavail)? };
            let index = groups.iter().position(|state| state.group == group);
            let index = match index {
                Some(index) => index,
                None => { groups.push(V6IfaceGroup::new(group, src)); groups.len() - 1 }
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
        if !report.live() { self.v6_mcast.lock().remove(&iface); return Err(NetError::Enodev); }
        let Some((_report_src, generation)) = staged else { return Ok(()) };
        if group == crate::ndp::IPV6_ALL_NODES {
            self.discard_mld_change(iface, group, generation); return Ok(());
        }
        self.drive_mld_reports(iface, now_ns);
        Ok(())
    }

    /// Remove dead socket policy and retain only a compact failed report. # C: O(N)
    pub(crate) fn release_ipv6_multicast(&self, owner: usize, iface: NetIfaceId,
                                         group: Ipv6Addr, _src: Ipv6Addr) {
        let report = self.ifaces.mcast_report(iface);
        let now_ns = crate::stack::net_now_ns();
        let snapshot = {
            let mut all = self.v6_mcast.lock();
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
        if group == crate::ndp::IPV6_ALL_NODES { self.discard_mld_change(iface, group, generation); return; }
        if report.as_ref().is_some_and(|report| report.live()) {
            self.drive_mld_reports(iface, now_ns);
        } else { self.v6_mcast.lock().remove(&iface); }
    }

    fn emit_mldv2(&self, iface: NetIfaceId, src: Ipv6Addr,
                  records: &[(u8, Ipv6Addr, &[Ipv6Addr])]) -> NetResult<()> {
        let body = crate::icmpv6::build_mldv2_records(src, records);
        self.emit_mld_body(iface, src, crate::icmpv6::IPV6_MLDV2_ROUTERS, &body)
    }

    fn emit_mld_body(&self, iface: NetIfaceId, src: Ipv6Addr, dst: Ipv6Addr,
                     body: &[u8]) -> NetResult<()> {
        let net_ns = self.ifaces.namespace(iface).ok_or(NetError::Enetunreach)?;
        let dev = self.ifaces.lookup_in_ns(iface, net_ns).ok_or(NetError::Enetunreach)?;
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
        if !group.is_multicast() { return Err(NetError::Einval); }
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let src = if src.is_unspecified() { self.mld_src_on_iface(iface).unwrap_or(src) } else { src };
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v6_mcast.lock();
            let groups = all.entry(iface).or_default();
            let index = match groups.iter().position(|state| state.group == group) {
                Some(index) => index,
                None => { groups.push(V6IfaceGroup::new(group, src)); groups.len() - 1 }
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
        if !report.live() { self.v6_mcast.lock().remove(&iface); return Err(NetError::Enodev); }
        let Some((_report_src, generation)) = staged else { return Ok(()) };
        if group == crate::ndp::IPV6_ALL_NODES {
            self.discard_mld_change(iface, group, generation); return Ok(());
        }
        self.drive_mld_reports(iface, now_ns);
        Ok(())
    }

    pub fn leave_ipv6_multicast(&self, iface: NetIfaceId, group: Ipv6Addr, _src: Ipv6Addr) -> NetResult<()> {
        self.leave_ipv6_multicast_in(0, iface, group, _src)
    }

    /// Leave an IPv6 multicast group in one network namespace. # C: O(N)
    pub fn leave_ipv6_multicast_in(&self, net_ns: u64, iface: NetIfaceId,
                                   group: Ipv6Addr, _src: Ipv6Addr) -> NetResult<()> {
        let report = self.ifaces.mcast_report_in_ns(iface, net_ns).ok_or(NetError::Enodev)?;
        if !report.live() { return Err(NetError::Enodev); }
        let now_ns = crate::stack::net_now_ns();
        let staged = {
            let mut all = self.v6_mcast.lock();
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
        if !report.live() { self.v6_mcast.lock().remove(&iface); return Err(NetError::Enodev); }
        let Some(generation) = staged else { return Ok(()) };
        if group == crate::ndp::IPV6_ALL_NODES {
            self.discard_mld_change(iface, group, generation); return Ok(());
        }
        self.drive_mld_reports(iface, now_ns);
        Ok(())
    }

    pub(crate) fn retry_mld_reports(&self, now_ns: u64) {
        let pending = {
            let all = self.v6_mcast.lock();
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
            self.drive_mld_reports(iface, now_ns);
        }
    }

    pub fn respond_mld_query(&self, iface: NetIfaceId, q: crate::icmpv6::Mldv1Query,
                             v1: bool) -> NetResult<()> {
        let now_ns = crate::stack::net_now_ns();
        let version = if v1 { 1 } else { 2 };
        let groups = {
            let mut all = self.v6_mcast.lock();
            if let Some(groups) = all.get_mut(&iface) {
                for state in groups.iter_mut() {
                    state.observe_query(q.qrv, q.qqic, q.max_resp_ns(), version, now_ns);
                }
            }
            all.get(&iface).cloned().unwrap_or_default()
        };
        let src = self.mld_src_on_iface(iface).unwrap_or(Ipv6Addr::ANY);
        for state in groups {
            if state.is_empty() || state.group == crate::ndp::IPV6_ALL_NODES { continue; }
            if !q.group.is_unspecified() && q.group != state.group { continue; }
            if v1 {
                let body = crate::icmpv6::build_mldv1_report(src, state.group);
                self.emit_mld_body(iface, src, state.group, &body)?;
                continue;
            }
            let aggregate = state.aggregate();
            let (mode, sources) = if q.sources.is_empty() {
                let mode = match aggregate.mode {
                    FilterMode::Include => crate::icmpv6::MLDV2_RECORD_MODE_IS_INCLUDE,
                    FilterMode::Exclude => crate::icmpv6::MLDV2_RECORD_MODE_IS_EXCLUDE,
                };
                (mode, aggregate.sources)
            } else {
                let mut wanted = alloc::vec::Vec::new();
                for queried in &q.sources {
                    let listed = aggregate.sources.contains(queried);
                    let accepted = match aggregate.mode { FilterMode::Include => listed, FilterMode::Exclude => !listed };
                    if accepted && !wanted.contains(queried) { wanted.push(*queried); }
                }
                if wanted.is_empty() { continue; }
                (crate::icmpv6::MLDV2_RECORD_MODE_IS_INCLUDE, wanted)
            };
            self.emit_mldv2(iface, src, &[(mode, state.group, sources.as_slice())])?;
        }
        Ok(())
    }
}
