use super::*;

impl NetStack {
    pub(crate) fn finish_v4_multicast(&self, work: Option<V4ReportWork>) {
        let Some(work) = work else { return };
        self.drive_v4_reports(work);
    }
    pub(super) fn v4_src_on_iface(&self, net_ns: u64, iface: NetIfaceId) -> Option<Ipv4Addr> {
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
    pub(super) fn discard_v4_change(&self, iface: NetIfaceId, iface_generation: u64,
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
}
