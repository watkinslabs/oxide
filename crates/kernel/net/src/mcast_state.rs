use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use crate::addr::{Ipv4Addr, Ipv6Addr};
use crate::mcast_filter::{FilterMode, SourceFilter, SourceFilter6};
pub(crate) struct V4ReportWork {
    pub owner: network_namespace::NetworkNamespaceRef,
    pub iface: crate::addr::NetIfaceId,
    pub iface_generation: u64,
    pub driver: alloc::sync::Arc<crate::netdev::McastReportState>,
    pub now_ns: u64,
}
pub(crate) struct V6ReportWork {
    pub owner: network_namespace::NetworkNamespaceRef,
    pub iface: crate::addr::NetIfaceId,
    pub iface_generation: u64,
    pub driver: alloc::sync::Arc<crate::netdev::McastReportState>,
    pub now_ns: u64,
}
#[derive(Clone)]
pub(crate) struct V4Query {
    pub generation: u64,
    pub version: u8,
    pub sources: alloc::vec::Vec<Ipv4Addr>,
    pub deadline_ns: u64,
}
#[derive(Clone)]
pub(crate) struct V6Query {
    pub generation: u64,
    pub version: u8,
    pub sources: alloc::vec::Vec<Ipv6Addr>,
    pub deadline_ns: u64,
}
pub(crate) const REPORT_INTERVAL_NS: u64 = 1_000_000_000;
pub(crate) const REPORT_ROBUSTNESS: u8 = 2;
pub(crate) const DEFAULT_QUERY_INTERVAL_NS: u64 = 125_000_000_000;
const IGMP_V1_RESPONSE_INTERVAL_NS: u64 = 10_000_000_000;
#[cfg(not(test))]
static QUERY_RANDOM: AtomicU64 = AtomicU64::new(0x6a09_e667_f3bc_c909);
#[cfg(not(test))]
pub(crate) fn query_random() -> u64 {
    let mut value = QUERY_RANDOM.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed);
    value ^= value >> 30;
    value = value.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value ^= value >> 27;
    value = value.wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}
#[cfg(test)]
pub(crate) fn query_random() -> u64 { 0 }
fn query_deadline(now_ns: u64, max_resp_ns: u64, random: u64) -> u64 {
    let delay = if max_resp_ns == u64::MAX { random }
        else { random % max_resp_ns.saturating_add(1) };
    now_ns.saturating_add(delay)
}
struct IfaceCompat {
    generation: u64,
    robustness: AtomicU8,
    query_interval_ns: AtomicU64,
    v1_querier_until_ns: AtomicU64,
    v2_querier_until_ns: AtomicU64,
}
impl IfaceCompat {
    fn new(generation: u64) -> Self {
        Self { generation, robustness: AtomicU8::new(REPORT_ROBUSTNESS),
            query_interval_ns: AtomicU64::new(DEFAULT_QUERY_INTERVAL_NS),
            v1_querier_until_ns: AtomicU64::new(0), v2_querier_until_ns: AtomicU64::new(0) }
    }
    fn observe_general(&self, qrv: u8, qqic: u8, max_resp_ns: u64,
                       version: u8, now_ns: u64) {
        if qrv != 0 { self.robustness.store(qrv, Ordering::Relaxed); }
        if qqic != 0 { self.query_interval_ns.store(
            decode8(qqic).saturating_mul(1_000_000_000), Ordering::Relaxed); }
        if version > 2 { return; }
        let until = now_ns.saturating_add((self.robustness() as u64)
            .saturating_mul(self.query_interval_ns())).saturating_add(max_resp_ns);
        if version == 1 { self.v1_querier_until_ns.store(until, Ordering::Relaxed); }
        else { self.v2_querier_until_ns.store(until, Ordering::Relaxed); }
    }
    fn robustness(&self) -> u8 { self.robustness.load(Ordering::Relaxed) }
    fn query_interval_ns(&self) -> u64 { self.query_interval_ns.load(Ordering::Relaxed) }
    fn report_version(&self, newest: u8, now_ns: u64) -> u8 {
        if now_ns < self.v1_querier_until_ns.load(Ordering::Relaxed) { 1 }
        else if newest > 2 && now_ns < self.v2_querier_until_ns.load(Ordering::Relaxed) { 2 }
        else { newest }
    }
}
#[derive(Clone)]
pub(crate) struct V4Record { pub record_type: u8, pub sources: alloc::vec::Vec<Ipv4Addr> }
#[derive(Clone)]
pub(crate) struct V6Record { pub record_type: u8, pub sources: alloc::vec::Vec<Ipv6Addr> }
#[derive(Clone)]
pub(crate) enum V4Report { Active(SourceFilter), Tomb }
#[derive(Clone)]
pub(crate) enum V6Report { Active(SourceFilter6), Tomb }
#[derive(Clone)]
pub(crate) struct V4Change {
    pub base: Option<SourceFilter>,
    pub report: V4Report,
    pub records: alloc::vec::Vec<V4Record>,
    pub next_ns: u64,
    pub remaining: u8,
    pub reported: bool,
    pub fallback_base: Option<SourceFilter>,
    pub has_fallback: bool,
}
#[derive(Clone)]
pub(crate) struct V6Change {
    pub base: Option<SourceFilter6>,
    pub report: V6Report,
    pub records: alloc::vec::Vec<V6Record>,
    pub next_ns: u64,
    pub remaining: u8,
    pub reported: bool,
    pub fallback_base: Option<SourceFilter6>,
    pub has_fallback: bool,
}
/// Interface-owned IPv4 multicast policy and pending report state.
#[derive(Clone)]
pub(crate) struct V4IfaceGroup {
    compat: Arc<IfaceCompat>,
    pub group: Ipv4Addr,
    pub report_src: Ipv4Addr,
    pub asm_refs: u32,
    pub members: BTreeMap<usize, SourceFilter>,
    pub generation: u64,
    pub change: Option<V4Change>,
    pub queries: alloc::vec::Vec<V4Query>,
}
/// Interface-owned IPv6 multicast policy and pending report state.
#[derive(Clone)]
pub(crate) struct V6IfaceGroup {
    compat: Arc<IfaceCompat>,
    pub group: Ipv6Addr,
    pub report_src: Ipv6Addr,
    pub asm_refs: u32,
    pub members: BTreeMap<usize, SourceFilter6>,
    pub generation: u64,
    pub change: Option<V6Change>,
    pub queries: alloc::vec::Vec<V6Query>,
}
impl V4IfaceGroup {
    pub(crate) fn new(iface_generation: u64, group: Ipv4Addr, report_src: Ipv4Addr) -> Self {
        Self::with_compat(Arc::new(IfaceCompat::new(iface_generation)), group, report_src)
    }
    pub(crate) fn inherited(groups: &[Self], iface_generation: u64,
                            group: Ipv4Addr, report_src: Ipv4Addr) -> Self {
        let compat = groups.iter().find(|state| state.iface_generation() == iface_generation)
            .map(|state| state.compat.clone())
            .unwrap_or_else(|| Arc::new(IfaceCompat::new(iface_generation)));
        Self::with_compat(compat, group, report_src)
    }
    fn with_compat(compat: Arc<IfaceCompat>, group: Ipv4Addr, report_src: Ipv4Addr) -> Self {
        Self { compat, group, report_src, asm_refs: 0, members: BTreeMap::new(), generation: 0,
            change: None, queries: alloc::vec::Vec::new() }
    }
    pub(crate) fn iface_generation(&self) -> u64 { self.compat.generation }
    pub(crate) fn robustness(&self) -> u8 { self.compat.robustness() }
    /// Test-only readback: the querier-interval consumer is `IfaceCompat`'s own
    /// `observe_general`, which reads the atomic directly.
    #[cfg(test)]
    pub(crate) fn query_interval_ns(&self) -> u64 { self.compat.query_interval_ns() }
    pub(crate) fn observe_general_query(&self, qrv: u8, qqic: u8, max_resp_ns: u64,
                                        version: u8, now_ns: u64) {
        let response_ns = if version == 1 { IGMP_V1_RESPONSE_INTERVAL_NS } else { max_resp_ns };
        self.compat.observe_general(qrv, qqic, response_ns, version, now_ns)
    }
    pub(crate) fn aggregate(&self) -> SourceFilter {
        let mut includes = alloc::vec::Vec::new();
        let mut excludes = if self.asm_refs != 0 { Some(alloc::vec::Vec::new()) } else { None };
        for filter in self.members.values() {
            match filter.mode {
                FilterMode::Include => union4(&mut includes, &filter.sources),
                FilterMode::Exclude => match &mut excludes {
                    None => excludes = Some(filter.sources.clone()),
                    Some(common) => common.retain(|source| filter.sources.contains(source)),
                },
            }
        }
        match excludes {
            Some(mut sources) => {
                sources.retain(|source| !includes.contains(source));
                SourceFilter { mode: FilterMode::Exclude, sources }
            }
            None => SourceFilter { mode: FilterMode::Include, sources: includes },
        }
    }
    pub(crate) fn is_empty(&self) -> bool { self.asm_refs == 0 && self.members.is_empty() }
    /// Admit one IPv4 packet through this interface group's aggregate source policy.
    /// # C: O(S + M)
    pub(crate) fn admits_rx(&self, src: Ipv4Addr, proto: u8) -> bool {
        if self.is_empty() { return false; }
        if src == Ipv4Addr::ANY || proto == crate::addr::IpProto::Igmp as u8 { return true; }
        let filter = self.aggregate();
        let listed = filter.sources.contains(&src);
        match filter.mode { FilterMode::Include => listed, FilterMode::Exclude => !listed }
    }
    pub(crate) fn stage(&mut self, prior: Option<&SourceFilter>, now_ns: u64) -> (u64, V4Change) {
        self.queries.clear();
        self.generation = self.generation.wrapping_add(1);
        let report = if self.is_empty() { V4Report::Tomb } else { V4Report::Active(self.aggregate()) };
        let target = match &report {
            V4Report::Active(filter) => filter.clone(),
            V4Report::Tomb => SourceFilter { mode: FilterMode::Include, sources: alloc::vec::Vec::new() },
        };
        let (base, fallback_base, has_fallback) = match self.change.as_ref() {
            Some(change) if change.reported => (prior.cloned(), change.base.clone(), true),
            Some(change) if change.has_fallback && v4_baseline_eq(change.base.as_ref(), &target) =>
                (change.fallback_base.clone(), None, false),
            Some(change) => (change.base.clone(), change.fallback_base.clone(), change.has_fallback),
            None => (prior.cloned(), None, false),
        };
        let records = if base.is_none() && target == empty_v4() { alloc::vec::Vec::new() }
            else { v4_records(base.as_ref(), &target) };
        let remaining = if records.is_empty() { 1 } else { self.robustness() };
        let change = V4Change { base, report, records, next_ns: now_ns, remaining,
            reported: false, fallback_base, has_fallback };
        self.change = Some(change.clone());
        (self.generation, change)
    }
    pub(crate) fn reconcile_superseded(&mut self, attempted: &V4Change,
                                       delivered: bool, now_ns: u64) {
        let base = if delivered || attempted.reported { Some(v4_target(&attempted.report)) }
            else { attempted.base.clone() };
        let robustness = self.robustness();
        let Some(change) = self.change.as_mut() else { return };
        let target = v4_target(&change.report);
        change.base = base;
        change.records = v4_records(change.base.as_ref(), &target);
        change.remaining = if change.records.is_empty() { 1 } else { robustness };
        change.reported = false;
        change.fallback_base = None;
        change.has_fallback = false;
        change.next_ns = now_ns;
    }
    pub(crate) fn report_version(&self, now_ns: u64) -> u8 {
        self.compat.report_version(3, now_ns)
    }
    pub(crate) fn compatibility_active(&self, now_ns: u64) -> bool {
        self.report_version(now_ns) != 3
    }
    pub(crate) fn queue_query(&mut self, version: u8, sources: &[Ipv4Addr],
                              max_resp_ns: u64, now_ns: u64, random: u64) {
        let max_resp_ns = if version == 1 { IGMP_V1_RESPONSE_INTERVAL_NS } else { max_resp_ns };
        let next = V4Query { generation: self.generation, version, sources: sources.to_vec(),
            deadline_ns: query_deadline(now_ns, max_resp_ns, random) };
        let Some(pending) = self.queries.first_mut() else { self.queries.push(next); return };
        if pending.generation != next.generation { *pending = next; self.queries.truncate(1); return; }
        pending.deadline_ns = pending.deadline_ns.min(next.deadline_ns);
        pending.version = pending.version.min(next.version);
        if pending.version < 3 || pending.sources.is_empty() || next.sources.is_empty() {
            pending.sources.clear();
        } else {
            union4(&mut pending.sources, &next.sources);
        }
        self.queries.truncate(1);
    }
}
impl V6IfaceGroup {
    pub(crate) fn new(iface_generation: u64, group: Ipv6Addr, report_src: Ipv6Addr) -> Self {
        Self::with_compat(Arc::new(IfaceCompat::new(iface_generation)), group, report_src)
    }
    pub(crate) fn inherited(groups: &[Self], iface_generation: u64,
                            group: Ipv6Addr, report_src: Ipv6Addr) -> Self {
        let compat = groups.iter().find(|state| state.iface_generation() == iface_generation)
            .map(|state| state.compat.clone())
            .unwrap_or_else(|| Arc::new(IfaceCompat::new(iface_generation)));
        Self::with_compat(compat, group, report_src)
    }
    fn with_compat(compat: Arc<IfaceCompat>, group: Ipv6Addr, report_src: Ipv6Addr) -> Self {
        Self { compat, group, report_src, asm_refs: 0, members: BTreeMap::new(), generation: 0,
            change: None, queries: alloc::vec::Vec::new() }
    }
    pub(crate) fn iface_generation(&self) -> u64 { self.compat.generation }
    pub(crate) fn robustness(&self) -> u8 { self.compat.robustness() }
    pub(crate) fn observe_general_query(&self, qrv: u8, qqic: u8, max_resp_ns: u64,
                                        version: u8, now_ns: u64) {
        self.compat.observe_general(qrv, qqic, max_resp_ns, version, now_ns)
    }
    pub(crate) fn aggregate(&self) -> SourceFilter6 {
        let mut includes = alloc::vec::Vec::new();
        let mut excludes = if self.asm_refs != 0 { Some(alloc::vec::Vec::new()) } else { None };
        for filter in self.members.values() {
            match filter.mode {
                FilterMode::Include => union6(&mut includes, &filter.sources),
                FilterMode::Exclude => match &mut excludes {
                    None => excludes = Some(filter.sources.clone()),
                    Some(common) => common.retain(|source| filter.sources.contains(source)),
                },
            }
        }
        match excludes {
            Some(mut sources) => {
                sources.retain(|source| !includes.contains(source));
                SourceFilter6 { mode: FilterMode::Exclude, sources }
            }
            None => SourceFilter6 { mode: FilterMode::Include, sources: includes },
        }
    }
    pub(crate) fn is_empty(&self) -> bool { self.asm_refs == 0 && self.members.is_empty() }
    pub(crate) fn stage(&mut self, prior: Option<&SourceFilter6>, now_ns: u64) -> (u64, V6Change) {
        self.queries.clear();
        self.generation = self.generation.wrapping_add(1);
        let report = if self.is_empty() { V6Report::Tomb } else { V6Report::Active(self.aggregate()) };
        let target = match &report {
            V6Report::Active(filter) => filter.clone(),
            V6Report::Tomb => SourceFilter6 { mode: FilterMode::Include, sources: alloc::vec::Vec::new() },
        };
        let (base, fallback_base, has_fallback) = match self.change.as_ref() {
            Some(change) if change.reported => (prior.cloned(), change.base.clone(), true),
            Some(change) if change.has_fallback && v6_baseline_eq(change.base.as_ref(), &target) =>
                (change.fallback_base.clone(), None, false),
            Some(change) => (change.base.clone(), change.fallback_base.clone(), change.has_fallback),
            None => (prior.cloned(), None, false),
        };
        let records = if base.is_none() && target == empty_v6() { alloc::vec::Vec::new() }
            else { v6_records(base.as_ref(), &target) };
        let remaining = if records.is_empty() { 1 } else { self.robustness() };
        let change = V6Change { base, report, records, next_ns: now_ns, remaining,
            reported: false, fallback_base, has_fallback };
        self.change = Some(change.clone());
        (self.generation, change)
    }
    pub(crate) fn reconcile_superseded(&mut self, attempted: &V6Change,
                                       delivered: bool, now_ns: u64) {
        let base = if delivered || attempted.reported { Some(v6_target(&attempted.report)) }
            else { attempted.base.clone() };
        let robustness = self.robustness();
        let Some(change) = self.change.as_mut() else { return };
        let target = v6_target(&change.report);
        change.base = base;
        change.records = v6_records(change.base.as_ref(), &target);
        change.remaining = if change.records.is_empty() { 1 } else { robustness };
        change.reported = false;
        change.fallback_base = None;
        change.has_fallback = false;
        change.next_ns = now_ns;
    }
    pub(crate) fn report_version(&self, now_ns: u64) -> u8 {
        self.compat.report_version(2, now_ns)
    }
    pub(crate) fn compatibility_active(&self, now_ns: u64) -> bool {
        self.report_version(now_ns) != 2
    }
    pub(crate) fn queue_query(&mut self, version: u8, sources: &[Ipv6Addr],
                              max_resp_ns: u64, now_ns: u64, random: u64) {
        let next = V6Query { generation: self.generation, version, sources: sources.to_vec(),
            deadline_ns: query_deadline(now_ns, max_resp_ns, random) };
        let Some(pending) = self.queries.first_mut() else { self.queries.push(next); return };
        if pending.generation != next.generation { *pending = next; self.queries.truncate(1); return; }
        pending.deadline_ns = pending.deadline_ns.min(next.deadline_ns);
        pending.version = pending.version.min(next.version);
        if pending.version == 1 || pending.sources.is_empty() || next.sources.is_empty() {
            pending.sources.clear();
        } else {
            union6(&mut pending.sources, &next.sources);
        }
        self.queries.truncate(1);
    }
}
impl V4Change {
    pub(crate) fn due(&self, now_ns: u64) -> bool { now_ns >= self.next_ns }
    pub(crate) fn attempted(&mut self, delivered: bool, now_ns: u64) -> bool {
        if delivered {
            self.reported = true;
            self.fallback_base = None;
            self.has_fallback = false;
        }
        self.remaining = self.remaining.saturating_sub(1);
        self.next_ns = now_ns.saturating_add(REPORT_INTERVAL_NS);
        self.remaining == 0
    }
}
impl V6Change {
    pub(crate) fn due(&self, now_ns: u64) -> bool { now_ns >= self.next_ns }
    pub(crate) fn attempted(&mut self, delivered: bool, now_ns: u64) -> bool {
        if delivered {
            self.reported = true;
            self.fallback_base = None;
            self.has_fallback = false;
        }
        self.remaining = self.remaining.saturating_sub(1);
        self.next_ns = now_ns.saturating_add(REPORT_INTERVAL_NS);
        self.remaining == 0
    }
}
fn union4(dst: &mut alloc::vec::Vec<Ipv4Addr>, src: &[Ipv4Addr]) {
    for source in src { if !dst.contains(source) { dst.push(*source); } }
}
fn union6(dst: &mut alloc::vec::Vec<Ipv6Addr>, src: &[Ipv6Addr]) {
    for source in src { if !dst.contains(source) { dst.push(*source); } }
}
fn v4_target(report: &V4Report) -> SourceFilter {
    match report { V4Report::Active(filter) => filter.clone(), V4Report::Tomb => empty_v4() }
}
fn v6_target(report: &V6Report) -> SourceFilter6 {
    match report { V6Report::Active(filter) => filter.clone(), V6Report::Tomb => empty_v6() }
}
fn empty_v4() -> SourceFilter {
    SourceFilter { mode: FilterMode::Include, sources: alloc::vec::Vec::new() }
}
fn empty_v6() -> SourceFilter6 {
    SourceFilter6 { mode: FilterMode::Include, sources: alloc::vec::Vec::new() }
}
fn v4_baseline_eq(base: Option<&SourceFilter>, target: &SourceFilter) -> bool {
    base.cloned().unwrap_or_else(empty_v4) == *target
}
fn v6_baseline_eq(base: Option<&SourceFilter6>, target: &SourceFilter6) -> bool {
    base.cloned().unwrap_or_else(empty_v6) == *target
}
fn v4_records(prior: Option<&SourceFilter>, target: &SourceFilter) -> alloc::vec::Vec<V4Record> {
    use crate::igmp::{IGMP_V3_RECORD_ALLOW_NEW_SOURCES, IGMP_V3_RECORD_BLOCK_OLD_SOURCES,
        IGMP_V3_RECORD_CHANGE_TO_EXCLUDE, IGMP_V3_RECORD_CHANGE_TO_INCLUDE};
    let Some(prior) = prior else {
        let typ = match target.mode { FilterMode::Include => IGMP_V3_RECORD_CHANGE_TO_INCLUDE,
            FilterMode::Exclude => IGMP_V3_RECORD_CHANGE_TO_EXCLUDE };
        return alloc::vec![V4Record { record_type: typ, sources: target.sources.clone() }];
    };
    if prior.mode != target.mode {
        let typ = match target.mode { FilterMode::Include => IGMP_V3_RECORD_CHANGE_TO_INCLUDE,
            FilterMode::Exclude => IGMP_V3_RECORD_CHANGE_TO_EXCLUDE };
        return alloc::vec![V4Record { record_type: typ, sources: target.sources.clone() }];
    }
    let (allow, block) = source_delta(prior.mode, &prior.sources, &target.sources);
    let mut records = alloc::vec::Vec::new();
    if !allow.is_empty() { records.push(V4Record { record_type: IGMP_V3_RECORD_ALLOW_NEW_SOURCES, sources: allow }); }
    if !block.is_empty() { records.push(V4Record { record_type: IGMP_V3_RECORD_BLOCK_OLD_SOURCES, sources: block }); }
    records
}
fn v6_records(prior: Option<&SourceFilter6>, target: &SourceFilter6) -> alloc::vec::Vec<V6Record> {
    use crate::icmpv6::{MLDV2_RECORD_ALLOW_NEW_SOURCES, MLDV2_RECORD_BLOCK_OLD_SOURCES,
        MLDV2_RECORD_CHANGE_TO_EXCLUDE, MLDV2_RECORD_CHANGE_TO_INCLUDE};
    let Some(prior) = prior else {
        let typ = match target.mode { FilterMode::Include => MLDV2_RECORD_CHANGE_TO_INCLUDE,
            FilterMode::Exclude => MLDV2_RECORD_CHANGE_TO_EXCLUDE };
        return alloc::vec![V6Record { record_type: typ, sources: target.sources.clone() }];
    };
    if prior.mode != target.mode {
        let typ = match target.mode { FilterMode::Include => MLDV2_RECORD_CHANGE_TO_INCLUDE,
            FilterMode::Exclude => MLDV2_RECORD_CHANGE_TO_EXCLUDE };
        return alloc::vec![V6Record { record_type: typ, sources: target.sources.clone() }];
    }
    let (allow, block) = source_delta(prior.mode, &prior.sources, &target.sources);
    let mut records = alloc::vec::Vec::new();
    if !allow.is_empty() { records.push(V6Record { record_type: MLDV2_RECORD_ALLOW_NEW_SOURCES, sources: allow }); }
    if !block.is_empty() { records.push(V6Record { record_type: MLDV2_RECORD_BLOCK_OLD_SOURCES, sources: block }); }
    records
}
fn source_delta<T: Copy + Eq>(mode: FilterMode, prior: &[T], target: &[T])
    -> (alloc::vec::Vec<T>, alloc::vec::Vec<T>)
{
    let added = target.iter().filter(|source| !prior.contains(source)).copied().collect();
    let removed = prior.iter().filter(|source| !target.contains(source)).copied().collect();
    match mode { FilterMode::Include => (added, removed), FilterMode::Exclude => (removed, added) }
}
pub(crate) fn decode8(code: u8) -> u64 {
    if code < 128 { return code as u64; }
    let mant = ((code & 0x0f) | 0x10) as u64;
    mant << (((code >> 4) & 0x07) + 3)
}
