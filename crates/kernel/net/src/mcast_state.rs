use alloc::collections::BTreeMap;

use crate::addr::{Ipv4Addr, Ipv6Addr};
use crate::mcast_filter::{FilterMode, SourceFilter, SourceFilter6};

pub(crate) const REPORT_INTERVAL_NS: u64 = 1_000_000_000;
pub(crate) const REPORT_ROBUSTNESS: u8 = 2;
pub(crate) const DEFAULT_QUERY_INTERVAL_NS: u64 = 125_000_000_000;
const IGMP_V1_RESPONSE_INTERVAL_NS: u64 = 10_000_000_000;

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
    pub group: Ipv4Addr,
    pub report_src: Ipv4Addr,
    pub asm_refs: u32,
    pub members: BTreeMap<usize, SourceFilter>,
    pub generation: u64,
    pub change: Option<V4Change>,
    pub robustness: u8,
    pub query_interval_ns: u64,
    pub v1_querier_until_ns: u64,
    pub v2_querier_until_ns: u64,
}

/// Interface-owned IPv6 multicast policy and pending report state.
#[derive(Clone)]
pub(crate) struct V6IfaceGroup {
    pub group: Ipv6Addr,
    pub report_src: Ipv6Addr,
    pub asm_refs: u32,
    pub members: BTreeMap<usize, SourceFilter6>,
    pub generation: u64,
    pub change: Option<V6Change>,
    pub robustness: u8,
    pub query_interval_ns: u64,
    pub v1_querier_until_ns: u64,
}

impl V4IfaceGroup {
    pub(crate) fn new(group: Ipv4Addr, report_src: Ipv4Addr) -> Self {
        Self { group, report_src, asm_refs: 0, members: BTreeMap::new(), generation: 0, change: None,
            robustness: REPORT_ROBUSTNESS, query_interval_ns: DEFAULT_QUERY_INTERVAL_NS,
            v1_querier_until_ns: 0, v2_querier_until_ns: 0 }
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

    pub(crate) fn stage(&mut self, prior: Option<&SourceFilter>, now_ns: u64) -> (u64, V4Change) {
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
        let remaining = if records.is_empty() { 1 } else { self.robustness };
        let change = V4Change { base, report, records, next_ns: now_ns, remaining,
            reported: false, fallback_base, has_fallback };
        self.change = Some(change.clone());
        (self.generation, change)
    }

    pub(crate) fn reconcile_superseded(&mut self, attempted: &V4Change,
                                       delivered: bool, now_ns: u64) {
        let base = if delivered || attempted.reported { Some(v4_target(&attempted.report)) }
            else { attempted.base.clone() };
        let Some(change) = self.change.as_mut() else { return };
        let target = v4_target(&change.report);
        change.base = base;
        change.records = v4_records(change.base.as_ref(), &target);
        change.remaining = if change.records.is_empty() { 1 } else { self.robustness };
        change.reported = false;
        change.fallback_base = None;
        change.has_fallback = false;
        change.next_ns = now_ns;
    }

    pub(crate) fn observe_query(&mut self, qrv: u8, qqic: u8, max_resp_ns: u64,
                                version: u8, now_ns: u64) {
        if qrv != 0 { self.robustness = qrv; }
        if qqic != 0 { self.query_interval_ns = decode8(qqic).saturating_mul(1_000_000_000); }
        let response_ns = if version == 1 { IGMP_V1_RESPONSE_INTERVAL_NS } else { max_resp_ns };
        let until = now_ns.saturating_add((self.robustness as u64)
            .saturating_mul(self.query_interval_ns)).saturating_add(response_ns);
        if version == 1 { self.v1_querier_until_ns = until; }
        else if version == 2 { self.v2_querier_until_ns = until; }
    }

    pub(crate) fn report_version(&self, now_ns: u64) -> u8 {
        if now_ns < self.v1_querier_until_ns { 1 }
        else if now_ns < self.v2_querier_until_ns { 2 }
        else { 3 }
    }
}

impl V6IfaceGroup {
    pub(crate) fn new(group: Ipv6Addr, report_src: Ipv6Addr) -> Self {
        Self { group, report_src, asm_refs: 0, members: BTreeMap::new(), generation: 0, change: None,
            robustness: REPORT_ROBUSTNESS, query_interval_ns: DEFAULT_QUERY_INTERVAL_NS,
            v1_querier_until_ns: 0 }
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
        let remaining = if records.is_empty() { 1 } else { self.robustness };
        let change = V6Change { base, report, records, next_ns: now_ns, remaining,
            reported: false, fallback_base, has_fallback };
        self.change = Some(change.clone());
        (self.generation, change)
    }

    pub(crate) fn reconcile_superseded(&mut self, attempted: &V6Change,
                                       delivered: bool, now_ns: u64) {
        let base = if delivered || attempted.reported { Some(v6_target(&attempted.report)) }
            else { attempted.base.clone() };
        let Some(change) = self.change.as_mut() else { return };
        let target = v6_target(&change.report);
        change.base = base;
        change.records = v6_records(change.base.as_ref(), &target);
        change.remaining = if change.records.is_empty() { 1 } else { self.robustness };
        change.reported = false;
        change.fallback_base = None;
        change.has_fallback = false;
        change.next_ns = now_ns;
    }

    pub(crate) fn observe_query(&mut self, qrv: u8, qqic: u8, max_resp_ns: u64,
                                version: u8, now_ns: u64) {
        if qrv != 0 { self.robustness = qrv; }
        if qqic != 0 { self.query_interval_ns = decode8(qqic).saturating_mul(1_000_000_000); }
        if version == 1 {
            self.v1_querier_until_ns = now_ns.saturating_add((self.robustness as u64)
                .saturating_mul(self.query_interval_ns)).saturating_add(max_resp_ns);
        }
    }

    pub(crate) fn report_version(&self, now_ns: u64) -> u8 {
        if now_ns < self.v1_querier_until_ns { 1 } else { 2 }
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
