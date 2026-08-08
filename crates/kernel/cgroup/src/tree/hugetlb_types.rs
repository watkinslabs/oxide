// hugetlb-controller state: the granule identity this crate owns, the split
// USAGE/RESERVATION counter pair, and the control-file name tables.
//
// The granule is named HERE rather than borrowed from the huge-page pool: the
// pool's crate depends on this one, so a shared type would invert the
// dependency. The pool converts its own granule into a `HugeGranule` on the
// way in — one direction only, so there is exactly one place the two spellings
// meet and no second table to fall out of step.


/// Number of huge-page granules the controller keeps counters for.
pub const HUGE_GRANULES: usize = 2;
/// Number of counter kinds per granule (usage + reservation).
pub const HUGE_COUNTER_KINDS: usize = 2;

/// Upper bound of any counter, in base pages: the largest signed word divided
/// by the page size, which is what "no limit" reads back as on a hierarchy
/// that renders limits numerically.
pub const HUGE_COUNTER_MAX_PAGES: u64 = (i64::MAX as u64) / hal::PAGE_SIZE_BYTES;

/// A huge-page granule the controller accounts separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum HugeGranule {
    /// 2 MiB.
    Huge2M,
    /// 1 GiB.
    Huge1G,
}

impl HugeGranule {
    /// Every accounted granule, in control-file order.
    pub const ALL: [HugeGranule; HUGE_GRANULES] = [HugeGranule::Huge2M, HugeGranule::Huge1G];

    /// Counter-array slot. # C: O(1)
    pub const fn index(self) -> usize {
        match self { HugeGranule::Huge2M => 0, HugeGranule::Huge1G => 1 }
    }

    /// Bytes one page of this granule covers. # C: O(1)
    pub const fn bytes(self) -> u64 {
        match self { HugeGranule::Huge2M => 1u64 << 21, HugeGranule::Huge1G => 1u64 << 30 }
    }

    /// Base pages one page of this granule covers — the unit every counter,
    /// limit and watermark is kept in, matching the unit the interface files
    /// multiply by the page size. # C: O(1)
    pub const fn base_pages(self) -> u64 { self.bytes() / hal::PAGE_SIZE_BYTES }

    /// The name component that identifies this granule in a control file
    /// (`hugetlb.<label>.<attr>`). # C: O(1)
    pub const fn label(self) -> &'static str {
        match self { HugeGranule::Huge2M => "2MB", HugeGranule::Huge1G => "1GB" }
    }
}

/// Which of a granule's two ledgers a charge belongs to. A hugetlb charge is
/// taken twice over its life for different reasons: once when a mapping is
/// PROMISED pages it has not touched, and once when a page is actually handed
/// out. Collapsing them would make a limit either unenforceable at mmap time
/// or double-counted at fault time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HugeCounterKind {
    /// Pages handed out and still held.
    Usage,
    /// Pages promised to a mapping that has not faulted them.
    Reservation,
}

impl HugeCounterKind {
    /// Both kinds, in control-file order.
    pub const ALL: [HugeCounterKind; HUGE_COUNTER_KINDS] =
        [HugeCounterKind::Usage, HugeCounterKind::Reservation];

    /// Counter-array slot. # C: O(1)
    pub const fn index(self) -> usize {
        match self { HugeCounterKind::Usage => 0, HugeCounterKind::Reservation => 1 }
    }
}

/// Which hierarchy a counter set is being read, written or charged through.
/// The two differ in more than file spelling: only the legacy hierarchy keeps
/// a per-counter failure count, because only it publishes one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HierarchyKind {
    /// Legacy (one hierarchy per controller).
    V1,
    /// Unified.
    V2,
}

impl HierarchyKind {
    /// Whether a refused charge bumps the limiting counter's failure count.
    /// # C: O(1)
    pub const fn tracks_failcnt(self) -> bool { matches!(self, HierarchyKind::V1) }

    /// The token this hierarchy spells "no limit" with when a limit is
    /// written. # C: O(1)
    pub const fn unlimited_token(self) -> &'static str {
        match self { HierarchyKind::V1 => "-1", HierarchyKind::V2 => "max" }
    }
}

/// One (cgroup, granule, kind) ledger. Every field is in base pages except
/// `failcnt`, which counts events.
#[derive(Clone, Copy, Default)]
pub struct HugeCounter {
    /// Pages charged directly at this cgroup. The hierarchical figure the
    /// interface reports is derived by summing the subtree, so there is one
    /// place a charge lives and no roll-up to keep consistent.
    pub usage: u64,
    /// `None` is no limit.
    pub max: Option<u64>,
    /// High-water mark of the HIERARCHICAL usage at this cgroup.
    pub watermark: u64,
    /// Charges refused because this counter's own limit was the one exceeded.
    pub failcnt: u64,
}

/// Cumulative controller events for one granule. The controller defines
/// exactly one: a charge refused by a limit.
#[derive(Clone, Copy, Default)]
pub struct HugeEvents { pub max: u64 }

/// Every hugetlb ledger one cgroup owns.
#[derive(Clone, Copy, Default)]
pub struct HugetlbState {
    counters: [[HugeCounter; HUGE_COUNTER_KINDS]; HUGE_GRANULES],
    /// Events raised by charges made AT this cgroup; the hierarchical figure
    /// is the subtree sum.
    events_local: [HugeEvents; HUGE_GRANULES],
}

impl HugetlbState {
    /// Read one ledger. # C: O(1)
    pub fn counter(&self, g: HugeGranule, k: HugeCounterKind) -> &HugeCounter {
        &self.counters[g.index()][k.index()]
    }

    /// Mutate one ledger. # C: O(1)
    pub fn counter_mut(&mut self, g: HugeGranule, k: HugeCounterKind) -> &mut HugeCounter {
        &mut self.counters[g.index()][k.index()]
    }

    /// Read one granule's event counts. # C: O(1)
    pub fn events(&self, g: HugeGranule) -> HugeEvents { self.events_local[g.index()] }

    /// Record a refused charge at this cgroup. # C: O(1)
    pub fn record_max_event(&mut self, g: HugeGranule) {
        let e = &mut self.events_local[g.index()];
        e.max = e.max.saturating_add(1);
    }

    /// True while any granule still holds a live usage charge — the question
    /// asked of a cgroup that is going away. # C: O(granules)
    pub fn has_usage(&self) -> bool {
        HugeGranule::ALL.iter().any(|g| self.counter(*g, HugeCounterKind::Usage).usage != 0)
    }
}

/// The attribute a hugetlb control file exposes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HugeAttr {
    /// The counter's limit.
    Limit,
    /// The counter's current hierarchical charge.
    Usage,
    /// The counter's high-water mark; writable to reset it.
    MaxUsage,
    /// The counter's refused-charge count; writable to reset it.
    Failcnt,
    /// Hierarchical event counts for the granule.
    Events,
    /// This cgroup's own event counts for the granule.
    EventsLocal,
    /// Per-memory-node usage for the granule.
    NumaStat,
}

/// A parsed hugetlb control-file name.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HugeFile {
    pub granule: HugeGranule,
    pub kind: HugeCounterKind,
    pub attr: HugeAttr,
}

const PREFIX: &str = "hugetlb.";

/// `(suffix, kind, attr)` for the unified hierarchy. Every one of these is
/// absent from the root cgroup.
const V2_ATTRS: &[(&str, HugeCounterKind, HugeAttr)] = &[
    ("max",           HugeCounterKind::Usage,       HugeAttr::Limit),
    ("rsvd.max",      HugeCounterKind::Reservation, HugeAttr::Limit),
    ("current",       HugeCounterKind::Usage,       HugeAttr::Usage),
    ("rsvd.current",  HugeCounterKind::Reservation, HugeAttr::Usage),
    ("events",        HugeCounterKind::Usage,       HugeAttr::Events),
    ("events.local",  HugeCounterKind::Usage,       HugeAttr::EventsLocal),
    ("numa_stat",     HugeCounterKind::Usage,       HugeAttr::NumaStat),
];

/// `(suffix, kind, attr)` for the legacy hierarchy.
const V1_ATTRS: &[(&str, HugeCounterKind, HugeAttr)] = &[
    ("limit_in_bytes",           HugeCounterKind::Usage,       HugeAttr::Limit),
    ("rsvd.limit_in_bytes",      HugeCounterKind::Reservation, HugeAttr::Limit),
    ("usage_in_bytes",           HugeCounterKind::Usage,       HugeAttr::Usage),
    ("rsvd.usage_in_bytes",      HugeCounterKind::Reservation, HugeAttr::Usage),
    ("max_usage_in_bytes",       HugeCounterKind::Usage,       HugeAttr::MaxUsage),
    ("rsvd.max_usage_in_bytes",  HugeCounterKind::Reservation, HugeAttr::MaxUsage),
    ("failcnt",                  HugeCounterKind::Usage,       HugeAttr::Failcnt),
    ("rsvd.failcnt",             HugeCounterKind::Reservation, HugeAttr::Failcnt),
    ("numa_stat",                HugeCounterKind::Usage,       HugeAttr::NumaStat),
];

/// The attribute table a hierarchy publishes. # C: O(1)
pub const fn attr_table(h: HierarchyKind) -> &'static [(&'static str, HugeCounterKind, HugeAttr)] {
    match h { HierarchyKind::V1 => V1_ATTRS, HierarchyKind::V2 => V2_ATTRS }
}

/// Resolve a control-file name to the counter and attribute it addresses.
/// `None` when the name is not a hugetlb file of this hierarchy, including a
/// well-formed name that names a granule this kernel does not serve.
/// # C: O(granules · attrs)
pub fn parse_file(name: &str, h: HierarchyKind) -> Option<HugeFile> {
    let rest = name.strip_prefix(PREFIX)?;
    for granule in HugeGranule::ALL {
        let Some(tail) = rest.strip_prefix(granule.label()).and_then(|t| t.strip_prefix('.')) else { continue };
        for (suffix, kind, attr) in attr_table(h) {
            if *suffix == tail { return Some(HugeFile { granule, kind: *kind, attr: *attr }); }
        }
        return None;
    }
    None
}

/// The control-file name `(granule, suffix)` spells.
///
/// The published names are the static tables below; this generator exists to
/// hold them to their own grammar, so a hand-edited table entry cannot drift
/// from the spelling the controller means. That check is its only caller.
/// # C: O(len)
#[cfg(test)]
pub fn file_name(granule: HugeGranule, suffix: &str) -> alloc::string::String {
    let mut s = alloc::string::String::from(PREFIX);
    s.push_str(granule.label());
    s.push('.');
    s.push_str(suffix);
    s
}

/// Interned control-file names for the unified hierarchy, granule-major and
/// in the same order as `V2_ATTRS`. The directory surface is built from
/// `&'static str`, so the names are spelled out once here; a test pins them
/// against `file_name` so the two spellings cannot drift.
const V2_NAMES: &[&str] = &[
    "hugetlb.2MB.max", "hugetlb.2MB.rsvd.max", "hugetlb.2MB.current",
    "hugetlb.2MB.rsvd.current", "hugetlb.2MB.events", "hugetlb.2MB.events.local",
    "hugetlb.2MB.numa_stat",
    "hugetlb.1GB.max", "hugetlb.1GB.rsvd.max", "hugetlb.1GB.current",
    "hugetlb.1GB.rsvd.current", "hugetlb.1GB.events", "hugetlb.1GB.events.local",
    "hugetlb.1GB.numa_stat",
];

/// Interned control-file names for the legacy hierarchy, granule-major and in
/// the same order as `V1_ATTRS`. No hierarchy in this kernel publishes them
/// yet; they exist so the counter set can be driven and checked as the legacy
/// one rather than being a v2 set wearing v1 names.
const V1_NAMES: &[&str] = &[
    "hugetlb.2MB.limit_in_bytes", "hugetlb.2MB.rsvd.limit_in_bytes",
    "hugetlb.2MB.usage_in_bytes", "hugetlb.2MB.rsvd.usage_in_bytes",
    "hugetlb.2MB.max_usage_in_bytes", "hugetlb.2MB.rsvd.max_usage_in_bytes",
    "hugetlb.2MB.failcnt", "hugetlb.2MB.rsvd.failcnt", "hugetlb.2MB.numa_stat",
    "hugetlb.1GB.limit_in_bytes", "hugetlb.1GB.rsvd.limit_in_bytes",
    "hugetlb.1GB.usage_in_bytes", "hugetlb.1GB.rsvd.usage_in_bytes",
    "hugetlb.1GB.max_usage_in_bytes", "hugetlb.1GB.rsvd.max_usage_in_bytes",
    "hugetlb.1GB.failcnt", "hugetlb.1GB.rsvd.failcnt", "hugetlb.1GB.numa_stat",
];

/// Every control-file name a hierarchy publishes, granule-major.
/// # C: O(1)
pub const fn file_names(h: HierarchyKind) -> &'static [&'static str] {
    match h { HierarchyKind::V1 => V1_NAMES, HierarchyKind::V2 => V2_NAMES }
}

/// Parse a limit written to a hugetlb limit file: the hierarchy's own
/// unlimited token, or a byte count with an optional binary-magnitude suffix.
/// The result is base pages, clamped to the counter ceiling and rounded DOWN
/// to a whole number of huge pages — a limit that is not a multiple of the
/// granule can never be reached, so it is not one the controller accepts.
/// `None` is a malformed value (the caller answers EINVAL).
/// # C: O(len)
pub fn parse_limit(buf: &str, granule: HugeGranule, h: HierarchyKind) -> Option<Option<u64>> {
    let t = buf.trim();
    let pages = if t == h.unlimited_token() {
        HUGE_COUNTER_MAX_PAGES
    } else {
        let bytes = parse_bytes(t)?;
        core::cmp::min(bytes / hal::PAGE_SIZE_BYTES, HUGE_COUNTER_MAX_PAGES)
    };
    let per = granule.base_pages();
    let rounded = (pages / per) * per;
    Some(if rounded >= (HUGE_COUNTER_MAX_PAGES / per) * per { None } else { Some(rounded) })
}

/// The numeric value an unlimited limit reads back as on a hierarchy that
/// renders limits as bytes rather than a token. # C: O(1)
pub const fn unlimited_bytes(granule: HugeGranule) -> u64 {
    let per = granule.base_pages();
    (HUGE_COUNTER_MAX_PAGES / per) * per * hal::PAGE_SIZE_BYTES
}

/// Decimal byte count with an optional `K`/`M`/`G`/`T`/`P`/`E` binary
/// magnitude suffix, either case. Saturates rather than wrapping, so an
/// absurd value becomes the ceiling instead of a small number.
/// # C: O(len)
fn parse_bytes(t: &str) -> Option<u64> {
    let (digits, shift) = match t.as_bytes().last() {
        Some(c) => match c.to_ascii_uppercase() {
            b'K' => (&t[..t.len() - 1], 10),
            b'M' => (&t[..t.len() - 1], 20),
            b'G' => (&t[..t.len() - 1], 30),
            b'T' => (&t[..t.len() - 1], 40),
            b'P' => (&t[..t.len() - 1], 50),
            b'E' => (&t[..t.len() - 1], 60),
            _ => (t, 0),
        },
        None => return None,
    };
    if digits.is_empty() { return None; }
    let n: u64 = digits.parse().ok()?;
    Some(n.checked_shl(shift).filter(|v| (v >> shift) == n).unwrap_or(u64::MAX))
}
