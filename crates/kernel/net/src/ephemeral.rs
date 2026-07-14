use core::sync::atomic::{AtomicU64, Ordering};

/// Linux default `net.ipv4.ip_local_port_range`.
pub const DEFAULT_START: u16 = 32_768;
pub const DEFAULT_END: u16 = 60_999;

pub const DEFAULT_UNPRIVILEGED_START: u16 = 1_024;

const fn pack(start: u16, end: u16, floor: u16) -> u64 {
    (start as u64) << 32 | (end as u64) << 16 | floor as u64
}

/// Coherent per-network-namespace local-port configuration.
pub struct State { packed: AtomicU64 }

impl State {
    pub const fn new() -> Self {
        Self { packed: AtomicU64::new(pack(DEFAULT_START, DEFAULT_END, DEFAULT_UNPRIVILEGED_START)) }
    }

    pub fn range(&self) -> Range {
        let raw = self.packed.load(Ordering::Acquire);
        Range { start: (raw >> 32) as u16, end: (raw >> 16) as u16 }
    }

    pub fn unprivileged_start(&self) -> u16 { self.packed.load(Ordering::Acquire) as u16 }

    pub fn set_range(&self, start: u16, end: u16) -> Result<(), ()> {
        let range = Range::new(start, end).ok_or(())?;
        let mut old = self.packed.load(Ordering::Acquire);
        loop {
            let floor = old as u16;
            if range.start < floor { return Err(()); }
            let new = pack(range.start, range.end, floor);
            match self.packed.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(()), Err(current) => old = current,
            }
        }
    }

    pub fn set_unprivileged_start(&self, floor: u16) -> Result<(), ()> {
        let mut old = self.packed.load(Ordering::Acquire);
        loop {
            let start = (old >> 32) as u16;
            let end = (old >> 16) as u16;
            if floor > start { return Err(()); }
            let new = pack(start, end, floor);
            match self.packed.compare_exchange_weak(old, new, Ordering::AcqRel, Ordering::Acquire) {
                Ok(_) => return Ok(()), Err(current) => old = current,
            }
        }
    }
}

impl Default for State { fn default() -> Self { Self::new() } }

static INIT_STATE: State = State::new();

/// One coherent allocator range snapshot.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Range { pub start: u16, pub end: u16 }

impl Range {
    /// Validate one Linux local-port interval. # C: O(1)
    pub const fn new(start: u16, end: u16) -> Option<Self> {
        if start == 0 || start > end { None } else { Some(Self { start, end }) }
    }

    /// Inclusive number of candidate ports. # C: O(1)
    pub const fn count(self) -> u32 { self.end as u32 - self.start as u32 + 1 }

    /// Map a wrapping allocation sequence into this interval. # C: O(1)
    pub const fn port(self, seq: u32) -> u16 {
        (self.start as u32 + seq.wrapping_sub(self.start as u32) % self.count()) as u16
    }
}

/// Snapshot the live `ip_local_port_range` atomically. # C: O(1)
pub fn range() -> Range {
    range_in(crate::netdev::current_net_ns())
}

/// Replace the live `ip_local_port_range` atomically. # C: O(1)
pub fn set_range(start: u16, end: u16) -> Result<(), ()> {
    set_range_in(crate::netdev::current_net_ns(), start, end)
}

pub fn range_in(ns: u64) -> Range {
    if ns == 0 { INIT_STATE.range() } else { crate::net_ns::ns_net(ns).ports.range() }
}

pub fn set_range_in(ns: u64, start: u16, end: u16) -> Result<(), ()> {
    if ns == 0 { INIT_STATE.set_range(start, end) }
    else { crate::net_ns::ns_net(ns).ports.set_range(start, end) }
}

pub fn unprivileged_start() -> u16 {
    unprivileged_start_in(crate::netdev::current_net_ns())
}

pub fn unprivileged_start_in(ns: u64) -> u16 {
    if ns == 0 { INIT_STATE.unprivileged_start() }
    else { crate::net_ns::ns_net(ns).ports.unprivileged_start() }
}

pub fn set_unprivileged_start(floor: u16) -> Result<(), ()> {
    set_unprivileged_start_in(crate::netdev::current_net_ns(), floor)
}

pub fn set_unprivileged_start_in(ns: u64, floor: u16) -> Result<(), ()> {
    if ns == 0 { INIT_STATE.set_unprivileged_start(floor) }
    else { crate::net_ns::ns_net(ns).ports.set_unprivileged_start(floor) }
}

#[cfg(test)]
mod tests {
    use super::{Range, State};

    #[test]
    fn snapshot_mapping_wraps_and_visits_both_endpoints() {
        let range = Range::new(40_000, 40_002).unwrap();
        assert_eq!(range.count(), 3);
        assert_eq!(range.port(40_000), 40_000);
        assert_eq!(range.port(40_001), 40_001);
        assert_eq!(range.port(40_002), 40_002);
        assert_eq!(range.port(40_003), 40_000);
        assert!(Range::new(0, 1).is_none());
        assert!(Range::new(2, 1).is_none());
    }

    #[test]
    fn range_and_privilege_floor_remain_coherent() {
        let state = State::new();
        assert!(state.set_range(1_023, 60_999).is_err());
        state.set_unprivileged_start(40_000).unwrap_err();
        state.set_range(40_000, 40_100).unwrap();
        state.set_unprivileged_start(40_000).unwrap();
        assert!(state.set_range(39_999, 40_100).is_err());
        assert_eq!(state.range(), Range { start: 40_000, end: 40_100 });
    }

    #[test]
    fn non_init_namespace_ranges_are_isolated() {
        let first = 0x8230_0001;
        let second = 0x8230_0002;
        super::set_range_in(first, 45_000, 45_009).unwrap();
        assert_eq!(super::range_in(first), Range { start: 45_000, end: 45_009 });
        assert_eq!(super::range_in(second),
            Range { start: super::DEFAULT_START, end: super::DEFAULT_END });
    }
}
