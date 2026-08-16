// The per-interface station table.
//
// A station is inserted BEFORE it is usable and removed only once nothing is
// looking at it. The order matters in both directions: a frame from a peer
// can arrive between the decision to admit it and its appearance in the
// table, and a peer can be removed while a queued frame still names it.

extern crate alloc;

use alloc::vec::Vec;

use sync::{Spinlock, Sta80211 as StaLock};
use wireless::ieee80211::MacAddr;

use super::record::Sta;
use super::state;
use crate::limits;
use crate::ops::StaState;

/// The stations one interface knows.
pub struct StaTable {
    stas: Spinlock<Vec<Sta>, StaLock>,
}

impl Default for StaTable {
    fn default() -> Self { Self { stas: Spinlock::new(Vec::new()) } }
}

impl StaTable {
    /// Run `f` against a station, if it is there. # C: O(N stations)
    pub fn with<R>(&self, addr: MacAddr, f: impl FnOnce(&mut Sta) -> R) -> Option<R> {
        let mut g = self.stas.lock();
        g.iter_mut().find(|s| s.addr == addr).map(f)
    }

    /// Run `f` against every station. # C: O(N stations)
    pub fn for_each<R>(&self, mut f: impl FnMut(&mut Sta) -> Option<R>) -> Vec<R> {
        let mut g = self.stas.lock();
        g.iter_mut().filter_map(|s| f(s)).collect()
    }

    /// Insert a station. A second insertion of the same address is refused
    /// rather than replacing the first: replacing would discard the reorder
    /// windows and replay counters of a link that is still up. # C: O(N stations)
    pub fn insert(&self, sta: Sta) -> bool {
        let mut g = self.stas.lock();
        if g.len() >= limits::MAX_STATIONS { return false; }
        if g.iter().any(|s| s.addr == sta.addr) { return false; }
        g.push(sta);
        true
    }

    /// Remove a station. Reports whether it was there. # C: O(N stations)
    pub fn remove(&self, addr: MacAddr) -> bool {
        let mut g = self.stas.lock();
        let before = g.len();
        g.retain(|s| s.addr != addr);
        g.len() != before
    }

    /// Whether an address is in the table. # C: O(N stations)
    pub fn contains(&self, addr: MacAddr) -> bool {
        self.stas.lock().iter().any(|s| s.addr == addr)
    }

    /// State of one station. # C: O(N stations)
    pub fn state(&self, addr: MacAddr) -> StaState {
        self.stas.lock().iter().find(|s| s.addr == addr)
            .map_or(StaState::NotExist, |s| s.state)
    }

    /// Stations in the table. # C: O(1)
    pub fn len(&self) -> usize { self.stas.lock().len() }
    /// Whether the table is empty. # C: O(1)
    pub fn is_empty(&self) -> bool { self.stas.lock().is_empty() }

    /// Every station's address, in insertion order. # C: O(N stations)
    pub fn addrs(&self) -> Vec<MacAddr> { self.stas.lock().iter().map(|s| s.addr).collect() }

    /// Address at an index, for a dump that walks by position. # C: O(1)
    pub fn addr_at(&self, idx: usize) -> Option<MacAddr> {
        self.stas.lock().get(idx).map(|s| s.addr)
    }

    /// Move a station along the ladder, one step at a time, invoking `step`
    /// for each. The station's own state is advanced only as each step
    /// succeeds, so a driver refusing a step leaves the station where the
    /// driver last agreed it was. # C: O(steps)
    pub fn set_state(&self, addr: MacAddr, new: StaState,
                     mut step: impl FnMut(StaState, StaState) -> bool) -> bool {
        let old = self.state(addr);
        if old == StaState::NotExist && new != StaState::NotExist { return false; }
        for (from, to) in state::steps(old, new) {
            if !step(from, to) { return false; }
            let applied = self.with(addr, |s| s.state = to).is_some();
            if !applied { return false; }
        }
        true
    }

    /// Every station that has been silent too long. # C: O(N stations)
    pub fn inactive(&self, now_ns: u64) -> Vec<MacAddr> {
        self.stas.lock().iter().filter(|s| s.is_inactive(now_ns)).map(|s| s.addr).collect()
    }

    /// Lowest association identifier not in use, or nothing when the network
    /// is full. Identifier zero is not an identifier. # C: O(N stations)
    pub fn next_aid(&self) -> Option<u16> {
        let g = self.stas.lock();
        (1..=wireless::ieee80211::mgmt::MAX_AID).find(|aid| !g.iter().any(|s| s.aid == *aid))
    }

    /// Drop everything, as taking the interface down does. # C: O(N stations)
    pub fn flush(&self) -> Vec<MacAddr> {
        let mut g = self.stas.lock();
        let addrs = g.iter().map(|s| s.addr).collect();
        g.clear();
        addrs
    }
}
