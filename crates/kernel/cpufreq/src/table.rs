// The frequency table: the operating points a driver declares, and the rule
// that turns a requested frequency into one of them.
//
// The rule is where a scaling bug hides. Resolving a minimum-frequency
// constraint with the wrong relation silently runs the machine slower than
// something asked for; resolving a maximum with the wrong one runs it faster
// than a thermal limit allows. Both produce a frequency that exists, so
// nothing complains.

use alloc::vec::Vec;

use crate::uapi::{Relation, ENTRY_INVALID, FLAG_BOOST, FLAG_INEFFICIENT};

/// One operating point.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct FreqEntry {
    /// Kilohertz, or `ENTRY_INVALID`.
    pub frequency: u32,
    /// The driver's own index for this point — what it is handed back.
    pub driver_data: u32,
    pub flags: u32,
}

impl FreqEntry {
    /// A plain entry. # C: O(1)
    pub fn new(frequency_khz: u32, driver_data: u32) -> FreqEntry {
        FreqEntry { frequency: frequency_khz, driver_data, flags: 0 }
    }

    /// Whether the platform can use this point at all. # C: O(1)
    pub fn valid(&self) -> bool { self.frequency != ENTRY_INVALID && self.frequency != 0 }
    /// Whether this point is only reachable with boost enabled. # C: O(1)
    pub fn boost(&self) -> bool { self.flags & FLAG_BOOST != 0 }
    /// Whether another point does the same work for less. # C: O(1)
    pub fn inefficient(&self) -> bool { self.flags & FLAG_INEFFICIENT != 0 }
}

/// Whether the declared order is a ladder, and which way.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Sorted { Ascending, Descending, Unsorted }

/// The declared operating points.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FreqTable {
    pub entries: Vec<FreqEntry>,
    pub sorted: Sorted,
}

/// Why a declared table was refused.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TableError {
    /// Nothing usable in it.
    NoValidEntry,
    TooMany,
    /// The same frequency twice: two table indexes for one operating point,
    /// so the two disagree about which one a resolution picked.
    Duplicate,
}

impl FreqTable {
    /// Build and check a table. # C: O(N²)
    pub fn new(entries: Vec<FreqEntry>) -> Result<FreqTable, TableError> {
        if entries.len() > crate::limits::MAX_TABLE_ENTRIES { return Err(TableError::TooMany); }
        if !entries.iter().any(FreqEntry::valid) { return Err(TableError::NoValidEntry); }
        let valid: Vec<u32> = entries.iter().filter(|e| e.valid()).map(|e| e.frequency).collect();
        for (index, freq) in valid.iter().enumerate() {
            if valid[index + 1..].contains(freq) { return Err(TableError::Duplicate); }
        }
        let sorted = detect_order(&valid);
        Ok(FreqTable { entries, sorted })
    }

    /// Lowest and highest usable frequency, kilohertz. Boost points count only
    /// when boost is on: a machine reporting its boost ceiling as its ordinary
    /// maximum would have every utilisation-derived target scaled against a
    /// frequency it cannot hold. # C: O(N)
    pub fn cpuinfo(&self, boost_enabled: bool) -> Option<(u32, u32)> {
        let mut min = u32::MAX;
        let mut max = 0;
        for entry in &self.entries {
            if !entry.valid() { continue; }
            if entry.boost() && !boost_enabled { continue; }
            if entry.frequency < min { min = entry.frequency; }
            if entry.frequency > max { max = entry.frequency; }
        }
        if max == 0 { None } else { Some((min, max)) }
    }

    /// Whether any point is boost-only. # C: O(N)
    pub fn boost_supported(&self) -> bool { self.entries.iter().any(FreqEntry::boost) }

    /// Every usable frequency in ascending order, as
    /// `scaling_available_frequencies` lists them. # C: O(N log N)
    pub fn available(&self, boost_enabled: bool) -> Vec<u32> {
        let mut freqs: Vec<u32> = self.entries.iter()
            .filter(|entry| entry.valid() && (boost_enabled || !entry.boost()))
            .map(|entry| entry.frequency)
            .collect();
        freqs.sort_unstable();
        freqs
    }

    /// Resolve `target_khz` to a table index.
    ///
    /// The target is first clamped into `[min_khz, max_khz]`, so a resolution
    /// can never step outside the policy's limits whatever the relation. Where
    /// the relation permits it, a point the platform marked inefficient is
    /// skipped — but only as a preference: if skipping them leaves nothing in
    /// range, the scan runs again without the preference rather than returning
    /// a frequency outside the limits. # C: O(N)
    pub fn resolve(&self, target_khz: u32, min_khz: u32, max_khz: u32, relation: Relation,
                   boost_enabled: bool) -> Option<usize>
    {
        let max_khz = max_khz.max(min_khz);
        let target = target_khz.clamp(min_khz, max_khz);
        if relation.prefers_efficient() {
            if let Some(index) = self.scan(target, min_khz, max_khz, relation, boost_enabled,
                                           true) {
                return Some(index);
            }
        }
        self.scan(target, min_khz, max_khz, relation, boost_enabled, false)
    }

    /// One pass of the resolution. # C: O(N)
    fn scan(&self, target: u32, min_khz: u32, max_khz: u32, relation: Relation,
            boost_enabled: bool, skip_inefficient: bool) -> Option<usize>
    {
        let mut best: Option<usize> = None;
        for (index, entry) in self.entries.iter().enumerate() {
            if !entry.valid() { continue; }
            if entry.boost() && !boost_enabled { continue; }
            if skip_inefficient && entry.inefficient() { continue; }
            let freq = entry.frequency;
            if freq < min_khz || freq > max_khz { continue; }
            let acceptable = match relation {
                Relation::Lowest => freq >= target,
                Relation::Highest => freq <= target,
                Relation::Closest => true,
            };
            if !acceptable { continue; }
            best = Some(match best {
                None => index,
                Some(current) => if better(relation, target, freq,
                                           self.entries[current].frequency) { index }
                                 else { current },
            });
        }
        // Nothing on the asked-for side of the target: take the nearest point
        // on the other side rather than refusing. A policy whose limits admit
        // exactly one frequency must still resolve to it.
        if best.is_none() && relation != Relation::Closest {
            return self.scan(target, min_khz, max_khz, Relation::Closest, boost_enabled,
                             skip_inefficient);
        }
        best
    }
}

/// Whether `candidate` beats `current` for this relation. # C: O(1)
fn better(relation: Relation, target: u32, candidate: u32, current: u32) -> bool {
    match relation {
        Relation::Lowest => candidate < current,
        Relation::Highest => candidate > current,
        Relation::Closest => {
            let (near, far) = (candidate.abs_diff(target), current.abs_diff(target));
            near < far || (near == far && candidate > current)
        }
    }
}

/// Whether the declared order is a ladder. # C: O(N)
fn detect_order(valid: &[u32]) -> Sorted {
    if valid.len() < 2 { return Sorted::Ascending; }
    let ascending = valid.windows(2).all(|pair| pair[0] < pair[1]);
    if ascending { return Sorted::Ascending; }
    if valid.windows(2).all(|pair| pair[0] > pair[1]) { return Sorted::Descending; }
    Sorted::Unsorted
}

#[cfg(test)]
#[path = "tests/table.rs"]
mod tests;
