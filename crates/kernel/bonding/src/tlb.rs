// Transmit load balancing. A one-byte fold of the destination address indexes
// a table of flow-to-slave assignments; an unassigned flow goes to the slave
// with the largest remaining headroom, and its bytes accumulate there.

use crate::limits::{BOND_MAX_SLAVES, TLB_HASH_TABLE_SIZE, TLB_NULL_INDEX};
use crate::slave::SlaveState;

/// One transmit-hash table entry.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct TlbEntry {
    /// Slave index this flow is pinned to, when assigned.
    pub tx_slave: Option<usize>,
    /// Bytes sent on this flow since the last rebalance.
    pub tx_bytes: u64,
    /// Bytes carried forward from the previous rebalance window.
    pub load_history: u64,
    /// Next entry on the owning slave's chain.
    pub next: u32,
    /// Previous entry on the owning slave's chain.
    pub prev: u32,
}

impl Default for TlbEntry {
    fn default() -> Self {
        TlbEntry { tx_slave: None, tx_bytes: 0, load_history: 0,
                   next: TLB_NULL_INDEX, prev: TLB_NULL_INDEX }
    }
}

/// The transmit table plus the per-slave chain heads and loads.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlbTable {
    entries: [TlbEntry; TLB_HASH_TABLE_SIZE],
    /// Chain head per slave index.
    heads: [u32; BOND_MAX_SLAVES],
    /// Accumulated load per slave index, in bytes.
    loads: [u64; BOND_MAX_SLAVES],
}

impl Default for TlbTable {
    fn default() -> Self {
        TlbTable {
            entries: [TlbEntry::default(); TLB_HASH_TABLE_SIZE],
            heads: [TLB_NULL_INDEX; BOND_MAX_SLAVES],
            loads: [0; BOND_MAX_SLAVES],
        }
    }
}

/// One-byte fold used to index both the transmit and the receive tables.
/// # C: O(len)
pub fn simple_hash(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |acc, b| acc ^ *b)
}

/// Headroom left on a slave: its link capacity in bits less the bits already
/// accounted to it. The largest gap is the least loaded slave.
/// # C: O(1)
pub fn compute_gap(slave: &SlaveState) -> i64 {
    ((slave.speed_mbps as i64) << 20) - ((slave.tlb_load as i64) << 3)
}

/// Slave with the most headroom among those able to transmit.
/// # C: O(slaves)
pub fn least_loaded_slave(slaves: &[SlaveState]) -> Option<usize> {
    let mut best: Option<usize> = None;
    let mut max_gap = i64::MIN;
    for (i, s) in slaves.iter().enumerate() {
        if !s.can_tx() { continue; }
        let gap = compute_gap(s);
        if max_gap < gap { max_gap = gap; best = Some(i); }
    }
    best
}

impl TlbTable {
    /// # C: O(1)
    pub fn entry(&self, index: u8) -> &TlbEntry { &self.entries[index as usize] }

    /// Accumulated bytes charged to one slave.
    /// # C: O(1)
    pub fn slave_load(&self, slave: usize) -> u64 {
        self.loads.get(slave).copied().unwrap_or(0)
    }

    /// Chain head for one slave, or the sentinel when the chain is empty.
    /// # C: O(1)
    pub fn slave_head(&self, slave: usize) -> u32 {
        self.heads.get(slave).copied().unwrap_or(TLB_NULL_INDEX)
    }

    /// Pick the slave for one flow. An already-assigned flow keeps its slave;
    /// an unassigned one is linked onto the least-loaded slave's chain and
    /// inherits that flow's carried-forward load.
    /// # C: O(slaves)
    pub fn choose_channel(&mut self, index: u8, len: u64, slaves: &[SlaveState])
        -> Option<usize>
    {
        let i = index as usize;
        let mut assigned = self.entries[i].tx_slave;
        if assigned.is_none() {
            assigned = least_loaded_slave(slaves).filter(|s| *s < BOND_MAX_SLAVES);
            if let Some(s) = assigned {
                let next = self.heads[s];
                self.entries[i].tx_slave = Some(s);
                self.entries[i].next = next;
                self.entries[i].prev = TLB_NULL_INDEX;
                if next != TLB_NULL_INDEX { self.entries[next as usize].prev = index as u32; }
                self.heads[s] = index as u32;
                self.loads[s] += self.entries[i].load_history;
            }
        }
        if assigned.is_some() { self.entries[i].tx_bytes += len; }
        assigned
    }

    /// Fold this window's byte counts into the carried-forward history and
    /// clear the per-slave accumulators for the next window.
    /// # C: O(table)
    pub fn rebalance(&mut self) {
        for e in self.entries.iter_mut() {
            e.load_history = e.tx_bytes;
            e.tx_bytes = 0;
        }
        for l in self.loads.iter_mut() { *l = 0; }
        for i in 0..TLB_HASH_TABLE_SIZE {
            if let Some(s) = self.entries[i].tx_slave {
                if s < BOND_MAX_SLAVES { self.loads[s] += self.entries[i].load_history; }
            }
        }
    }

    /// Drop every assignment pointing at a departing slave.
    /// # C: O(table)
    pub fn deinitialize_slave(&mut self, slave: usize) {
        if slave >= BOND_MAX_SLAVES { return; }
        for e in self.entries.iter_mut() {
            if e.tx_slave == Some(slave) {
                e.tx_slave = None;
                e.next = TLB_NULL_INDEX;
                e.prev = TLB_NULL_INDEX;
            }
        }
        self.heads[slave] = TLB_NULL_INDEX;
        self.loads[slave] = 0;
    }
}
