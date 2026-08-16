// The two priority translations a VLAN interface owns: a received code point
// becomes a transmit priority, and a transmit priority becomes a code point.

extern crate alloc;
use alloc::vec::Vec;

use crate::limits::{EGRESS_BUCKETS, EGRESS_BUCKET_MASK, INGRESS_MAP_LEN, INGRESS_MAP_MASK};
use crate::tci;

/// One exact-match egress translation. `qos` is stored already shifted into the
/// priority field, so the transmit path ORs it into the tag control information
/// without touching it again.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct EgressEntry {
    pub priority: u32,
    pub qos: u16,
}

/// Both priority tables of one interface.
pub struct PrioMaps {
    ingress: [u32; INGRESS_MAP_LEN],
    nr_ingress: u32,
    egress: [Vec<EgressEntry>; EGRESS_BUCKETS],
    nr_egress: u32,
}

impl Default for PrioMaps {
    fn default() -> Self { Self::new() }
}

impl PrioMaps {
    /// Tables with no translation configured: every received code point maps to
    /// priority 0 and every transmit priority sends code point 0. # C: O(1)
    pub fn new() -> Self {
        Self {
            ingress: [0; INGRESS_MAP_LEN],
            nr_ingress: 0,
            egress: core::array::from_fn(|_| Vec::new()),
            nr_egress: 0,
        }
    }

    /// Point one code point at a transmit priority. A zero priority is the
    /// unconfigured state, so writing it removes the translation from the
    /// count that decides whether the table is reported at all.
    /// # C: O(1)
    pub fn set_ingress(&mut self, skb_priority: u32, vlan_priority: u32) {
        let slot = (vlan_priority & INGRESS_MAP_MASK) as usize;
        let had = self.ingress[slot] != 0;
        if had && skb_priority == 0 { self.nr_ingress -= 1; }
        else if !had && skb_priority != 0 { self.nr_ingress += 1; }
        self.ingress[slot] = skb_priority;
    }

    /// Transmit priority a received code point selects. # C: O(1)
    pub fn ingress(&self, vlan_priority: u32) -> u32 {
        self.ingress[(vlan_priority & INGRESS_MAP_MASK) as usize]
    }

    /// Transmit priority the tag control information of a received frame
    /// selects. # C: O(1)
    pub fn ingress_for_tci(&self, tci: u16) -> u32 { self.ingress(tci::pcp(tci) as u32) }

    /// Configured code-point translations as `(code point, transmit priority)`.
    /// # C: O(1)
    pub fn ingress_mappings(&self) -> Vec<(u32, u32)> {
        (0..INGRESS_MAP_LEN)
            .filter(|i| self.ingress[*i] != 0)
            .map(|i| (i as u32, self.ingress[i]))
            .collect()
    }

    /// Number of live code-point translations. # C: O(1)
    pub fn nr_ingress(&self) -> u32 { self.nr_ingress }

    /// Point one exact transmit priority at a code point. A code point of zero
    /// is the unconfigured state: it deletes an existing translation and
    /// creates none.
    /// # C: O(bucket length)
    pub fn set_egress(&mut self, skb_priority: u32, vlan_priority: u32) {
        let qos = tci::qos_mask(vlan_priority as u8);
        let bucket = &mut self.egress[(skb_priority & EGRESS_BUCKET_MASK) as usize];
        if let Some(pos) = bucket.iter().position(|e| e.priority == skb_priority) {
            if qos == 0 { bucket.remove(pos); self.nr_egress -= 1; }
            else { bucket[pos].qos = qos; }
            return;
        }
        if qos == 0 { return; }
        bucket.push(EgressEntry { priority: skb_priority, qos });
        self.nr_egress += 1;
    }

    /// Priority-field bits a transmit priority contributes to the outgoing tag.
    /// An unmapped priority contributes nothing, which is code point 0.
    /// # C: O(bucket length)
    pub fn egress_mask(&self, skb_priority: u32) -> u16 {
        self.egress[(skb_priority & EGRESS_BUCKET_MASK) as usize]
            .iter()
            .find(|e| e.priority == skb_priority)
            .map(|e| e.qos)
            .unwrap_or(0)
    }

    /// Configured priority translations as `(transmit priority, code point)`.
    /// # C: O(entries)
    pub fn egress_mappings(&self) -> Vec<(u32, u32)> {
        self.egress.iter().flatten()
            .map(|e| (e.priority, tci::pcp(e.qos) as u32))
            .collect()
    }

    /// Number of live priority translations. # C: O(1)
    pub fn nr_egress(&self) -> u32 { self.nr_egress }
}
