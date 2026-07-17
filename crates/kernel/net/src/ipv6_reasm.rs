// IPv6 Fragment extension reassembly per RFC 8200. Per-flow
// (namespace, src, dst, next_header, identification) state; finalize when the last
// fragment lands and the fragmentable payload has contiguous coverage.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use crate::addr::{Ipv6Addr, NetIfaceId};

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ReasmKey {
    pub net_ns:     u64,
    pub iface:      Option<NetIfaceId>,
    pub src:         Ipv6Addr,
    pub dst:         Ipv6Addr,
    pub next_header: u8,
    pub id:          u32,
}

const REASM_TIMEOUT_NS: u64 = 30 * 1_000_000_000;
const REASM_MAX_BYTES: usize = 65_535;

#[derive(Debug)]
struct Frag {
    offset: usize,
    bytes: Vec<u8>,
}

#[derive(Debug)]
struct Flow {
    frags: Vec<Frag>,
    total: Option<usize>,
    last_ns: u64,
}

fn conflicts(flow: &Flow, offset: usize, end: usize, terminal: bool) -> bool {
    if flow.frags.iter().any(|frag| {
        let frag_end = frag.offset + frag.bytes.len();
        offset < frag_end && frag.offset < end
    }) { return true; }
    if let Some(total) = flow.total {
        if end > total || (terminal && end != total) { return true; }
    }
    terminal && flow.frags.iter().any(|frag| frag.offset + frag.bytes.len() > end)
}

pub struct ReasmTable {
    flows: Spinlock<BTreeMap<ReasmKey, Flow>, LockClass>,
}

impl ReasmTable {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { flows: Spinlock::new(BTreeMap::new()) }
    }

    /// Offer a fragmentable-part slice. Returns the complete L4/ext payload
    /// when all bytes in [0,total) are present. # C: O(N frags)
    pub fn push(
        &self,
        key: ReasmKey,
        now_ns: u64,
        offset_bytes: usize,
        payload: &[u8],
        more_fragments: bool,
    ) -> Option<Vec<u8>> {
        let end = offset_bytes.checked_add(payload.len())?;
        if end > REASM_MAX_BYTES { return None; }
        if more_fragments && (payload.len() & 7) != 0 { return None; }

        let mut g = self.flows.lock();
        g.retain(|_, f| now_ns.saturating_sub(f.last_ns) < REASM_TIMEOUT_NS);
        if g.get(&key).map(|flow| conflicts(flow, offset_bytes, end, !more_fragments))
            .unwrap_or(false)
        {
            g.remove(&key);
            return None;
        }
        let flow = g.entry(key).or_insert(Flow {
            frags: Vec::new(),
            total: None,
            last_ns: now_ns,
        });
        flow.last_ns = now_ns;
        flow.frags.push(Frag { offset: offset_bytes, bytes: payload.to_vec() });
        if !more_fragments {
            flow.total = Some(end);
        }

        let total = flow.total?;
        flow.frags.sort_by_key(|f| f.offset);
        let mut cur = 0usize;
        for frag in &flow.frags {
            if frag.offset != cur { return None; }
            cur += frag.bytes.len();
        }
        if cur != total { return None; }

        let mut out = alloc::vec![0u8; total];
        for frag in &flow.frags {
            out[frag.offset..frag.offset + frag.bytes.len()].copy_from_slice(&frag.bytes);
        }
        g.remove(&key);
        Some(out)
    }

    /// # C: O(N flows)
    pub fn gc(&self, now_ns: u64) {
        self.flows.lock().retain(|_, f| now_ns.saturating_sub(f.last_ns) < REASM_TIMEOUT_NS);
    }

    /// Remove every incomplete flow owned by one network namespace. # C: O(N flows)
    pub fn remove_namespace(&self, net_ns: u64) -> usize {
        let mut g = self.flows.lock();
        let before = g.len();
        g.retain(|key, _| key.net_ns != net_ns);
        before - g.len()
    }

    /// Remove incomplete flows received through one interface. # C: O(N flows)
    pub fn remove_iface(&self, net_ns: u64, iface: NetIfaceId) -> usize {
        let mut g = self.flows.lock();
        let before = g.len();
        g.retain(|key, _| !(key.net_ns == net_ns && key.iface == Some(iface)));
        before - g.len()
    }
}

impl Default for ReasmTable {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u32) -> ReasmKey {
        ReasmKey {
            net_ns: 0, iface: None,
            src: Ipv6Addr::LOOPBACK,
            dst: Ipv6Addr::LOOPBACK,
            next_header: 17,
            id,
        }
    }

    #[test]
    fn out_of_order_fragments_complete() {
        let t = ReasmTable::new();
        assert!(t.push(key(1), 1, 8, b"world", false).is_none());
        let r = t.push(key(1), 1, 0, b"hello---", true).unwrap();
        assert_eq!(r, b"hello---world");
    }

    #[test]
    fn rejects_non_final_unaligned_fragment() {
        let t = ReasmTable::new();
        assert!(t.push(key(2), 1, 0, b"short", true).is_none());
        assert!(t.push(key(2), 1, 5, b"tail", false).is_none());
    }

    #[test]
    fn identical_fragment_tuples_are_namespace_isolated() {
        let t = ReasmTable::new();
        let a = ReasmKey { net_ns: 41, ..key(3) };
        let b = ReasmKey { net_ns: 42, ..a };
        assert!(t.push(a, 1, 0, b"aaaaaaaa", true).is_none());
        assert!(t.push(b, 1, 8, b"BBBB", false).is_none());
        assert_eq!(t.push(a, 1, 8, b"AAAA", false).unwrap(), b"aaaaaaaaAAAA");
        assert_eq!(t.push(b, 1, 0, b"bbbbbbbb", true).unwrap(), b"bbbbbbbbBBBB");
    }

    #[test]
    fn namespace_removal_preserves_foreign_flows() {
        let t = ReasmTable::new();
        let a = ReasmKey { net_ns: 41, ..key(4) };
        let b = ReasmKey { net_ns: 42, ..a };
        assert!(t.push(a, 1, 0, b"aaaaaaaa", true).is_none());
        assert!(t.push(b, 1, 0, b"bbbbbbbb", true).is_none());
        assert_eq!(t.remove_namespace(41), 1);
        assert!(t.push(a, 2, 8, b"AAAA", false).is_none());
        assert_eq!(t.push(b, 2, 8, b"BBBB", false).unwrap(), b"bbbbbbbbBBBB");
    }

    #[test]
    fn interface_removal_preserves_foreign_flows() {
        let t = ReasmTable::new();
        let a = ReasmKey { net_ns: 41, iface: Some(NetIfaceId::from_raw(1)), ..key(5) };
        let b = ReasmKey { iface: Some(NetIfaceId::from_raw(2)), ..a };
        assert!(t.push(a, 1, 0, b"aaaaaaaa", true).is_none());
        assert!(t.push(b, 1, 0, b"bbbbbbbb", true).is_none());
        assert_eq!(t.remove_iface(41, NetIfaceId::from_raw(1)), 1);
        assert!(t.push(a, 2, 8, b"AAAA", false).is_none());
        assert_eq!(t.push(b, 2, 8, b"BBBB", false).unwrap(), b"bbbbbbbbBBBB");
    }

    fn clean_retry(table: &ReasmTable, flow_key: ReasmKey) {
        assert!(table.push(flow_key, 2, 0, b"fresh---", true).is_none());
        assert_eq!(table.push(flow_key, 2, 8, b"tail", false).unwrap(), b"fresh---tail");
    }

    #[test]
    fn every_overlap_shape_kills_queue_and_allows_clean_retry() {
        let shapes = [
            (16, 16, 16, 16), // duplicate
            (8, 24, 16, 8),   // incoming contained
            (16, 8, 8, 24),   // incoming contains
            (16, 16, 8, 16),  // incoming overlaps left edge
            (8, 16, 16, 16),  // incoming overlaps right edge
        ];
        for (index, &(queued_offset, queued_len, incoming_offset, incoming_len))
            in shapes.iter().enumerate()
        {
            let table = ReasmTable::new();
            let flow_key = key(10 + index as u32);
            assert!(table.push(flow_key, 1, queued_offset,
                &alloc::vec![1; queued_len], true).is_none());
            assert!(table.push(flow_key, 1, incoming_offset,
                &alloc::vec![2; incoming_len], true).is_none());
            clean_retry(&table, flow_key);
        }
    }

    #[test]
    fn shorter_terminal_below_queued_data_kills_queue_without_panicking() {
        let table = ReasmTable::new();
        let flow_key = key(20);
        assert!(table.push(flow_key, 1, 24, b"high----", true).is_none());
        assert!(table.push(flow_key, 1, 8, b"terminal", false).is_none());
        clean_retry(&table, flow_key);
    }
}
