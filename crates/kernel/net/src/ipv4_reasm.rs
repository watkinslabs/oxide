// F195: IPv4 reassembly per RFC 791 §3.2. Per-flow (src, dst,
// proto, id) hole-list state; finalize when MF=0 lands AND all
// preceding fragments have arrived. Timeout drops half-assembled
// state after REASM_TIMEOUT_NS (30s; Linux default 30s).

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use crate::addr::Ipv4Addr;

/// Key: (src_ip, dst_ip, proto, id). One flow's reassembly state.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ReasmKey {
    pub src:   Ipv4Addr,
    pub dst:   Ipv4Addr,
    pub proto: u8,
    pub id:    u16,
}

const REASM_TIMEOUT_NS: u64 = 30 * 1_000_000_000;
const REASM_MAX_BYTES:  usize = 65_535;

#[derive(Debug)]
struct Frag {
    offset: usize,
    bytes:  Vec<u8>,
}

#[derive(Debug)]
struct Flow {
    frags:  Vec<Frag>,
    total:  Option<usize>,   // Set when MF=0 fragment seen.
    last_ns: u64,
}

/// Process-global reassembly table.
pub struct ReasmTable {
    flows: Spinlock<BTreeMap<ReasmKey, Flow>, LockClass>,
}

impl ReasmTable {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { flows: Spinlock::new(BTreeMap::new()) }
    }

    /// Offer a fragment (`offset_bytes`, `payload`, `more_fragments`).
    /// Returns Some(reassembled) when the flow completes; None if more
    /// fragments are still expected (or the fragment was invalid).
    /// # C: O(N frags)
    pub fn push(
        &self, key: ReasmKey, now_ns: u64,
        offset_bytes: usize, payload: &[u8], mf: bool,
    ) -> Option<Vec<u8>> {
        if offset_bytes + payload.len() > REASM_MAX_BYTES { return None; }
        let mut g = self.flows.lock();
        // Evict stale flows opportunistically.
        g.retain(|_, f| now_ns.saturating_sub(f.last_ns) < REASM_TIMEOUT_NS);
        let flow = g.entry(key).or_insert(Flow {
            frags: Vec::new(), total: None, last_ns: now_ns,
        });
        flow.last_ns = now_ns;
        flow.frags.push(Frag { offset: offset_bytes, bytes: payload.to_vec() });
        if !mf {
            flow.total = Some(offset_bytes + payload.len());
        }
        // Try to finalize.
        let total = flow.total?;
        // Sort + verify contiguous coverage [0, total).
        flow.frags.sort_by_key(|f| f.offset);
        let mut cur = 0usize;
        for f in &flow.frags {
            if f.offset > cur { return None; }    // hole
            cur = core::cmp::max(cur, f.offset + f.bytes.len());
        }
        if cur < total { return None; }
        // Assemble.
        let mut out = alloc::vec![0u8; total];
        for f in &flow.frags {
            let end = core::cmp::min(f.offset + f.bytes.len(), total);
            out[f.offset..end].copy_from_slice(&f.bytes[..end - f.offset]);
        }
        g.remove(&key);
        Some(out)
    }

    /// Time-based GC. Caller invokes from the periodic tick.
    /// # C: O(N flows)
    pub fn gc(&self, now_ns: u64) {
        let mut g = self.flows.lock();
        g.retain(|_, f| now_ns.saturating_sub(f.last_ns) < REASM_TIMEOUT_NS);
    }
}

impl Default for ReasmTable { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_two_fragments() {
        let t = ReasmTable::new();
        let key = ReasmKey { src: Ipv4Addr::LOOPBACK, dst: Ipv4Addr::LOOPBACK, proto: 17, id: 1 };
        assert!(t.push(key, 1, 0,    b"hello", true).is_none());
        let r = t.push(key, 1, 5, b"world", false).unwrap();
        assert_eq!(r, b"helloworld");
    }

    #[test]
    fn ooo_two_fragments() {
        let t = ReasmTable::new();
        let key = ReasmKey { src: Ipv4Addr::LOOPBACK, dst: Ipv4Addr::LOOPBACK, proto: 17, id: 2 };
        assert!(t.push(key, 1, 5, b"world", false).is_none());
        let r = t.push(key, 1, 0, b"hello", true).unwrap();
        assert_eq!(r, b"helloworld");
    }

    #[test]
    fn stale_dropped() {
        let t = ReasmTable::new();
        let key = ReasmKey { src: Ipv4Addr::LOOPBACK, dst: Ipv4Addr::LOOPBACK, proto: 17, id: 3 };
        let _ = t.push(key, 1, 0, b"a", true);
        // Time jumps past timeout; another push triggers retain GC.
        let r = t.push(key, 60_000_000_000, 1, b"b", false);
        // First frag was evicted, second has total=2 but only its own
        // 1 byte covered → no completion.
        assert!(r.is_none());
    }
}
