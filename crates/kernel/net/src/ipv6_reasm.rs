// IPv6 Fragment extension reassembly per RFC 8200. Per-flow
// (src, dst, next_header, identification) state; finalize when the last
// fragment lands and the fragmentable payload has contiguous coverage.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use crate::addr::Ipv6Addr;

#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ReasmKey {
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
        if offset_bytes + payload.len() > REASM_MAX_BYTES { return None; }
        if more_fragments && (payload.len() & 7) != 0 { return None; }

        let mut g = self.flows.lock();
        g.retain(|_, f| now_ns.saturating_sub(f.last_ns) < REASM_TIMEOUT_NS);
        let flow = g.entry(key).or_insert(Flow {
            frags: Vec::new(),
            total: None,
            last_ns: now_ns,
        });
        flow.last_ns = now_ns;
        flow.frags.push(Frag { offset: offset_bytes, bytes: payload.to_vec() });
        if !more_fragments {
            flow.total = Some(offset_bytes + payload.len());
        }

        let total = flow.total?;
        flow.frags.sort_by_key(|f| f.offset);
        let mut cur = 0usize;
        for frag in &flow.frags {
            if frag.offset > cur { return None; }
            cur = core::cmp::max(cur, frag.offset + frag.bytes.len());
        }
        if cur < total { return None; }

        let mut out = alloc::vec![0u8; total];
        for frag in &flow.frags {
            let end = core::cmp::min(frag.offset + frag.bytes.len(), total);
            out[frag.offset..end].copy_from_slice(&frag.bytes[..end - frag.offset]);
        }
        g.remove(&key);
        Some(out)
    }

    /// # C: O(N flows)
    pub fn gc(&self, now_ns: u64) {
        self.flows.lock().retain(|_, f| now_ns.saturating_sub(f.last_ns) < REASM_TIMEOUT_NS);
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
}
