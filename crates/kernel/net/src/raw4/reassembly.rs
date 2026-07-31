use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use sync::{Spinlock, Socket as LockClass};

use crate::addr::Ipv4Addr;
use crate::ipv4::{ip_checksum, Ipv4Hdr};

const RAW4_REASM_TIMEOUT_NS: u64 = 30_000_000_000;

#[derive(Copy, Clone, Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    id: u16,
}

struct Fragment { offset: usize, bytes: Vec<u8> }

struct Flow {
    first_header: Option<Vec<u8>>,
    fragments: Vec<Fragment>,
    total: Option<usize>,
    updated_ns: u64,
}

fn conflicts(flow: &Flow, offset: usize, end: usize, terminal: bool) -> bool {
    if flow.fragments.iter().any(|fragment| {
        let fragment_end = fragment.offset + fragment.bytes.len();
        offset < fragment_end && fragment.offset < end
    }) { return true; }
    if let Some(total) = flow.total {
        if end > total || (terminal && end != total) { return true; }
    }
    terminal && flow.fragments.iter().any(|fragment| fragment.offset + fragment.bytes.len() > end)
}

pub(crate) struct Raw4Reassembly {
    flows: Spinlock<BTreeMap<Key, Flow>, LockClass>,
}

impl Raw4Reassembly {
    /// Build empty namespace-local raw reassembly state. # C: O(1)
    pub(crate) fn new() -> Self { Self { flows: Spinlock::new(BTreeMap::new()) } }

    /// Record one validated fragment and return one normalized packet on completion. # C: O(N log N)
    pub(crate) fn push(&self, now_ns: u64, packet: &[u8], hdr: Ipv4Hdr) -> Option<Vec<u8>> {
        let ihl = hdr.ihl_bytes();
        let total = hdr.total_len as usize;
        if packet.len() < total || total < ihl { return None; }
        let offset = ((hdr.flags_frag & 0x1fff) as usize) * 8;
        let more = hdr.flags_frag & 0x2000 != 0;
        let key = Key { src: hdr.src, dst: hdr.dst, protocol: hdr.proto, id: hdr.id };
        let mut all = self.flows.lock();
        all.retain(|_, flow| now_ns.saturating_sub(flow.updated_ns) < RAW4_REASM_TIMEOUT_NS);
        let body = &packet[ihl..total];
        let end = offset.checked_add(body.len())?;
        if all.get(&key).map(|flow| conflicts(flow, offset, end, !more)).unwrap_or(false) {
            all.remove(&key);
            return None;
        }
        let flow = all.entry(key).or_insert_with(|| Flow {
            first_header: None, fragments: Vec::new(), total: None, updated_ns: now_ns,
        });
        flow.updated_ns = now_ns;
        if offset == 0 { flow.first_header = Some(packet[..ihl].to_vec()); }
        flow.fragments.push(Fragment { offset, bytes: body.to_vec() });
        if !more { flow.total = Some(end); }
        let payload_len = flow.total?;
        let header = flow.first_header.as_ref()?;
        // STABLE ON PURPOSE (costs a 4 KiB `driftsort` scratch frame): a peer may send two
        // fragments at the same offset; which one the reassembled datagram
        // keeps is decided by arrival order, so that order must survive.
        flow.fragments.sort_by_key(|fragment| fragment.offset);
        let mut covered = 0usize;
        for fragment in &flow.fragments {
            if fragment.offset != covered { return None; }
            covered += fragment.bytes.len();
        }
        if covered != payload_len { return None; }
        let mut out = alloc::vec![0u8; header.len() + payload_len];
        out[..header.len()].copy_from_slice(header);
        for fragment in &flow.fragments {
            let start = header.len() + fragment.offset;
            out[start..start + fragment.bytes.len()].copy_from_slice(&fragment.bytes);
        }
        let packet_len = out.len() as u16;
        out[2..4].copy_from_slice(&packet_len.to_be_bytes());
        out[6..8].copy_from_slice(&0u16.to_be_bytes());
        out[10..12].copy_from_slice(&0u16.to_be_bytes());
        let checksum = ip_checksum(&out[..header.len()]);
        out[10..12].copy_from_slice(&checksum.to_be_bytes());
        all.remove(&key);
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipv4::IPV4_HDR_LEN;

    fn push(table: &Raw4Reassembly, id: u16, offset: usize, payload: &[u8], more: bool)
        -> Option<Vec<u8>>
    {
        assert_eq!(offset & 7, 0);
        let flags_frag = (offset / 8) as u16 | if more { 0x2000 } else { 0 };
        let hdr = Ipv4Hdr {
            version_ihl: 0x45, tos: 0, total_len: (IPV4_HDR_LEN + payload.len()) as u16,
            id, flags_frag, ttl: 64, proto: 17, checksum: 0,
            src: Ipv4Addr::LOOPBACK, dst: Ipv4Addr::LOOPBACK,
        };
        let mut packet = alloc::vec![0u8; IPV4_HDR_LEN];
        packet.extend_from_slice(payload);
        table.push(1, &packet, hdr)
    }

    fn clean_retry(table: &Raw4Reassembly, id: u16) {
        assert!(push(table, id, 0, b"fresh---", true).is_none());
        let packet = push(table, id, 8, b"tail", false).unwrap();
        assert_eq!(&packet[IPV4_HDR_LEN..], b"fresh---tail");
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
            let table = Raw4Reassembly::new();
            let id = index as u16;
            assert!(push(&table, id, queued_offset, &alloc::vec![1; queued_len], true).is_none());
            assert!(push(&table, id, incoming_offset, &alloc::vec![2; incoming_len], true).is_none());
            clean_retry(&table, id);
        }
    }

    #[test]
    fn shorter_terminal_below_queued_data_kills_queue_without_panicking() {
        let table = Raw4Reassembly::new();
        assert!(push(&table, 9, 24, b"high----", true).is_none());
        assert!(push(&table, 9, 8, b"terminal", false).is_none());
        clean_retry(&table, 9);
    }
}
