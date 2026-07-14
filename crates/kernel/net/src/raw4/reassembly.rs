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
        let flow = all.entry(key).or_insert_with(|| Flow {
            first_header: None, fragments: Vec::new(), total: None, updated_ns: now_ns,
        });
        flow.updated_ns = now_ns;
        if offset == 0 { flow.first_header = Some(packet[..ihl].to_vec()); }
        let body = &packet[ihl..total];
        if !flow.fragments.iter().any(|f| f.offset == offset && f.bytes == body) {
            flow.fragments.push(Fragment { offset, bytes: body.to_vec() });
        }
        if !more { flow.total = Some(offset + body.len()); }
        let payload_len = flow.total?;
        let header = flow.first_header.as_ref()?;
        flow.fragments.sort_by_key(|fragment| fragment.offset);
        let mut covered = 0usize;
        for fragment in &flow.fragments {
            if fragment.offset > covered { return None; }
            covered = covered.max(fragment.offset + fragment.bytes.len());
        }
        if covered < payload_len { return None; }
        let mut out = alloc::vec![0u8; header.len() + payload_len];
        out[..header.len()].copy_from_slice(header);
        for fragment in &flow.fragments {
            let end = (fragment.offset + fragment.bytes.len()).min(payload_len);
            out[header.len() + fragment.offset..header.len() + end]
                .copy_from_slice(&fragment.bytes[..end - fragment.offset]);
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
