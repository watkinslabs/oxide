//! ctnetlink encoding. Entries are reported as nested attribute trees; the
//! nesting depth and attribute numbers are the ABI `conntrack -L`/`-E` parse.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::entry::{Conn, ProtoState};
use crate::tuple::Tuple;
use crate::uapi::*;

fn align4(n: usize) -> usize { (n + 3) & !3 }

/// Append one attribute with a raw payload. # C: O(len(payload))
pub fn put_attr(out: &mut Vec<u8>, kind: u16, payload: &[u8]) {
    let len = 4 + payload.len();
    out.extend_from_slice(&(len as u16).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(payload);
    out.resize(align4(out.len()), 0);
}

/// Append a big-endian u16 attribute — ctnetlink carries ports and ids in
/// network order, not host order. # C: O(1)
pub fn put_be16(out: &mut Vec<u8>, kind: u16, v: u16) {
    put_attr(out, kind, &v.to_be_bytes());
}

/// Append a big-endian u32 attribute. # C: O(1)
pub fn put_be32(out: &mut Vec<u8>, kind: u16, v: u32) {
    put_attr(out, kind, &v.to_be_bytes());
}

/// Append a big-endian u64 attribute. # C: O(1)
pub fn put_be64(out: &mut Vec<u8>, kind: u16, v: u64) {
    put_attr(out, kind, &v.to_be_bytes());
}

/// Append a u8 attribute. # C: O(1)
pub fn put_u8(out: &mut Vec<u8>, kind: u16, v: u8) { put_attr(out, kind, &[v]); }

/// Open a nested attribute; returns the offset its length must be patched at.
/// # C: O(1)
pub fn nest_start(out: &mut Vec<u8>, kind: u16) -> usize {
    let at = out.len();
    out.extend_from_slice(&0u16.to_ne_bytes());
    // Nested attributes carry the NLA_F_NESTED bit; a parser that trusts the
    // bit will skip a nest that lacks it.
    out.extend_from_slice(&(kind | NLA_F_NESTED).to_ne_bytes());
    at
}

/// Patch a nest's length. # C: O(1)
pub fn nest_end(out: &mut Vec<u8>, at: usize) {
    let len = (out.len() - at) as u16;
    out[at..at + 2].copy_from_slice(&len.to_ne_bytes());
}

/// Netlink's nested-attribute marker bit.
pub const NLA_F_NESTED: u16 = 1 << 15;

/// Encode one tuple as `CTA_TUPLE_IP` + `CTA_TUPLE_PROTO`. # C: O(1)
pub fn put_tuple(out: &mut Vec<u8>, kind: u16, t: &Tuple) {
    let outer = nest_start(out, kind);
    let ip = nest_start(out, CTA_TUPLE_IP);
    if t.l3num == NFPROTO_IPV6 {
        put_attr(out, CTA_IP_V6_SRC, &t.src.addr.0);
        put_attr(out, CTA_IP_V6_DST, &t.dst.addr.0);
    } else {
        put_attr(out, CTA_IP_V4_SRC, &t.src.addr.0[..4]);
        put_attr(out, CTA_IP_V4_DST, &t.dst.addr.0[..4]);
    }
    nest_end(out, ip);
    let pr = nest_start(out, CTA_TUPLE_PROTO);
    put_u8(out, CTA_PROTO_NUM, t.protonum);
    if t.is_icmp() {
        let (id, ty, code) = if t.l3num == NFPROTO_IPV6 {
            (CTA_PROTO_ICMPV6_ID, CTA_PROTO_ICMPV6_TYPE, CTA_PROTO_ICMPV6_CODE)
        } else {
            (CTA_PROTO_ICMP_ID, CTA_PROTO_ICMP_TYPE, CTA_PROTO_ICMP_CODE)
        };
        put_be16(out, id, t.src.proto.port);
        put_u8(out, ty, t.dst.proto.icmp_type);
        put_u8(out, code, t.dst.proto.icmp_code);
    } else {
        put_be16(out, CTA_PROTO_SRC_PORT, t.src.proto.port);
        put_be16(out, CTA_PROTO_DST_PORT, t.dst.proto.port);
    }
    nest_end(out, pr);
    nest_end(out, outer);
}

fn put_counters(out: &mut Vec<u8>, kind: u16, packets: u64, bytes: u64) {
    let n = nest_start(out, kind);
    put_be64(out, CTA_COUNTERS_PACKETS, packets);
    put_be64(out, CTA_COUNTERS_BYTES, bytes);
    nest_end(out, n);
}

/// Encode one entry's attribute body. # C: O(1)
pub fn encode_entry(c: &Arc<Conn>, now: u64, acct: bool) -> Vec<u8> {
    encode_entry_with_counters(c, now, acct, None)
}

/// Encode one entry using counters already atomically removed from the owner.
/// # C: O(1)
pub fn encode_entry_with_counters(c: &Arc<Conn>, now: u64, acct: bool,
                                  counters: Option<[(u64, u64); IP_CT_DIR_MAX]>) -> Vec<u8> {
    let mut out = Vec::new();
    put_tuple(&mut out, CTA_TUPLE_ORIG, &c.orig);
    let reply = c.reply_tuple();
    put_tuple(&mut out, CTA_TUPLE_REPLY, &reply);
    put_be32(&mut out, CTA_STATUS, c.status());
    put_be32(&mut out, CTA_TIMEOUT, c.expires_in(now) as u32);
    put_be32(&mut out, CTA_MARK, c.mark.load(::core::sync::atomic::Ordering::Relaxed));
    put_be32(&mut out, CTA_ID, c.id as u32);
    put_be16(&mut out, CTA_ZONE, c.orig.zone);
    if let Some(master) = c.master.as_ref() {
        put_tuple(&mut out, CTA_TUPLE_MASTER, &master.orig);
    }
    if let ProtoState::Tcp(track) = *c.proto.lock() {
        let pi = nest_start(&mut out, CTA_PROTOINFO);
        let tcp = nest_start(&mut out, CTA_PROTOINFO_TCP);
        put_u8(&mut out, CTA_PROTOINFO_TCP_STATE, track.state);
        put_u8(&mut out, CTA_PROTOINFO_TCP_WSCALE_ORIGINAL, track.seen[0].td_scale);
        put_u8(&mut out, CTA_PROTOINFO_TCP_WSCALE_REPLY, track.seen[1].td_scale);
        put_attr(&mut out, CTA_PROTOINFO_TCP_FLAGS_ORIGINAL,
                 &[track.seen[0].flags, 0]);
        put_attr(&mut out, CTA_PROTOINFO_TCP_FLAGS_REPLY,
                 &[track.seen[1].flags, 0]);
        nest_end(&mut out, tcp);
        nest_end(&mut out, pi);
    }
    if let ProtoState::Sctp(track) = *c.proto.lock() {
        let pi = nest_start(&mut out, CTA_PROTOINFO);
        let sctp = nest_start(&mut out, CTA_PROTOINFO_SCTP);
        put_u8(&mut out, CTA_PROTOINFO_SCTP_STATE, track.state);
        put_be32(&mut out, CTA_PROTOINFO_SCTP_VTAG_ORIGINAL,
                 track.vtag[IP_CT_DIR_ORIGINAL as usize]);
        put_be32(&mut out, CTA_PROTOINFO_SCTP_VTAG_REPLY,
                 track.vtag[IP_CT_DIR_REPLY as usize]);
        nest_end(&mut out, sctp);
        nest_end(&mut out, pi);
    }
    if c.status() & IPS_SEQ_ADJUST != 0 {
        for (dir, kind) in [(IP_CT_DIR_ORIGINAL, CTA_SEQ_ADJ_ORIG),
                             (IP_CT_DIR_REPLY, CTA_SEQ_ADJ_REPLY)] {
            let record = c.seqadj_record(dir);
            let n = nest_start(&mut out, kind);
            put_be32(&mut out, CTA_SEQADJ_CORRECTION_POS, record.correction_pos);
            put_be32(&mut out, CTA_SEQADJ_OFFSET_BEFORE, record.offset_before as u32);
            put_be32(&mut out, CTA_SEQADJ_OFFSET_AFTER, record.offset_after as u32);
            nest_end(&mut out, n);
        }
    }
    if let Some(h) = c.helper.lock().as_ref() {
        let n = nest_start(&mut out, CTA_HELP);
        let mut name = Vec::with_capacity(h.len() + 1);
        name.extend_from_slice(h.as_bytes());
        name.push(0);
        put_attr(&mut out, CTA_HELP_NAME, &name);
        nest_end(&mut out, n);
    }
    if acct {
        let (p, b) = counters.as_ref().map(|v| v[IP_CT_DIR_ORIGINAL as usize])
            .unwrap_or_else(|| c.counters[IP_CT_DIR_ORIGINAL as usize].read());
        put_counters(&mut out, CTA_COUNTERS_ORIG, p, b);
        let (p, b) = counters.as_ref().map(|v| v[IP_CT_DIR_REPLY as usize])
            .unwrap_or_else(|| c.counters[IP_CT_DIR_REPLY as usize].read());
        put_counters(&mut out, CTA_COUNTERS_REPLY, p, b);
    }
    let mut labels = [0u8; NF_CT_LABELS_MAX_SIZE];
    c.labels_copy(&mut labels);
    if labels.iter().any(|&byte| byte != 0) {
        put_attr(&mut out, CTA_LABELS, &labels);
    }
    if let Some(state) = *c.synproxy.lock() {
        let n = nest_start(&mut out, CTA_SYNPROXY);
        put_be32(&mut out, CTA_SYNPROXY_ISN, state.isn);
        put_be32(&mut out, CTA_SYNPROXY_ITS, state.its);
        put_be32(&mut out, CTA_SYNPROXY_TSOFF, state.tsoff as u32);
        nest_end(&mut out, n);
    }
    out
}

/// Bits a ctnetlink write may set on an existing entry. Everything the kernel
/// owns is masked off: letting userspace clear `IPS_CONFIRMED` or set
/// `IPS_SRC_NAT_DONE` would desynchronise the table from the entry.
/// # C: O(1)
pub fn writable_status(requested: u32) -> u32 { requested & !IPS_UNCHANGEABLE_MASK }
