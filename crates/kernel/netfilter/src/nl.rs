use alloc::{string::String, vec::Vec};

use ::netlink::{flags, msg, nlmsg_align, Nlmsghdr};

use crate::{
    Nfgenmsg, NftChain, NftRule, NftSet, NftTable, nft_dispatch, nft_msg, nfta_chain, nfta_rule,
    nfta_flowtable, nfta_set, nfta_table, subsys,
};

pub(crate) fn put_nlattr(out: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let total = 4 + payload.len();
    out.extend_from_slice(&(total as u16).to_ne_bytes());
    out.extend_from_slice(&ty.to_ne_bytes());
    out.extend_from_slice(payload);
    let pad = nlmsg_align(total) - total;
    for _ in 0..pad { out.push(0); }
}

pub(crate) fn put_nlattr_u32(out: &mut Vec<u8>, ty: u16, v: u32) {
    put_nlattr(out, ty, &v.to_be_bytes());
}

pub(crate) fn put_nlattr_str(out: &mut Vec<u8>, ty: u16, s: &str) {
    let mut payload: Vec<u8> = Vec::with_capacity(s.len() + 1);
    payload.extend_from_slice(s.as_bytes());
    payload.push(0);
    put_nlattr(out, ty, &payload);
}

pub(crate) fn find_str_attr<'a>(attrs: &'a [u8], target: u16) -> Option<&'a str> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        if nla_type == target {
            let payload = &attrs[off + 4..off + nla_len];
            let end = payload.iter().position(|&b| b == 0).unwrap_or(payload.len());
            return core::str::from_utf8(&payload[..end]).ok();
        }
        off += nlmsg_align(nla_len);
    }
    None
}

pub(crate) fn find_u32_attr(attrs: &[u8], target: u16) -> Option<u32> {
    let raw = find_bytes_attr(attrs, target)?;
    if raw.len() != 4 { return None; }
    Some(u32::from_be_bytes(raw.try_into().ok()?))
}

pub(crate) fn find_u64_attr(attrs: &[u8], target: u16) -> Option<u64> {
    let raw = find_bytes_attr(attrs, target)?;
    if raw.len() != 8 { return None; }
    Some(u64::from_be_bytes(raw.try_into().ok()?))
}

pub(crate) fn find_bytes_attr<'a>(attrs: &'a [u8], target: u16) -> Option<&'a [u8]> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        if nla_type == target { return Some(&attrs[off + 4..off + nla_len]); }
        off += nlmsg_align(nla_len);
    }
    None
}

fn find_be16_attr(attrs: &[u8], target: u16) -> Option<u16> {
    let raw = find_bytes_attr(attrs, target)?;
    (raw.len() == 2).then(|| u16::from_be_bytes([raw[0], raw[1]]))
}

fn find_u8_attr(attrs: &[u8], target: u16) -> Option<u8> {
    let raw = find_bytes_attr(attrs, target)?;
    (raw.len() == 1).then(|| raw[0])
}

fn parse_ct_tuple(raw: &[u8], family: u8, zone: u16) -> Option<::conntrack::Tuple> {
    use ::conntrack::{InetAddr, ProtoPart, Tuple, TupleEnd};
    let ip = find_bytes_attr(raw, ::conntrack::uapi::CTA_TUPLE_IP)?;
    let (src, dst) = if family == ::conntrack::uapi::NFPROTO_IPV6 {
        let src = find_bytes_attr(ip, ::conntrack::uapi::CTA_IP_V6_SRC)?;
        let dst = find_bytes_attr(ip, ::conntrack::uapi::CTA_IP_V6_DST)?;
        (InetAddr::v6(src.try_into().ok()?), InetAddr::v6(dst.try_into().ok()?))
    } else {
        let src = find_bytes_attr(ip, ::conntrack::uapi::CTA_IP_V4_SRC)?;
        let dst = find_bytes_attr(ip, ::conntrack::uapi::CTA_IP_V4_DST)?;
        (InetAddr::v4(src.try_into().ok()?), InetAddr::v4(dst.try_into().ok()?))
    };
    let proto = find_bytes_attr(raw, ::conntrack::uapi::CTA_TUPLE_PROTO)?;
    let protonum = find_u8_attr(proto, ::conntrack::uapi::CTA_PROTO_NUM)?;
    let icmp = (family == ::conntrack::uapi::NFPROTO_IPV4
        && protonum == ::conntrack::uapi::IPPROTO_ICMP)
        || (family == ::conntrack::uapi::NFPROTO_IPV6
            && protonum == ::conntrack::uapi::IPPROTO_ICMPV6);
    let (src_proto, dst_proto) = if icmp {
        let id_attr = if family == ::conntrack::uapi::NFPROTO_IPV6 {
            ::conntrack::uapi::CTA_PROTO_ICMPV6_ID
        } else { ::conntrack::uapi::CTA_PROTO_ICMP_ID };
        let type_attr = if family == ::conntrack::uapi::NFPROTO_IPV6 {
            ::conntrack::uapi::CTA_PROTO_ICMPV6_TYPE
        } else { ::conntrack::uapi::CTA_PROTO_ICMP_TYPE };
        let code_attr = if family == ::conntrack::uapi::NFPROTO_IPV6 {
            ::conntrack::uapi::CTA_PROTO_ICMPV6_CODE
        } else { ::conntrack::uapi::CTA_PROTO_ICMP_CODE };
        (ProtoPart::icmp(find_be16_attr(proto, id_attr)?,
                         find_u8_attr(proto, type_attr)?, find_u8_attr(proto, code_attr)?),
         ProtoPart::default())
    } else {
        (ProtoPart::port(find_be16_attr(proto, ::conntrack::uapi::CTA_PROTO_SRC_PORT)?),
         ProtoPart::port(find_be16_attr(proto, ::conntrack::uapi::CTA_PROTO_DST_PORT)?))
    };
    Some(Tuple {
        src: TupleEnd { addr: src, proto: src_proto },
        dst: TupleEnd { addr: dst, proto: dst_proto },
        l3num: family, protonum, zone,
    })
}

fn parse_seqadj(raw: &[u8]) -> Option<::conntrack::entry::SeqAdjust> {
    Some(::conntrack::entry::SeqAdjust {
        correction_pos: find_u32_attr(raw, ::conntrack::uapi::CTA_SEQADJ_CORRECTION_POS)?,
        offset_before: find_u32_attr(raw, ::conntrack::uapi::CTA_SEQADJ_OFFSET_BEFORE)? as i32,
        offset_after: find_u32_attr(raw, ::conntrack::uapi::CTA_SEQADJ_OFFSET_AFTER)? as i32,
        active: true,
    })
}

fn parse_seqadjs(attrs: &[u8])
    -> Result<[Option<::conntrack::entry::SeqAdjust>; ::conntrack::uapi::IP_CT_DIR_MAX], ()>
{
    let orig = find_bytes_attr(attrs, ::conntrack::uapi::CTA_SEQ_ADJ_ORIG)
        .map(|raw| parse_seqadj(raw).ok_or(())).transpose()?;
    let reply = find_bytes_attr(attrs, ::conntrack::uapi::CTA_SEQ_ADJ_REPLY)
        .map(|raw| parse_seqadj(raw).ok_or(())).transpose()?;
    Ok([orig, reply])
}

fn parse_tcp_protoinfo(attrs: &[u8])
    -> Result<Option<::conntrack::entry::TcpProtoInfoUpdate>, ()>
{
    let Some(protoinfo) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_PROTOINFO)
        else { return Ok(None); };
    let Some(tcp) = find_bytes_attr(protoinfo, ::conntrack::uapi::CTA_PROTOINFO_TCP)
        else { return Ok(Some(Default::default())); };
    let state = find_u8_attr(tcp, ::conntrack::uapi::CTA_PROTOINFO_TCP_STATE);
    if state.is_some_and(|state| state > ::conntrack::proto::tcp_state::TCP_CONNTRACK_SYN_SENT2) {
        return Err(());
    }
    for kind in [::conntrack::uapi::CTA_PROTOINFO_TCP_WSCALE_ORIGINAL,
                 ::conntrack::uapi::CTA_PROTOINFO_TCP_WSCALE_REPLY] {
        if find_u8_attr(tcp, kind).is_some_and(|scale| scale > ::conntrack::proto::tcp_state::TCP_MAX_WSCALE) {
            return Err(());
        }
    }
    let parse_flags = |kind| {
        let Some(raw) = find_bytes_attr(tcp, kind) else { return Ok(None); };
        if raw.len() != 2 { return Err(()); }
        Ok(Some((raw[0], raw[1])))
    };
    Ok(Some(::conntrack::entry::TcpProtoInfoUpdate {
        state,
        flags: [
            parse_flags(::conntrack::uapi::CTA_PROTOINFO_TCP_FLAGS_ORIGINAL)?,
            parse_flags(::conntrack::uapi::CTA_PROTOINFO_TCP_FLAGS_REPLY)?,
        ],
    }))
}

fn parse_helper_name(attrs: &[u8]) -> Result<Option<String>, ()> {
    let Some(help) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_HELP) else {
        return Ok(None);
    };
    let Some(raw) = find_bytes_attr(help, ::conntrack::uapi::CTA_HELP_NAME) else {
        return Err(());
    };
    if raw.len() < 1 || raw.len() > 16 || *raw.last().unwrap() != 0 {
        return Err(());
    }
    String::from_utf8(raw[..raw.len() - 1].to_vec()).map(Some).map_err(|_| ())
}

/// Flush the canonical conntrack event queue through NETLINK_NETFILTER.
/// # C: O(N events × listeners)
pub(crate) fn flush_conntrack_events(namespace: u64) {
    for (family, events, attrs) in ::net::global_stack().conntrack_drain_events_in(namespace) {
        let (command, msg_flags, group) = if events & ::conntrack::uapi::IPCT_DESTROY != 0 {
            (conntrack::uapi::IPCTNL_MSG_CT_DELETE, 0, 3u32)
        } else if events & (::conntrack::uapi::IPCT_NEW | ::conntrack::uapi::IPCT_RELATED) != 0 {
            (conntrack::uapi::IPCTNL_MSG_CT_NEW,
             flags::NLM_F_CREATE | flags::NLM_F_EXCL, 1u32)
        } else {
            (conntrack::uapi::IPCTNL_MSG_CT_NEW, 0, 2u32)
        };
        let mut body = Vec::with_capacity(Nfgenmsg::SIZE + attrs.len());
        let mut nfg = [0u8; Nfgenmsg::SIZE];
        Nfgenmsg { nfgen_family: family, version: 0, res_id: 0 }.write_to(&mut nfg);
        body.extend_from_slice(&nfg);
        body.extend_from_slice(&attrs);
        let total = Nlmsghdr::SIZE + body.len();
        let hdr = Nlmsghdr {
            nlmsg_len: total as u32,
            nlmsg_type: ((subsys::NFNL_SUBSYS_CTNETLINK as u16) << 8) | command as u16,
            nlmsg_flags: msg_flags,
            nlmsg_seq: 0,
            nlmsg_pid: 0,
        };
        let mut msg = Vec::with_capacity(total);
        let mut hb = [0u8; Nlmsghdr::SIZE];
        hdr.write_to(&mut hb);
        msg.extend_from_slice(&hb);
        msg.extend_from_slice(&body);
        while msg.len() % 4 != 0 { msg.push(0); }
        let _ = ::netlink::netfilter_multicast_in(namespace, group, &msg);
    }
}

pub(crate) fn nlmsg_ack(req: &Nlmsghdr, err: i32) -> Vec<u8> {
    let total = Nlmsghdr::SIZE + 4 + Nlmsghdr::SIZE;
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: msg::NLMSG_ERROR,
        nlmsg_flags: 0,
        nlmsg_seq: req.nlmsg_seq,
        nlmsg_pid: req.nlmsg_pid,
    };
    let mut out = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&err.to_ne_bytes());
    let mut req_buf = [0u8; Nlmsghdr::SIZE];
    req.write_to(&mut req_buf);
    out.extend_from_slice(&req_buf);
    out
}

fn handle_one(full_msg: &[u8], namespace: u64) -> Vec<u8> {
    let hdr = match Nlmsghdr::parse(full_msg) {
        Some(h) => h,
        None => return Vec::new(),
    };
    let nfg_off = Nlmsghdr::SIZE;
    let nfg = match Nfgenmsg::parse(&full_msg[nfg_off..]) {
        Some(n) => n,
        None => return nlmsg_ack(&hdr, -22),
    };
    let attrs = &full_msg[nfg_off + Nfgenmsg::SIZE..];
    match (hdr.nlmsg_type >> 8) as u8 {
        subsys::NFNL_SUBSYS_CTNETLINK => handle_ct(&hdr, &nfg, attrs, namespace),
        subsys::NFNL_SUBSYS_NFTABLES => nft_dispatch::handle_nft(
            namespace, &hdr, &nfg, (hdr.nlmsg_type & 0xFF) as u8, attrs),
        _ => nlmsg_ack(&hdr, 0),
    }
}

/// ctnetlink's GET dump is the read path used by `conntrack -L`. Each entry
/// is encoded by conntrack itself; this layer only supplies the nfgenmsg and
/// multipart netlink framing.
fn handle_ct(req: &Nlmsghdr, nfg: &Nfgenmsg, attrs: &[u8], namespace: u64) -> Vec<u8> {
    let cmd = (req.nlmsg_type & 0xff) as u8;
    if cmd == conntrack::uapi::IPCTNL_MSG_CT_GET {
        return handle_ct_get(req, nfg, attrs, namespace);
    }
    if cmd == conntrack::uapi::IPCTNL_MSG_CT_DELETE {
        let tuple_attr = find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_ORIG)
            .or_else(|| find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_REPLY));
        if let Some(raw) = tuple_attr {
            let Some(tuple) = parse_ct_tuple(raw, nfg.nfgen_family,
                find_be16_attr(attrs, ::conntrack::uapi::CTA_ZONE).unwrap_or(0)) else {
                return nlmsg_ack(req, -22);
            };
            let ok = ::net::global_stack().conntrack_delete_tuple_in(namespace, tuple);
            return nlmsg_ack(req, if ok { 0 } else { -2 });
        }
    }
    if cmd == conntrack::uapi::IPCTNL_MSG_CT_NEW {
        if let Some(raw) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_ORIG) {
            let Some(tuple) = parse_ct_tuple(raw, nfg.nfgen_family,
                find_be16_attr(attrs, ::conntrack::uapi::CTA_ZONE).unwrap_or(0)) else {
                return nlmsg_ack(req, -22);
            };
            let existing = ::net::global_stack().conntrack_id_tuple_in(namespace, tuple);
            if let Some(id) = existing {
                if req.nlmsg_flags & flags::NLM_F_EXCL != 0 {
                    return nlmsg_ack(req, -17);
                }
                if find_bytes_attr(attrs, ::conntrack::uapi::CTA_HELP).is_some() {
                    // Linux cannot attach a helper to an existing flow that
                    // has no helper extension; changing a sibling helper is
                    // also not permitted by ctnetlink.
                    return nlmsg_ack(req, -95);
                }
                let mark = find_u32_attr(attrs, ::conntrack::uapi::CTA_MARK).map(|value| {
                    (value, find_u32_attr(attrs, ::conntrack::uapi::CTA_MARK_MASK))
                });
                let Ok(seqadj) = parse_seqadjs(attrs) else { return nlmsg_ack(req, -22); };
                let Ok(protoinfo) = parse_tcp_protoinfo(attrs) else { return nlmsg_ack(req, -22); };
                let ok = ::net::global_stack().conntrack_update_in(
                    namespace, id, find_u32_attr(attrs, ::conntrack::uapi::CTA_TIMEOUT),
                    find_u32_attr(attrs, ::conntrack::uapi::CTA_STATUS), mark, seqadj, protoinfo);
                return nlmsg_ack(req, if ok { 0 } else { -2 });
            }
            if req.nlmsg_flags & flags::NLM_F_CREATE == 0 {
                return nlmsg_ack(req, -2);
            }
            let Some(timeout) = find_u32_attr(attrs, ::conntrack::uapi::CTA_TIMEOUT) else {
                return nlmsg_ack(req, -22);
            };
            let reply = find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_REPLY)
                .and_then(|raw| parse_ct_tuple(raw, nfg.nfgen_family, tuple.zone));
            if find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_REPLY).is_some()
                && reply.is_none() {
                return nlmsg_ack(req, -22);
            }
            let Ok(protoinfo) = parse_tcp_protoinfo(attrs) else { return nlmsg_ack(req, -22); };
            let Ok(helper) = parse_helper_name(attrs) else { return nlmsg_ack(req, -22); };
            let id = ::net::global_stack().conntrack_create_tuple_in(
                namespace, tuple, reply, timeout,
                find_u32_attr(attrs, ::conntrack::uapi::CTA_STATUS).unwrap_or(0),
                find_u32_attr(attrs, ::conntrack::uapi::CTA_MARK), protoinfo, helper);
            return nlmsg_ack(req, if id.is_some() { 0 } else { -28 });
        }
    }
    let Some(id) = find_u32_attr(attrs, conntrack::uapi::CTA_ID) else {
        return nlmsg_ack(req, -22 /* EINVAL */);
    };
    let ok = match cmd {
        conntrack::uapi::IPCTNL_MSG_CT_DELETE =>
            ::net::global_stack().conntrack_delete_in(namespace, id as u64),
        conntrack::uapi::IPCTNL_MSG_CT_NEW => {
            let timeout = find_u32_attr(attrs, conntrack::uapi::CTA_TIMEOUT);
            let status = find_u32_attr(attrs, conntrack::uapi::CTA_STATUS);
            let mark = find_u32_attr(attrs, conntrack::uapi::CTA_MARK).map(|value| {
                (value, find_u32_attr(attrs, conntrack::uapi::CTA_MARK_MASK))
            });
            let Ok(seqadj) = parse_seqadjs(attrs) else { return nlmsg_ack(req, -22); };
            let Ok(protoinfo) = parse_tcp_protoinfo(attrs) else { return nlmsg_ack(req, -22); };
            if find_bytes_attr(attrs, conntrack::uapi::CTA_HELP).is_some() {
                return nlmsg_ack(req, -95);
            }
            ::net::global_stack().conntrack_update_in(namespace, id as u64,
                                                       timeout, status, mark, seqadj, protoinfo)
        }
        _ => return nlmsg_ack(req, -95 /* EOPNOTSUPP */),
    };
    nlmsg_ack(req, if ok { 0 } else { -2 /* ENOENT */ })
}

fn handle_ct_get(req: &Nlmsghdr, nfg: &Nfgenmsg, attrs: &[u8], namespace: u64) -> Vec<u8> {
    if let Some(raw) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_ORIG)
        .or_else(|| find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_REPLY)) {
        let Some(tuple) = parse_ct_tuple(raw, nfg.nfgen_family,
            find_be16_attr(attrs, ::conntrack::uapi::CTA_ZONE).unwrap_or(0)) else {
            return nlmsg_ack(req, -22);
        };
        let Some(entry) = ::net::global_stack().conntrack_lookup_tuple_in(namespace, tuple) else {
            return nlmsg_ack(req, -2);
        };
        let mut body = Vec::with_capacity(Nfgenmsg::SIZE + entry.len());
        let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
        nfg.write_to(&mut nfg_buf);
        body.extend_from_slice(&nfg_buf);
        body.extend_from_slice(&entry);
        let total = Nlmsghdr::SIZE + body.len();
        let hdr = Nlmsghdr {
            nlmsg_len: total as u32,
            nlmsg_type: ((subsys::NFNL_SUBSYS_CTNETLINK as u16) << 8)
                | conntrack::uapi::IPCTNL_MSG_CT_GET as u16,
            nlmsg_flags: 0,
            nlmsg_seq: req.nlmsg_seq,
            nlmsg_pid: req.nlmsg_pid,
        };
        let mut out = Vec::with_capacity(total);
        let mut hb = [0u8; Nlmsghdr::SIZE];
        hdr.write_to(&mut hb);
        out.extend_from_slice(&hb);
        out.extend_from_slice(&body);
        while out.len() % 4 != 0 { out.push(0); }
        return out;
    }
    let mut out = Vec::new();
    for attrs in ::net::global_stack().conntrack_dump_in(namespace) {
        let mut body = Vec::with_capacity(Nfgenmsg::SIZE + attrs.len());
        let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
        nfg.write_to(&mut nfg_buf);
        body.extend_from_slice(&nfg_buf);
        body.extend_from_slice(&attrs);
        let total = Nlmsghdr::SIZE + body.len();
        let hdr = Nlmsghdr {
            nlmsg_len: total as u32,
            nlmsg_type: ((subsys::NFNL_SUBSYS_CTNETLINK as u16) << 8)
                | conntrack::uapi::IPCTNL_MSG_CT_GET as u16,
            nlmsg_flags: flags::NLM_F_MULTI,
            nlmsg_seq: req.nlmsg_seq,
            nlmsg_pid: req.nlmsg_pid,
        };
        let mut hb = [0u8; Nlmsghdr::SIZE];
        hdr.write_to(&mut hb);
        out.extend_from_slice(&hb);
        out.extend_from_slice(&body);
        while out.len() % 4 != 0 { out.push(0); }
    }
    let done = Nlmsghdr {
        nlmsg_len: Nlmsghdr::SIZE as u32,
        nlmsg_type: msg::NLMSG_DONE,
        nlmsg_flags: 0,
        nlmsg_seq: req.nlmsg_seq,
        nlmsg_pid: req.nlmsg_pid,
    };
    let mut db = [0u8; Nlmsghdr::SIZE];
    done.write_to(&mut db);
    out.extend_from_slice(&db);
    out
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use alloc::sync::Arc;
    use super::{parse_ct_tuple, parse_helper_name, parse_seqadjs, parse_tcp_protoinfo};
    use ::conntrack::{ProtoPart, Tuple, TupleEnd, InetAddr};
    use netlink::{NetlinkSocket, proto, register_netfilter_listener};

    #[test]
    fn ctnetlink_tuple_parser_preserves_family_ports_and_zone() {
        let expected = Tuple {
            src: TupleEnd { addr: InetAddr::v4([192, 0, 2, 1]), proto: ProtoPart::port(12345) },
            dst: TupleEnd { addr: InetAddr::v4([198, 51, 100, 2]), proto: ProtoPart::port(443) },
            l3num: ::conntrack::uapi::NFPROTO_IPV4,
            protonum: ::conntrack::uapi::IPPROTO_TCP,
            zone: 7,
        };
        let mut raw = Vec::new();
        ::conntrack::ctnetlink::put_tuple(
            &mut raw, ::conntrack::uapi::CTA_TUPLE_ORIG, &expected);
        assert_eq!(parse_ct_tuple(&raw[4..], expected.l3num, expected.zone), Some(expected));
    }

    #[test]
    fn ctnetlink_seqadj_parser_requires_the_linux_nested_fields() {
        let mut raw = Vec::new();
        let n = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_SEQ_ADJ_ORIG);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_SEQADJ_CORRECTION_POS, 100);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_SEQADJ_OFFSET_BEFORE, (-4i32) as u32);
        ::conntrack::ctnetlink::put_be32(
            &mut raw, ::conntrack::uapi::CTA_SEQADJ_OFFSET_AFTER, 8);
        ::conntrack::ctnetlink::nest_end(&mut raw, n);
        let parsed = parse_seqadjs(&raw).unwrap();
        assert_eq!(parsed[0].unwrap().offset_before, -4);
        assert_eq!(parsed[0].unwrap().offset_after, 8);
        let mut incomplete = Vec::new();
        let n = ::conntrack::ctnetlink::nest_start(
            &mut incomplete, ::conntrack::uapi::CTA_SEQ_ADJ_REPLY);
        ::conntrack::ctnetlink::put_be32(
            &mut incomplete, ::conntrack::uapi::CTA_SEQADJ_CORRECTION_POS, 1);
        ::conntrack::ctnetlink::nest_end(&mut incomplete, n);
        assert!(parse_seqadjs(&incomplete).is_err());
    }

    #[test]
    fn ctnetlink_tcp_protoinfo_applies_linux_state_and_masked_flags_shape() {
        let mut raw = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO);
        let tcp = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO_TCP);
        ::conntrack::ctnetlink::put_u8(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO_TCP_STATE, 4);
        ::conntrack::ctnetlink::put_attr(
            &mut raw, ::conntrack::uapi::CTA_PROTOINFO_TCP_FLAGS_ORIGINAL, &[0x80, 0xff]);
        ::conntrack::ctnetlink::nest_end(&mut raw, tcp);
        ::conntrack::ctnetlink::nest_end(&mut raw, outer);
        let parsed = parse_tcp_protoinfo(&raw).unwrap().unwrap();
        assert_eq!(parsed.state, Some(4));
        assert_eq!(parsed.flags[0], Some((0x80, 0xff)));
        assert_eq!(parsed.flags[1], None);

        let mut bad = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut bad, ::conntrack::uapi::CTA_PROTOINFO);
        let tcp = ::conntrack::ctnetlink::nest_start(
            &mut bad, ::conntrack::uapi::CTA_PROTOINFO_TCP);
        ::conntrack::ctnetlink::put_u8(
            &mut bad, ::conntrack::uapi::CTA_PROTOINFO_TCP_STATE, 10);
        ::conntrack::ctnetlink::nest_end(&mut bad, tcp);
        ::conntrack::ctnetlink::nest_end(&mut bad, outer);
        assert!(parse_tcp_protoinfo(&bad).is_err());
    }

    #[test]
    fn ctnetlink_helper_parser_requires_a_nul_terminated_name() {
        let mut raw = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut raw, ::conntrack::uapi::CTA_HELP);
        ::conntrack::ctnetlink::put_attr(
            &mut raw, ::conntrack::uapi::CTA_HELP_NAME, b"dns\0");
        ::conntrack::ctnetlink::nest_end(&mut raw, outer);
        assert_eq!(parse_helper_name(&raw).unwrap().as_deref(), Some("dns"));

        let mut bad = Vec::new();
        let outer = ::conntrack::ctnetlink::nest_start(
            &mut bad, ::conntrack::uapi::CTA_HELP);
        ::conntrack::ctnetlink::put_attr(
            &mut bad, ::conntrack::uapi::CTA_HELP_NAME, b"dns");
        ::conntrack::ctnetlink::nest_end(&mut bad, outer);
        assert!(parse_helper_name(&bad).is_err());
    }

    #[test]
    fn ctnetlink_event_flush_multicasts_the_canonical_new_message() {
        let ns = net::net_ns::initial_namespace();
        let socket = Arc::new(NetlinkSocket::new(proto::NETLINK_NETFILTER, &ns));
        register_netfilter_listener(&socket);
        socket.add_membership(1).unwrap();
        let stack = net::global_stack();
        let tuple = Tuple {
            src: TupleEnd { addr: InetAddr::v4([192, 0, 2, 9]), proto: ProtoPart::port(49123) },
            dst: TupleEnd { addr: InetAddr::v4([198, 51, 100, 9]), proto: ProtoPart::port(53) },
            l3num: ::conntrack::uapi::NFPROTO_IPV4,
            protonum: ::conntrack::uapi::IPPROTO_UDP,
            zone: 0,
        };
        let ct = stack.conntrack_in(0);
        let id = ct.create_tuple(tuple, None, 0, 30, 0, None, None, None).expect("create event");
        super::flush_conntrack_events(0);
        let mut bytes = [0u8; 512];
        let n = socket.read(&mut bytes).expect("conntrack event datagram");
        assert_eq!(u16::from_ne_bytes([bytes[4], bytes[5]]),
            ((crate::subsys::NFNL_SUBSYS_CTNETLINK as u16) << 8)
                | ::conntrack::uapi::IPCTNL_MSG_CT_NEW as u16);
        assert_eq!(bytes[16], ::conntrack::uapi::NFPROTO_IPV4);
        assert!(bytes[..n].windows(4).any(|w| w == (id as u32).to_be_bytes().as_slice()));
        let _ = ct.delete_id(id, 0);
        stack.conntrack_set_groups_in(0, 0);
    }
}

fn reply_errno(reply: &[u8]) -> Option<i32> {
    let header = Nlmsghdr::parse(reply)?;
    if header.nlmsg_type != msg::NLMSG_ERROR || reply.len() < Nlmsghdr::SIZE + 4 { return None; }
    Some(i32::from_ne_bytes(reply[Nlmsghdr::SIZE..Nlmsghdr::SIZE + 4].try_into().ok()?))
}

/// Dispatch one complete nfnetlink datagram. `NFNL_MSG_BATCH_BEGIN` snapshots
/// the canonical ruleset; `BATCH_END` compiles and publishes all intervening
/// mutations once. Any command error restores the snapshot.
/// # C: O(datagram + control-state commit)
pub fn handle(datagram: &[u8], namespace: u64) -> Vec<u8> {
    const NFNL_MSG_BATCH_BEGIN: u16 = msg::NLMSG_MIN_TYPE;
    const NFNL_MSG_BATCH_END: u16 = msg::NLMSG_MIN_TYPE + 1;

    let _serial = crate::nfnl_lock();
    let mut replies = Vec::new();
    let mut off = 0usize;
    let mut in_batch = false;
    let mut failed_batch = false;
    while off + Nlmsghdr::SIZE <= datagram.len() {
        let Some(hdr) = Nlmsghdr::parse(&datagram[off..]) else { break; };
        let len = hdr.nlmsg_len as usize;
        if len < Nlmsghdr::SIZE || off + len > datagram.len() { break; }
        let frame = &datagram[off..off + len];
        if hdr.nlmsg_flags & flags::NLM_F_REQUEST == 0 {
            if hdr.nlmsg_flags & flags::NLM_F_ACK != 0 {
                replies.extend_from_slice(&nlmsg_ack(&hdr, 0));
            }
            off += nlmsg_align(len);
            continue;
        }
        match hdr.nlmsg_type {
            NFNL_MSG_BATCH_BEGIN => {
                if in_batch || !crate::batch_begin(namespace) {
                    replies.extend_from_slice(&nlmsg_ack(&hdr, -22 /* EINVAL */));
                    failed_batch = true;
                } else {
                    in_batch = true;
                }
            }
            NFNL_MSG_BATCH_END => {
                if failed_batch {
                    if in_batch { crate::batch_abort(); }
                } else if !in_batch || !crate::batch_commit(namespace) {
                    replies.extend_from_slice(&nlmsg_ack(&hdr, -22 /* EINVAL */));
                }
                in_batch = false;
                failed_batch = false;
            }
            _ if !failed_batch => {
                let reply = handle_one(frame, namespace);
                let failed = reply_errno(&reply).is_some_and(|errno| errno < 0);
                replies.extend_from_slice(&reply);
                if failed && in_batch {
                    crate::batch_abort();
                    in_batch = false;
                    failed_batch = true;
                }
            }
            _ => {}
        }
        off += nlmsg_align(len);
    }
    if in_batch { crate::batch_abort(); }
    flush_conntrack_events(namespace);
    replies
}

/// # C: O(1)
pub(crate) fn build_newtable_reply(seq: u32, pid: u32, t: &NftTable, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: t.family, version: 0, res_id: 0 }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);
    put_nlattr_str(&mut body, nfta_table::NFTA_TABLE_NAME, &t.name);
    put_nlattr_u32(&mut body, nfta_table::NFTA_TABLE_FLAGS, t.flags);
    put_nlattr_u32(&mut body, nfta_table::NFTA_TABLE_USE, 0);
    build_reply(seq, pid, nft_msg::NFT_MSG_NEWTABLE, multi, body)
}

pub(crate) fn build_newflowtable_reply(seq: u32, pid: u32,
                                       flowtable: &::net::FlowtableConfig, use_count: u32,
                                       multi: bool) -> Vec<u8> {
    let mut body = Vec::with_capacity(128);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: flowtable.family, version: 0, res_id: 0 }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);
    put_nlattr_str(&mut body, nfta_flowtable::NFTA_FLOWTABLE_TABLE, &flowtable.table);
    put_nlattr_str(&mut body, nfta_flowtable::NFTA_FLOWTABLE_NAME, &flowtable.name);
    put_nlattr(&mut body, nfta_flowtable::NFTA_FLOWTABLE_HANDLE,
        &flowtable.handle.to_be_bytes());
    put_nlattr_u32(&mut body, nfta_flowtable::NFTA_FLOWTABLE_USE, use_count);
    put_nlattr_u32(&mut body, nfta_flowtable::NFTA_FLOWTABLE_FLAGS, flowtable.flags);
    let mut hook = Vec::with_capacity(64);
    put_nlattr_u32(&mut hook, nfta_flowtable::NFTA_FLOWTABLE_HOOK_NUM, flowtable.hook_num);
    put_nlattr_u32(&mut hook, nfta_flowtable::NFTA_FLOWTABLE_HOOK_PRIORITY,
        flowtable.priority as u32);
    let mut devices = Vec::new();
    for device in &flowtable.devices {
        let (ty, name) = match device {
            ::net::FlowtableDevice::Name(name) => (1, name),
            ::net::FlowtableDevice::Prefix(name) => (2, name),
        };
        put_nlattr_str(&mut devices, ty, name);
    }
    put_nlattr(&mut hook, nfta_flowtable::NFTA_FLOWTABLE_HOOK_DEVS, &devices);
    put_nlattr(&mut body, nfta_flowtable::NFTA_FLOWTABLE_HOOK, &hook);
    build_reply(seq, pid, nft_msg::NFT_MSG_NEWFLOWTABLE, multi, body)
}

/// # C: O(1)
pub(crate) fn build_newchain_reply(seq: u32, pid: u32, c: &NftChain, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: c.table_family, version: 0, res_id: 0 }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);
    put_nlattr_str(&mut body, nfta_chain::NFTA_CHAIN_TABLE, &c.table_name);
    put_nlattr_str(&mut body, nfta_chain::NFTA_CHAIN_NAME, &c.name);
    put_nlattr_u32(&mut body, nfta_chain::NFTA_CHAIN_USE, 0);
    put_nlattr_u32(&mut body, nfta_chain::NFTA_CHAIN_POLICY, c.policy);
    if let Some(hook_id) = c.hook {
        let mut inner: Vec<u8> = Vec::with_capacity(16);
        put_nlattr(&mut inner, 1u16, &hook_id.to_be_bytes());
        put_nlattr(&mut inner, 2u16, &(c.priority as u32).to_be_bytes());
        put_nlattr(&mut body, nfta_chain::NFTA_CHAIN_HOOK, &inner);
    }
    build_reply(seq, pid, nft_msg::NFT_MSG_NEWCHAIN, multi, body)
}

/// # C: O(1)
pub(crate) fn build_newrule_reply(seq: u32, pid: u32, r: &NftRule, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: r.table_family, version: 0, res_id: 0 }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);
    put_nlattr_str(&mut body, nfta_rule::NFTA_RULE_TABLE, &r.table_name);
    put_nlattr_str(&mut body, nfta_rule::NFTA_RULE_CHAIN, &r.chain_name);
    put_nlattr(&mut body, nfta_rule::NFTA_RULE_HANDLE, &r.handle.to_be_bytes());
    if !r.raw_expr.is_empty() { put_nlattr(&mut body, nfta_rule::NFTA_RULE_EXPRESSIONS, &r.raw_expr); }
    build_reply(seq, pid, nft_msg::NFT_MSG_NEWRULE, multi, body)
}

/// # C: O(1)
pub(crate) fn build_newset_reply(seq: u32, pid: u32, s: &NftSet, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: s.table_family, version: 0, res_id: 0 }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);
    put_nlattr_str(&mut body, nfta_set::NFTA_SET_TABLE, &s.table_name);
    put_nlattr_str(&mut body, nfta_set::NFTA_SET_NAME, &s.name);
    put_nlattr_u32(&mut body, nfta_set::NFTA_SET_FLAGS, s.flags);
    put_nlattr_u32(&mut body, nfta_set::NFTA_SET_KEY_TYPE, s.key_type);
    put_nlattr_u32(&mut body, nfta_set::NFTA_SET_KEY_LEN, s.key_len);
    put_nlattr_u32(&mut body, nfta_set::NFTA_SET_DATA_TYPE, s.data_type);
    put_nlattr_u32(&mut body, nfta_set::NFTA_SET_DATA_LEN, s.data_len);
    if s.flags & nfta_set::NFT_SET_OBJECT != 0 {
        put_nlattr_u32(&mut body, nfta_set::NFTA_SET_OBJ_TYPE, s.obj_type);
    }
    build_reply(seq, pid, nft_msg::NFT_MSG_NEWSET, multi, body)
}

fn build_reply(seq: u32, pid: u32, cmd: u8, multi: bool, body: Vec<u8>) -> Vec<u8> {
    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8) | (cmd as u16);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}
