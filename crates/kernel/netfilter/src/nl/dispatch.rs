use alloc::vec::Vec;

use ::netlink::{flags, msg, Nlmsghdr};

use super::*;

pub(super) fn handle_one(full_msg: &[u8], namespace: u64) -> Vec<u8> {
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
        subsys::NFNL_SUBSYS_OSF => handle_osf(&hdr, (hdr.nlmsg_type & 0xFF) as u8, attrs),
        subsys::NFNL_SUBSYS_NFTABLES => nft_dispatch::handle_nft(
            namespace, &hdr, &nfg, (hdr.nlmsg_type & 0xFF) as u8, attrs),
        _ => nlmsg_ack(&hdr, 0),
    }
}

fn handle_osf(req: &Nlmsghdr, cmd: u8, attrs: &[u8]) -> Vec<u8> {
    let Some(finger) = find_bytes_attr(attrs, crate::osf_attr::OSF_ATTR_FINGER) else {
        return nlmsg_ack(req, -22);
    };
    let result = match cmd {
        crate::osf_msg::OSF_MSG_ADD => {
            if req.nlmsg_flags & flags::NLM_F_CREATE == 0 { return nlmsg_ack(req, -22); }
            crate::nft_expr::osf::add(finger, req.nlmsg_flags & flags::NLM_F_EXCL != 0)
        }
        crate::osf_msg::OSF_MSG_REMOVE => crate::nft_expr::osf::remove(finger),
        _ => return nlmsg_ack(req, -95),
    };
    let errno = match result {
        Ok(()) => 0,
        Err(crate::nft_expr::osf::Error::Invalid) => -22,
        Err(crate::nft_expr::osf::Error::Exists) => -17,
        Err(crate::nft_expr::osf::Error::Missing) => -2,
    };
    nlmsg_ack(req, errno)
}

/// ctnetlink's GET dump is the read path used by `conntrack -L`. Each entry
/// is encoded by conntrack itself; this layer only supplies the nfgenmsg and
/// multipart netlink framing.
fn handle_ct(req: &Nlmsghdr, nfg: &Nfgenmsg, attrs: &[u8], namespace: u64) -> Vec<u8> {
    let cmd = (req.nlmsg_type & 0xff) as u8;
    if cmd == conntrack::uapi::IPCTNL_MSG_CT_GET
        || cmd == conntrack::uapi::IPCTNL_MSG_CT_GET_CTRZERO {
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
        if let Some(raw) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_ORIG)
            .or_else(|| find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_REPLY)) {
            let Some(tuple) = parse_ct_tuple(raw, nfg.nfgen_family,
                find_be16_attr(attrs, ::conntrack::uapi::CTA_ZONE).unwrap_or(0)) else {
                return nlmsg_ack(req, -22);
            };
            let existing = ::net::global_stack().conntrack_id_tuple_in(namespace, tuple);
            if let Some(id) = existing {
                if req.nlmsg_flags & flags::NLM_F_EXCL != 0 {
                    return nlmsg_ack(req, -17);
                }
                if find_bytes_attr(attrs, ::conntrack::uapi::CTA_NAT_SRC).is_some()
                    || find_bytes_attr(attrs, ::conntrack::uapi::CTA_NAT_DST).is_some() {
                    return nlmsg_ack(req, -95);
                }
                let Ok(labels) = parse_labels(attrs) else { return nlmsg_ack(req, -22); };
                let Ok(synproxy) = parse_synproxy(attrs) else { return nlmsg_ack(req, -22); };
                let Ok(sctp_protoinfo) = parse_sctp_protoinfo(attrs) else { return nlmsg_ack(req, -22); };
                let Ok(helper) = parse_helper_name(attrs) else { return nlmsg_ack(req, -22); };
                if let Some(name) = helper {
                    if let Err(error) = ::net::global_stack().conntrack_update_helper_in(
                        namespace, id, name) {
                        return nlmsg_ack(req, helper_change_errno(error));
                    }
                }
                let mark = find_u32_attr(attrs, ::conntrack::uapi::CTA_MARK).map(|value| {
                    (value, find_u32_attr(attrs, ::conntrack::uapi::CTA_MARK_MASK))
                });
                let Ok(seqadj) = parse_seqadjs(attrs) else { return nlmsg_ack(req, -22); };
                let Ok(protoinfo) = parse_tcp_protoinfo(attrs) else { return nlmsg_ack(req, -22); };
                let ok = ::net::global_stack().conntrack_update_in(
                    namespace, id, find_u32_attr(attrs, ::conntrack::uapi::CTA_TIMEOUT),
                    find_u32_attr(attrs, ::conntrack::uapi::CTA_STATUS), mark, seqadj,
                    protoinfo, sctp_protoinfo, labels, synproxy);
                return nlmsg_ack(req, if ok { 0 } else { -2 });
            }
            if req.nlmsg_flags & flags::NLM_F_CREATE == 0 {
                return nlmsg_ack(req, -2);
            }
            let Some(orig_raw) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_ORIG)
                else { return nlmsg_ack(req, -22); };
            let Some(orig) = parse_ct_tuple(orig_raw, nfg.nfgen_family,
                find_be16_attr(attrs, ::conntrack::uapi::CTA_ZONE).unwrap_or(0)) else {
                return nlmsg_ack(req, -22);
            };
            let Some(reply_raw) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_REPLY)
                else { return nlmsg_ack(req, -22); };
            let Some(reply) = parse_ct_tuple(reply_raw, nfg.nfgen_family, orig.zone) else {
                return nlmsg_ack(req, -22);
            };
            if orig.protonum != reply.protonum {
                return nlmsg_ack(req, -22);
            }
            let master = match find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_MASTER) {
                Some(raw) => parse_ct_tuple(raw, nfg.nfgen_family, orig.zone),
                None => None,
            };
            if find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_MASTER).is_some()
                && master.is_none() {
                return nlmsg_ack(req, -22);
            }
            let Some(timeout) = find_u32_attr(attrs, ::conntrack::uapi::CTA_TIMEOUT) else {
                return nlmsg_ack(req, -22);
            };
            let Ok(protoinfo) = parse_tcp_protoinfo(attrs) else { return nlmsg_ack(req, -22); };
            let Ok(sctp_protoinfo) = parse_sctp_protoinfo(attrs) else { return nlmsg_ack(req, -22); };
            let Ok(helper) = parse_helper_name(attrs) else { return nlmsg_ack(req, -22); };
            let Ok(labels) = parse_labels(attrs) else { return nlmsg_ack(req, -22); };
            let Ok(synproxy) = parse_synproxy(attrs) else { return nlmsg_ack(req, -22); };
            let Ok(src_nat) = parse_nat_range(attrs, nfg.nfgen_family,
                ::conntrack::uapi::CTA_NAT_SRC) else { return nlmsg_ack(req, -22); };
            let Ok(dst_nat) = parse_nat_range(attrs, nfg.nfgen_family,
                ::conntrack::uapi::CTA_NAT_DST) else { return nlmsg_ack(req, -22); };
            let created = if src_nat.is_some() || dst_nat.is_some() {
                ::net::global_stack().conntrack_create_tuple_nat_in(
                    namespace, orig, Some(reply), timeout,
                    find_u32_attr(attrs, ::conntrack::uapi::CTA_STATUS).unwrap_or(0),
                    find_u32_attr(attrs, ::conntrack::uapi::CTA_MARK), protoinfo, sctp_protoinfo,
                    master, helper,
                    src_nat, dst_nat, labels, synproxy)
            } else {
                ::net::global_stack().conntrack_create_tuple_in(
                namespace, orig, Some(reply), timeout,
                find_u32_attr(attrs, ::conntrack::uapi::CTA_STATUS).unwrap_or(0),
                find_u32_attr(attrs, ::conntrack::uapi::CTA_MARK), protoinfo, sctp_protoinfo,
                master, helper, labels,
                synproxy)
            };
            return nlmsg_ack(req, match created {
                Ok(Some(_)) => 0,
                Ok(None) => -28,
                Err(errno) => errno,
            });
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
            let Ok(sctp_protoinfo) = parse_sctp_protoinfo(attrs) else { return nlmsg_ack(req, -22); };
            let Ok(helper) = parse_helper_name(attrs) else { return nlmsg_ack(req, -22); };
            let Ok(labels) = parse_labels(attrs) else { return nlmsg_ack(req, -22); };
            let Ok(synproxy) = parse_synproxy(attrs) else { return nlmsg_ack(req, -22); };
            if let Some(name) = helper {
                if let Err(error) = ::net::global_stack().conntrack_update_helper_in(
                    namespace, id as u64, name) {
                    return nlmsg_ack(req, helper_change_errno(error));
                }
            }
            ::net::global_stack().conntrack_update_in(namespace, id as u64,
                                                       timeout, status, mark, seqadj, protoinfo,
                                                       sctp_protoinfo,
                                                       labels, synproxy)
        }
        _ => return nlmsg_ack(req, -95 /* EOPNOTSUPP */),
    };
    nlmsg_ack(req, if ok { 0 } else { -2 /* ENOENT */ })
}

fn ct_single_reply(req: &Nlmsghdr, nfg: &Nfgenmsg, entry: Vec<u8>) -> Vec<u8> {
    let mut body = Vec::with_capacity(Nfgenmsg::SIZE + entry.len());
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    nfg.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);
    body.extend_from_slice(&entry);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type: ((subsys::NFNL_SUBSYS_CTNETLINK as u16) << 8)
            | (req.nlmsg_type & 0xff),
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
    out
}

fn handle_ct_get(req: &Nlmsghdr, nfg: &Nfgenmsg, attrs: &[u8], namespace: u64) -> Vec<u8> {
    let zero = req.nlmsg_type & 0xff == conntrack::uapi::IPCTNL_MSG_CT_GET_CTRZERO as u16;
    if req.nlmsg_flags & flags::NLM_F_DUMP == 0 {
        let Some(raw) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_ORIG)
            .or_else(|| find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_REPLY)) else {
            return nlmsg_ack(req, -22);
        };
        let Some(tuple) = parse_ct_tuple(raw, nfg.nfgen_family,
            find_be16_attr(attrs, ::conntrack::uapi::CTA_ZONE).unwrap_or(0)) else {
            return nlmsg_ack(req, -22);
        };
        let entry = if zero {
            ::net::global_stack().conntrack_lookup_ctrzero_tuple_in(namespace, tuple)
        } else {
            ::net::global_stack().conntrack_lookup_tuple_in(namespace, tuple)
        };
        let Some(entry) = entry else { return nlmsg_ack(req, -2); };
        return ct_single_reply(req, nfg, entry);
    }
    let (_, filter) = match parse_dump_filter(attrs, nfg.nfgen_family) {
        Ok(value) => value,
        Err(errno) => return nlmsg_ack(req, errno),
    };
    let mut out = Vec::new();
    let entries = if zero {
        ::net::global_stack().conntrack_dump_ctrzero_filtered_in(namespace, filter)
    } else {
        ::net::global_stack().conntrack_dump_filtered_in(namespace, filter)
    };
    for attrs in entries {
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
