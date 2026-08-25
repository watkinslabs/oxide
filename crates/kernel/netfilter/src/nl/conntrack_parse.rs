use alloc::string::String;

use super::{find_bytes_attr, find_u32_attr};

pub(super) fn find_be16_attr(attrs: &[u8], target: u16) -> Option<u16> {
    let raw = find_bytes_attr(attrs, target)?;
    (raw.len() == 2).then(|| u16::from_be_bytes([raw[0], raw[1]]))
}

pub(super) fn find_u8_attr(attrs: &[u8], target: u16) -> Option<u8> {
    let raw = find_bytes_attr(attrs, target)?;
    (raw.len() == 1).then(|| raw[0])
}

pub(super) fn parse_ct_tuple(raw: &[u8], family: u8, zone: u16) -> Option<::conntrack::Tuple> {
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

pub(super) fn parse_ct_tuple_filter(raw: &[u8], family: u8, flags: u32)
    -> Result<::conntrack::ctnetlink::TupleFilter, i32>
{
    use ::conntrack::{InetAddr, ProtoPart, Tuple};
    if !matches!(family, ::conntrack::uapi::NFPROTO_IPV4 | ::conntrack::uapi::NFPROTO_IPV6) {
        return Err(-95);
    }
    let mut tuple = Tuple { l3num: family, ..Tuple::default() };
    if flags & (::conntrack::ctnetlink::FILTER_IP_SRC
        | ::conntrack::ctnetlink::FILTER_IP_DST) != 0 {
        let Some(ip) = find_bytes_attr(raw, ::conntrack::uapi::CTA_TUPLE_IP) else {
            return Err(-22);
        };
        if flags & ::conntrack::ctnetlink::FILTER_IP_SRC != 0 {
            let kind = if family == ::conntrack::uapi::NFPROTO_IPV6 {
                ::conntrack::uapi::CTA_IP_V6_SRC
            } else { ::conntrack::uapi::CTA_IP_V4_SRC };
            let Some(addr) = find_bytes_attr(ip, kind) else { return Err(-22); };
            tuple.src.addr = if family == ::conntrack::uapi::NFPROTO_IPV6 {
                InetAddr::v6(addr.try_into().map_err(|_| -22)?)
            } else { InetAddr::v4(addr.try_into().map_err(|_| -22)?) };
        }
        if flags & ::conntrack::ctnetlink::FILTER_IP_DST != 0 {
            let kind = if family == ::conntrack::uapi::NFPROTO_IPV6 {
                ::conntrack::uapi::CTA_IP_V6_DST
            } else { ::conntrack::uapi::CTA_IP_V4_DST };
            let Some(addr) = find_bytes_attr(ip, kind) else { return Err(-22); };
            tuple.dst.addr = if family == ::conntrack::uapi::NFPROTO_IPV6 {
                InetAddr::v6(addr.try_into().map_err(|_| -22)?)
            } else { InetAddr::v4(addr.try_into().map_err(|_| -22)?) };
        }
    }
    let proto_flags = flags & (::conntrack::ctnetlink::FILTER_PROTO_SRC_PORT
        | ::conntrack::ctnetlink::FILTER_PROTO_DST_PORT
        | ::conntrack::ctnetlink::FILTER_PROTO_ICMP_TYPE
        | ::conntrack::ctnetlink::FILTER_PROTO_ICMP_CODE
        | ::conntrack::ctnetlink::FILTER_PROTO_ICMP_ID
        | ::conntrack::ctnetlink::FILTER_PROTO_ICMPV6_TYPE
        | ::conntrack::ctnetlink::FILTER_PROTO_ICMPV6_CODE
        | ::conntrack::ctnetlink::FILTER_PROTO_ICMPV6_ID);
    if proto_flags != 0 && flags & ::conntrack::ctnetlink::FILTER_PROTO_NUM == 0 {
        return Err(-22);
    }
    if flags & ::conntrack::ctnetlink::FILTER_PROTO_NUM != 0 {
        let Some(proto) = find_bytes_attr(raw, ::conntrack::uapi::CTA_TUPLE_PROTO) else {
            return Err(-22);
        };
        tuple.protonum = find_u8_attr(proto, ::conntrack::uapi::CTA_PROTO_NUM)
            .ok_or(-22)?;
        let port_flags = flags & (::conntrack::ctnetlink::FILTER_PROTO_SRC_PORT
            | ::conntrack::ctnetlink::FILTER_PROTO_DST_PORT);
        if matches!(tuple.protonum, ::conntrack::uapi::IPPROTO_TCP | ::conntrack::uapi::IPPROTO_UDP) {
            if port_flags & ::conntrack::ctnetlink::FILTER_PROTO_SRC_PORT != 0 {
                tuple.src.proto = ProtoPart::port(
                    find_be16_attr(proto, ::conntrack::uapi::CTA_PROTO_SRC_PORT).ok_or(-22)?);
            }
            if port_flags & ::conntrack::ctnetlink::FILTER_PROTO_DST_PORT != 0 {
                tuple.dst.proto = ProtoPart::port(
                    find_be16_attr(proto, ::conntrack::uapi::CTA_PROTO_DST_PORT).ok_or(-22)?);
            }
        } else if tuple.protonum == ::conntrack::uapi::IPPROTO_ICMP {
            tuple.src.proto.port = if flags & ::conntrack::ctnetlink::FILTER_PROTO_ICMP_ID != 0 {
                find_be16_attr(proto, ::conntrack::uapi::CTA_PROTO_ICMP_ID).ok_or(-22)?
            } else { 0 };
            tuple.dst.proto.icmp_type = if flags & ::conntrack::ctnetlink::FILTER_PROTO_ICMP_TYPE != 0 {
                find_u8_attr(proto, ::conntrack::uapi::CTA_PROTO_ICMP_TYPE).ok_or(-22)?
            } else { 0 };
            if flags & ::conntrack::ctnetlink::FILTER_PROTO_ICMP_TYPE != 0
                && ::conntrack::tuple::icmp_invert_type(family, tuple.dst.proto.icmp_type).is_none() {
                return Err(-22);
            }
            tuple.dst.proto.icmp_code = if flags & ::conntrack::ctnetlink::FILTER_PROTO_ICMP_CODE != 0 {
                find_u8_attr(proto, ::conntrack::uapi::CTA_PROTO_ICMP_CODE).ok_or(-22)?
            } else { 0 };
        } else if tuple.protonum == ::conntrack::uapi::IPPROTO_ICMPV6 {
            tuple.src.proto.port = if flags & ::conntrack::ctnetlink::FILTER_PROTO_ICMPV6_ID != 0 {
                find_be16_attr(proto, ::conntrack::uapi::CTA_PROTO_ICMPV6_ID).ok_or(-22)?
            } else { 0 };
            tuple.dst.proto.icmp_type = if flags & ::conntrack::ctnetlink::FILTER_PROTO_ICMPV6_TYPE != 0 {
                find_u8_attr(proto, ::conntrack::uapi::CTA_PROTO_ICMPV6_TYPE).ok_or(-22)?
            } else { 0 };
            if flags & ::conntrack::ctnetlink::FILTER_PROTO_ICMPV6_TYPE != 0
                && ::conntrack::tuple::icmp_invert_type(family, tuple.dst.proto.icmp_type).is_none() {
                return Err(-22);
            }
            tuple.dst.proto.icmp_code = if flags & ::conntrack::ctnetlink::FILTER_PROTO_ICMPV6_CODE != 0 {
                find_u8_attr(proto, ::conntrack::uapi::CTA_PROTO_ICMPV6_CODE).ok_or(-22)?
            } else { 0 };
        }
    }
    Ok(::conntrack::ctnetlink::TupleFilter { flags, tuple })
}

pub(super) fn parse_seqadj(raw: &[u8]) -> Option<::conntrack::entry::SeqAdjust> {
    Some(::conntrack::entry::SeqAdjust {
        correction_pos: find_u32_attr(raw, ::conntrack::uapi::CTA_SEQADJ_CORRECTION_POS)?,
        offset_before: find_u32_attr(raw, ::conntrack::uapi::CTA_SEQADJ_OFFSET_BEFORE)? as i32,
        offset_after: find_u32_attr(raw, ::conntrack::uapi::CTA_SEQADJ_OFFSET_AFTER)? as i32,
        active: true,
    })
}

pub(super) fn parse_seqadjs(attrs: &[u8])
    -> Result<[Option<::conntrack::entry::SeqAdjust>; ::conntrack::uapi::IP_CT_DIR_MAX], ()>
{
    let orig = find_bytes_attr(attrs, ::conntrack::uapi::CTA_SEQ_ADJ_ORIG)
        .map(|raw| parse_seqadj(raw).ok_or(())).transpose()?;
    let reply = find_bytes_attr(attrs, ::conntrack::uapi::CTA_SEQ_ADJ_REPLY)
        .map(|raw| parse_seqadj(raw).ok_or(())).transpose()?;
    Ok([orig, reply])
}

pub(super) fn parse_tcp_protoinfo(attrs: &[u8])
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

pub(super) fn parse_sctp_protoinfo(attrs: &[u8])
    -> Result<Option<::conntrack::entry::SctpProtoInfoUpdate>, ()>
{
    let Some(protoinfo) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_PROTOINFO)
        else { return Ok(None); };
    let Some(sctp) = find_bytes_attr(protoinfo, ::conntrack::uapi::CTA_PROTOINFO_SCTP)
        else { return Ok(None); };
    let Some(state) = find_u8_attr(sctp, ::conntrack::uapi::CTA_PROTOINFO_SCTP_STATE)
        else { return Err(()); };
    if state > ::conntrack::uapi::SCTP_CONNTRACK_HEARTBEAT_SENT { return Err(()); }
    Ok(Some(::conntrack::entry::SctpProtoInfoUpdate {
        state,
        vtag: [
            find_u32_attr(sctp, ::conntrack::uapi::CTA_PROTOINFO_SCTP_VTAG_ORIGINAL)
                .ok_or(())?,
            find_u32_attr(sctp, ::conntrack::uapi::CTA_PROTOINFO_SCTP_VTAG_REPLY)
                .ok_or(())?,
        ],
    }))
}

pub(super) fn parse_nat_range(attrs: &[u8], family: u8, target: u16)
    -> Result<Option<nat::NatRange>, ()>
{
    let Some(raw) = find_bytes_attr(attrs, target) else { return Ok(None); };
    let mut range = nat::NatRange::default();
    let (min_ip, max_ip) = if family == ::conntrack::uapi::NFPROTO_IPV6 {
        (::conntrack::uapi::CTA_NAT_V6_MINIP, ::conntrack::uapi::CTA_NAT_V6_MAXIP)
    } else if family == ::conntrack::uapi::NFPROTO_IPV4 {
        (::conntrack::uapi::CTA_NAT_V4_MINIP, ::conntrack::uapi::CTA_NAT_V4_MAXIP)
    } else {
        return Err(());
    };
    if let Some(ip) = find_bytes_attr(raw, min_ip) {
        range.min_addr = if family == ::conntrack::uapi::NFPROTO_IPV6 {
            ::conntrack::InetAddr::v6(ip.try_into().map_err(|_| ())?)
        } else {
            ::conntrack::InetAddr::v4(ip.try_into().map_err(|_| ())?)
        };
        range.flags |= nat::uapi::NF_NAT_RANGE_MAP_IPS;
    }
    if let Some(ip) = find_bytes_attr(raw, max_ip) {
        range.max_addr = if family == ::conntrack::uapi::NFPROTO_IPV6 {
            ::conntrack::InetAddr::v6(ip.try_into().map_err(|_| ())?)
        } else {
            ::conntrack::InetAddr::v4(ip.try_into().map_err(|_| ())?)
        };
    } else {
        range.max_addr = range.min_addr;
    }
    if let Some(proto) = find_bytes_attr(raw, ::conntrack::uapi::CTA_NAT_PROTO) {
        if let Some(min) = find_bytes_attr(proto, ::conntrack::uapi::CTA_PROTONAT_PORT_MIN) {
            if min.len() != 2 { return Err(()); }
            range.min_proto = u16::from_be_bytes([min[0], min[1]]);
            range.max_proto = range.min_proto;
            range.flags |= nat::uapi::NF_NAT_RANGE_PROTO_SPECIFIED;
        }
        if let Some(max) = find_bytes_attr(proto, ::conntrack::uapi::CTA_PROTONAT_PORT_MAX) {
            if max.len() != 2 { return Err(()); }
            range.max_proto = u16::from_be_bytes([max[0], max[1]]);
            range.flags |= nat::uapi::NF_NAT_RANGE_PROTO_SPECIFIED;
        }
    }
    Ok(Some(range))
}

pub(super) fn parse_labels(attrs: &[u8]) -> Result<Option<::conntrack::entry::LabelUpdate>, ()> {
    let Some(raw) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_LABELS) else {
        return Ok(None);
    };
    if raw.len() > ::conntrack::uapi::NF_CT_LABELS_MAX_SIZE || raw.len() % 4 != 0 {
        return Err(());
    }
    let mask = find_bytes_attr(attrs, ::conntrack::uapi::CTA_LABELS_MASK);
    if mask.is_some_and(|value| value.is_empty() || value.len() != raw.len()) {
        return Err(());
    }
    let mut data = [0u8; ::conntrack::uapi::NF_CT_LABELS_MAX_SIZE];
    data[..raw.len()].copy_from_slice(raw);
    let mask = mask.map(|value| {
        let mut out = [0u8; ::conntrack::uapi::NF_CT_LABELS_MAX_SIZE];
        out[..value.len()].copy_from_slice(value);
        out
    });
    Ok(Some(::conntrack::entry::LabelUpdate { data, mask, len: raw.len() }))
}

pub(super) fn parse_synproxy(attrs: &[u8])
    -> Result<Option<::conntrack::entry::SynproxyState>, ()>
{
    let Some(raw) = find_bytes_attr(attrs, ::conntrack::uapi::CTA_SYNPROXY) else {
        return Ok(None);
    };
    Ok(Some(::conntrack::entry::SynproxyState {
        isn: find_u32_attr(raw, ::conntrack::uapi::CTA_SYNPROXY_ISN).ok_or(())?,
        its: find_u32_attr(raw, ::conntrack::uapi::CTA_SYNPROXY_ITS).ok_or(())?,
        tsoff: find_u32_attr(raw, ::conntrack::uapi::CTA_SYNPROXY_TSOFF)
            .ok_or(())? as i32,
    }))
}

pub(super) fn parse_dump_filter(attrs: &[u8], family: u8)
    -> Result<(bool, ::conntrack::ctnetlink::DumpFilter), i32>
{
    let mark = find_u32_attr(attrs, ::conntrack::uapi::CTA_MARK);
    if mark.is_none() && find_u32_attr(attrs, ::conntrack::uapi::CTA_MARK_MASK).is_some() {
        return Err(-22);
    }
    let status = find_u32_attr(attrs, ::conntrack::uapi::CTA_STATUS);
    if status.is_none() && find_u32_attr(attrs, ::conntrack::uapi::CTA_STATUS_MASK).is_some() {
        return Err(-22);
    }
    let mark = mark.map(|value| (value,
        find_u32_attr(attrs, ::conntrack::uapi::CTA_MARK_MASK).unwrap_or(u32::MAX)));
    let status = status.map(|value| (value,
        find_u32_attr(attrs, ::conntrack::uapi::CTA_STATUS_MASK).unwrap_or(value)));
    if status.is_some_and(|(_, mask)| mask == 0) { return Err(-22); }
    let zone = find_be16_attr(attrs, ::conntrack::uapi::CTA_ZONE);
    let filter_raw = find_bytes_attr(attrs, ::conntrack::uapi::CTA_FILTER);
    let parse_flags = |raw: &[u8], kind: u16| -> Result<u32, i32> {
        if find_bytes_attr(raw, kind).is_some() {
            let flags = find_u32_attr(raw, kind).ok_or(-22)?;
            if flags & !::conntrack::ctnetlink::FILTER_ALL != 0 { return Err(-22); }
            Ok(flags)
        } else { Ok(0) }
    };
    let (orig, reply) = if let Some(raw) = filter_raw {
        let orig_flags = parse_flags(raw, ::conntrack::uapi::CTA_FILTER_ORIG_FLAGS)?;
        let reply_flags = parse_flags(raw, ::conntrack::uapi::CTA_FILTER_REPLY_FLAGS)?;
        let orig = if orig_flags != 0 {
            let tuple = find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_ORIG)
                .ok_or(-22)?;
            Some(parse_ct_tuple_filter(tuple, family, orig_flags)?)
        } else { None };
        let reply = if reply_flags != 0 {
            let tuple = find_bytes_attr(attrs, ::conntrack::uapi::CTA_TUPLE_REPLY)
                .ok_or(-22)?;
            Some(parse_ct_tuple_filter(tuple, family, reply_flags)?)
        } else { None };
        (orig, reply)
    } else { (None, None) };
    let selected = mark.is_some() || status.is_some() || zone.is_some()
        || filter_raw.is_some();
    Ok((selected, ::conntrack::ctnetlink::DumpFilter {
        family: matches!(family, ::conntrack::uapi::NFPROTO_IPV4
            | ::conntrack::uapi::NFPROTO_IPV6).then_some(family),
        zone, mark, status, orig, reply,
    }))
}

pub(super) fn parse_helper_name(attrs: &[u8]) -> Result<Option<String>, ()> {
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

pub(super) fn helper_change_errno(error: ::conntrack::HelperChangeError) -> i32 {
    match error {
        ::conntrack::HelperChangeError::NotFound => -2,
        ::conntrack::HelperChangeError::Unsupported => -95,
        ::conntrack::HelperChangeError::Busy => -16,
    }
}

