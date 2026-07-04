use alloc::vec::Vec;

use ::netlink::{flags, msg, nlmsg_align, Nlmsghdr};

use crate::{
    Nfgenmsg, NftChain, NftRule, NftSet, NftTable, nft_dispatch, nft_msg, nfta_chain, nfta_rule,
    nfta_set, nfta_table, subsys,
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

/// # C: O(1)
pub fn handle(full_msg: &[u8]) -> Vec<u8> {
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
        subsys::NFNL_SUBSYS_NFTABLES => nft_dispatch::handle_nft(&hdr, &nfg, (hdr.nlmsg_type & 0xFF) as u8, attrs),
        _ => nlmsg_ack(&hdr, 0),
    }
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
