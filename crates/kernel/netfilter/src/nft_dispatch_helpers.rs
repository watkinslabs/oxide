use alloc::vec::Vec;

use netlink::{Nlmsghdr, flags, nlmsg_align};

use crate::{
    Nfgenmsg, NftObject, gen_current, nft_msg, nfta_gen, nfta_obj, nfta_set_elem,
    put_nlattr, put_nlattr_str, put_nlattr_u32, set_elems_snapshot, subsys,
};

pub(crate) fn build_newgen_reply(seq: u32, pid: u32) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(32);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: 0, version: 0, res_id: 0 }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);
    put_nlattr_u32(&mut body, nfta_gen::NFTA_GEN_ID, gen_current());

    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8)
        | (nft_msg::NFT_MSG_NEWGEN as u16);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32,
        nlmsg_type,
        nlmsg_flags: 0,
        nlmsg_seq: seq,
        nlmsg_pid: pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

pub(crate) fn build_newobj_reply(seq: u32, pid: u32, o: &NftObject, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: o.table_family, version: 0, res_id: 0 }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);

    put_nlattr_str(&mut body, nfta_obj::NFTA_OBJ_TABLE, &o.table_name);
    put_nlattr_str(&mut body, nfta_obj::NFTA_OBJ_NAME, &o.name);
    put_nlattr_u32(&mut body, nfta_obj::NFTA_OBJ_TYPE, o.ty);
    if !o.data.is_empty() {
        put_nlattr(&mut body, nfta_obj::NFTA_OBJ_DATA, &o.data);
    }
    put_nlattr_u32(&mut body, nfta_obj::NFTA_OBJ_USE, 0);

    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8)
        | (nft_msg::NFT_MSG_NEWOBJ as u16);
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
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

pub(crate) fn build_setelems_reply(
    seq: u32,
    pid: u32,
    table: &str,
    set: &str,
    family: u8,
    multi: bool,
) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(128);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: family, version: 0, res_id: 0 }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);
    put_nlattr_str(&mut body, nfta_set_elem::NFTA_SET_ELEM_LIST_TABLE, table);
    put_nlattr_str(&mut body, nfta_set_elem::NFTA_SET_ELEM_LIST_SET, set);

    let mut list_payload: Vec<u8> = Vec::new();
    for e in set_elems_snapshot()
        .iter()
        .filter(|e| e.table_family == family && e.table_name == table && e.set_name == set)
    {
        let mut elem: Vec<u8> = Vec::new();
        let mut keyval: Vec<u8> = Vec::new();
        put_nlattr(&mut keyval, nfta_set_elem::NFTA_DATA_VALUE, &e.key);
        put_nlattr(&mut elem, nfta_set_elem::NFTA_SET_ELEM_KEY, &keyval);
        if !e.data.is_empty() {
            let mut dataval: Vec<u8> = Vec::new();
            put_nlattr(&mut dataval, nfta_set_elem::NFTA_DATA_VALUE, &e.data);
            put_nlattr(&mut elem, nfta_set_elem::NFTA_SET_ELEM_DATA, &dataval);
        }
        put_nlattr(&mut list_payload, 1, &elem);
    }
    put_nlattr(
        &mut body,
        nfta_set_elem::NFTA_SET_ELEM_LIST_ELEMENTS,
        &list_payload,
    );

    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8)
        | (nft_msg::NFT_MSG_NEWSETELEM as u16);
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
    while out.len() % 4 != 0 {
        out.push(0);
    }
    out
}

pub(crate) fn walk_setelem_list<F: FnMut(&[u8], &[u8])>(payload: &[u8], mut f: F) -> usize {
    let mut count = 0usize;
    let mut off = 0;
    while off + 4 <= payload.len() {
        let nla_len = u16::from_ne_bytes([payload[off], payload[off + 1]]) as usize;
        if nla_len < 4 || off + nla_len > payload.len() {
            break;
        }
        let elem = &payload[off + 4..off + nla_len];

        let keyval = find_nested_value(elem, nfta_set_elem::NFTA_SET_ELEM_KEY);
        let dataval = find_nested_value(elem, nfta_set_elem::NFTA_SET_ELEM_DATA);
        if let Some(k) = keyval {
            f(k, dataval.unwrap_or(&[]));
            count += 1;
        }
        off += nlmsg_align(nla_len);
    }
    count
}

fn find_nested_value<'a>(attrs: &'a [u8], target: u16) -> Option<&'a [u8]> {
    let raw = find_bytes_attr_masked(attrs, target)?;
    find_bytes_attr_masked(raw, nfta_set_elem::NFTA_DATA_VALUE)
}

fn find_bytes_attr_masked<'a>(attrs: &'a [u8], target: u16) -> Option<&'a [u8]> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = u16::from_ne_bytes([attrs[off], attrs[off + 1]]) as usize;
        let nla_type = u16::from_ne_bytes([attrs[off + 2], attrs[off + 3]]) & 0x3fff;
        if nla_len < 4 || off + nla_len > attrs.len() {
            break;
        }
        if nla_type == target {
            return Some(&attrs[off + 4..off + nla_len]);
        }
        off += nlmsg_align(nla_len);
    }
    None
}
