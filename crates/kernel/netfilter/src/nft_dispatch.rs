use alloc::string::String;
use alloc::vec::Vec;
use netlink::{Nlmsghdr, flags};

use super::*;
use crate::nft_dispatch_helpers::{
    build_newgen_reply, build_newobj_reply, build_setelems_reply, walk_setelem_list,
};

pub(super) fn handle_nft(
    namespace: u64,
    req: &Nlmsghdr,
    nfg: &Nfgenmsg,
    cmd: u8,
    attrs: &[u8],
) -> Vec<u8> {
    match cmd {
        nft_msg::NFT_MSG_GETGEN => build_newgen_reply(namespace, req.nlmsg_seq, req.nlmsg_pid),
        nft_msg::NFT_MSG_GETTABLE => {
            // Single table lookup or full dump.
            if let Some(name) = find_str_attr(attrs, nfta_table::NFTA_TABLE_NAME) {
                let found = tables_snapshot_in(namespace).into_iter().find(|table|
                    table.family == nfg.nfgen_family && table.name == name);
                match found {
                    Some(t) => build_newtable_reply(req.nlmsg_seq, req.nlmsg_pid, &t, false),
                    None    => nlmsg_ack(req, -2 /* ENOENT */),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for t in tables_snapshot_in(namespace).iter() {
                    let one = build_newtable_reply(req.nlmsg_seq, req.nlmsg_pid, t, true);
                    reply.extend_from_slice(&one);
                }
                let mut done_buf = [0u8; Nlmsghdr::SIZE];
                let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
                done.nlmsg_flags = flags::NLM_F_MULTI;
                done.write_to(&mut done_buf);
                reply.extend_from_slice(&done_buf);
                reply
            }
        }
        nft_msg::NFT_MSG_NEWTABLE => {
            let name = match find_str_attr(attrs, nfta_table::NFTA_TABLE_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            table_insert_in(namespace, NftTable {
                family: nfg.nfgen_family,
                name:   String::from(name),
                flags:  0,
            });
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELTABLE => {
            let name = match find_str_attr(attrs, nfta_table::NFTA_TABLE_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let n = table_remove_in(namespace, nfg.nfgen_family, name);
            nlmsg_ack(req, if n > 0 { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETCHAIN => {
            let table_name = find_str_attr(attrs, nfta_chain::NFTA_CHAIN_TABLE);
            let chain_name = find_str_attr(attrs, nfta_chain::NFTA_CHAIN_NAME);
            if let (Some(tn), Some(cn)) = (table_name, chain_name) {
                let found = chains_snapshot_in(namespace).into_iter().find(|c|
                    c.table_family == nfg.nfgen_family
                    && c.table_name == tn
                    && c.name == cn);
                match found {
                    Some(c) => build_newchain_reply(req.nlmsg_seq, req.nlmsg_pid, &c, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for c in chains_snapshot_in(namespace).iter()
                    .filter(|c| table_name.map_or(true, |tn|
                        c.table_family == nfg.nfgen_family && c.table_name == tn))
                {
                    reply.extend_from_slice(&build_newchain_reply(
                        req.nlmsg_seq, req.nlmsg_pid, c, true));
                }
                let mut done_buf = [0u8; Nlmsghdr::SIZE];
                let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
                done.nlmsg_flags = flags::NLM_F_MULTI;
                done.write_to(&mut done_buf);
                reply.extend_from_slice(&done_buf);
                reply
            }
        }
        nft_msg::NFT_MSG_NEWCHAIN => {
            let table_name = match find_str_attr(attrs, nfta_chain::NFTA_CHAIN_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let chain_name = match find_str_attr(attrs, nfta_chain::NFTA_CHAIN_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            // Parse the optional NFTA_CHAIN_HOOK nested attribute
            // for base chains. Inner attrs: NFTA_HOOK_HOOKNUM = 1
            // (u32 BE), NFTA_HOOK_PRIORITY = 2 (i32 BE).
            let mut hook_id: Option<u32> = None;
            let mut priority: i32 = 0;
            if let Some(hook_blob) = find_bytes_attr(attrs, nfta_chain::NFTA_CHAIN_HOOK) {
                if let Some(h) = find_u32_attr(hook_blob, 1) { hook_id = Some(h); }
                if let Some(p) = find_u32_attr(hook_blob, 2) { priority = p as i32; }
            }
            let policy = find_u32_attr(attrs, nfta_chain::NFTA_CHAIN_POLICY)
                .unwrap_or(NFT_CHAIN_POLICY_ACCEPT);
            chain_insert_in(namespace, NftChain {
                table_family: nfg.nfgen_family,
                table_name:   String::from(table_name),
                name:         String::from(chain_name),
                hook:         hook_id,
                priority,
                policy,
            });
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELCHAIN => {
            let table_name = match find_str_attr(attrs, nfta_chain::NFTA_CHAIN_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let chain_name = match find_str_attr(attrs, nfta_chain::NFTA_CHAIN_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let n = chain_remove_in(namespace, nfg.nfgen_family, table_name, chain_name);
            nlmsg_ack(req, if n > 0 { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETRULE => {
            let table_name = find_str_attr(attrs, nfta_rule::NFTA_RULE_TABLE);
            let chain_name = find_str_attr(attrs, nfta_rule::NFTA_RULE_CHAIN);
            let want_handle = find_u64_attr(attrs, nfta_rule::NFTA_RULE_HANDLE);
            if let (Some(tn), Some(cn), Some(h)) = (table_name, chain_name, want_handle) {
                let found = rules_snapshot_in(namespace).into_iter().find(|r|
                    r.table_family == nfg.nfgen_family
                    && r.table_name == tn
                    && r.chain_name == cn
                    && r.handle == h);
                match found {
                    Some(r) => build_newrule_reply(req.nlmsg_seq, req.nlmsg_pid, &r, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for r in rules_snapshot_in(namespace).iter().filter(|r|
                    table_name.map_or(true, |tn|
                        r.table_family == nfg.nfgen_family && r.table_name == tn)
                    && chain_name.map_or(true, |cn| r.chain_name == cn))
                {
                    reply.extend_from_slice(&build_newrule_reply(
                        req.nlmsg_seq, req.nlmsg_pid, r, true));
                }
                let mut done_buf = [0u8; Nlmsghdr::SIZE];
                let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
                done.nlmsg_flags = flags::NLM_F_MULTI;
                done.write_to(&mut done_buf);
                reply.extend_from_slice(&done_buf);
                reply
            }
        }
        nft_msg::NFT_MSG_NEWRULE => {
            let table_name = match find_str_attr(attrs, nfta_rule::NFTA_RULE_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let chain_name = match find_str_attr(attrs, nfta_rule::NFTA_RULE_CHAIN) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let raw_expr = find_bytes_attr(attrs, nfta_rule::NFTA_RULE_EXPRESSIONS)
                .map(|b| b.to_vec()).unwrap_or_default();
            let result = rule_insert_in(namespace, NftRule {
                table_family: nfg.nfgen_family,
                table_name:   String::from(table_name),
                chain_name:   String::from(chain_name),
                handle:       next_rule_handle(),
                raw_expr,
            });
            match result {
                Ok(_) => nlmsg_ack(req, 0),
                Err(nft_expr::ParseError::Unsupported) => nlmsg_ack(req, -95 /* EOPNOTSUPP */),
                Err(nft_expr::ParseError::Malformed) => nlmsg_ack(req, -22 /* EINVAL */),
                Err(nft_expr::ParseError::MissingSet) => nlmsg_ack(req, -2 /* ENOENT */),
            }
        }
        nft_msg::NFT_MSG_DELRULE => {
            let table_name = match find_str_attr(attrs, nfta_rule::NFTA_RULE_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let chain_name = match find_str_attr(attrs, nfta_rule::NFTA_RULE_CHAIN) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            // No handle = delete every rule in (table, chain). With
            // handle = single-row delete. Mirrors nft userspace semantics.
            let handle = find_u64_attr(attrs, nfta_rule::NFTA_RULE_HANDLE);
            let n = match handle {
                Some(h) => rule_remove_in(namespace, nfg.nfgen_family, table_name, chain_name, h),
                None => rules_remove_in(namespace, nfg.nfgen_family, table_name, chain_name),
            };
            nlmsg_ack(req, if n > 0 || handle.is_none() { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETSET => {
            let tn = find_str_attr(attrs, nfta_set::NFTA_SET_TABLE);
            let sn = find_str_attr(attrs, nfta_set::NFTA_SET_NAME);
            if let (Some(tn), Some(sn)) = (tn, sn) {
                let found = sets_snapshot_in(namespace).into_iter().find(|s|
                    s.table_family == nfg.nfgen_family
                    && s.table_name == tn
                    && s.name == sn);
                match found {
                    Some(s) => build_newset_reply(req.nlmsg_seq, req.nlmsg_pid, &s, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for s in sets_snapshot_in(namespace).iter().filter(|s|
                    tn.map_or(true, |t|
                        s.table_family == nfg.nfgen_family && s.table_name == t))
                {
                    reply.extend_from_slice(&build_newset_reply(
                        req.nlmsg_seq, req.nlmsg_pid, s, true));
                }
                let mut done_buf = [0u8; Nlmsghdr::SIZE];
                let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
                done.nlmsg_flags = flags::NLM_F_MULTI;
                done.write_to(&mut done_buf);
                reply.extend_from_slice(&done_buf);
                reply
            }
        }
        nft_msg::NFT_MSG_NEWSET => {
            let table_name = match find_str_attr(attrs, nfta_set::NFTA_SET_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let set_name = match find_str_attr(attrs, nfta_set::NFTA_SET_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let flags     = find_u32_attr(attrs, nfta_set::NFTA_SET_FLAGS).unwrap_or(0);
            let key_type  = find_u32_attr(attrs, nfta_set::NFTA_SET_KEY_TYPE).unwrap_or(0);
            let key_len   = find_u32_attr(attrs, nfta_set::NFTA_SET_KEY_LEN).unwrap_or(0);
            let data_type = find_u32_attr(attrs, nfta_set::NFTA_SET_DATA_TYPE).unwrap_or(0);
            let data_len  = find_u32_attr(attrs, nfta_set::NFTA_SET_DATA_LEN).unwrap_or(0);
            set_insert_in(namespace, NftSet {
                table_family: nfg.nfgen_family,
                table_name:   String::from(table_name),
                name:         String::from(set_name),
                key_type, key_len, data_type, data_len, flags,
            });
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELSET => {
            let table_name = match find_str_attr(attrs, nfta_set::NFTA_SET_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let set_name = match find_str_attr(attrs, nfta_set::NFTA_SET_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            match set_remove_in(namespace, nfg.nfgen_family, table_name, set_name) {
                Ok(n) => nlmsg_ack(req, if n > 0 { 0 } else { -2 }),
                Err(SetRemoveError::Busy) => nlmsg_ack(req, -16 /* EBUSY */),
            }
        }
        nft_msg::NFT_MSG_GETOBJ => {
            let tn = find_str_attr(attrs, nfta_obj::NFTA_OBJ_TABLE);
            let on = find_str_attr(attrs, nfta_obj::NFTA_OBJ_NAME);
            if let (Some(tn), Some(on)) = (tn, on) {
                let found = objects_snapshot_in(namespace).into_iter().find(|o|
                    o.table_family == nfg.nfgen_family
                    && o.table_name == tn
                    && o.name == on);
                match found {
                    Some(o) => build_newobj_reply(req.nlmsg_seq, req.nlmsg_pid, &o, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for o in objects_snapshot_in(namespace).iter().filter(|o|
                    tn.map_or(true, |t|
                        o.table_family == nfg.nfgen_family && o.table_name == t))
                {
                    reply.extend_from_slice(&build_newobj_reply(
                        req.nlmsg_seq, req.nlmsg_pid, o, true));
                }
                let mut done_buf = [0u8; Nlmsghdr::SIZE];
                let mut done = Nlmsghdr::done(req.nlmsg_seq, req.nlmsg_pid);
                done.nlmsg_flags = flags::NLM_F_MULTI;
                done.write_to(&mut done_buf);
                reply.extend_from_slice(&done_buf);
                reply
            }
        }
        nft_msg::NFT_MSG_NEWOBJ => {
            let table_name = match find_str_attr(attrs, nfta_obj::NFTA_OBJ_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let obj_name = match find_str_attr(attrs, nfta_obj::NFTA_OBJ_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let ty = find_u32_attr(attrs, nfta_obj::NFTA_OBJ_TYPE).unwrap_or(0);
            let data = find_bytes_attr(attrs, nfta_obj::NFTA_OBJ_DATA)
                .map(|b| b.to_vec()).unwrap_or_default();
            object_insert_in(namespace, NftObject {
                table_family: nfg.nfgen_family,
                table_name:   String::from(table_name),
                name:         String::from(obj_name),
                ty, data,
            });
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELOBJ => {
            let table_name = match find_str_attr(attrs, nfta_obj::NFTA_OBJ_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let obj_name = match find_str_attr(attrs, nfta_obj::NFTA_OBJ_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let n = object_remove_in(namespace, nfg.nfgen_family, table_name, obj_name);
            nlmsg_ack(req, if n > 0 { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_NEWSETELEM => {
            let table = match find_str_attr(attrs, nfta_set_elem::NFTA_SET_ELEM_LIST_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let set = match find_str_attr(attrs, nfta_set_elem::NFTA_SET_ELEM_LIST_SET) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let list = find_bytes_attr(attrs, nfta_set_elem::NFTA_SET_ELEM_LIST_ELEMENTS)
                .unwrap_or(&[]);
            let mut elems = Vec::new();
            walk_setelem_list(list, |k, d| {
                elems.push(NftSetElem {
                    table_family: nfg.nfgen_family,
                    table_name:   String::from(table),
                    set_name:     String::from(set),
                    key:  k.to_vec(),
                    data: d.to_vec(),
                });
            });
            set_elems_insert_in(namespace, elems);
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELSETELEM => {
            let table = match find_str_attr(attrs, nfta_set_elem::NFTA_SET_ELEM_LIST_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let set = match find_str_attr(attrs, nfta_set_elem::NFTA_SET_ELEM_LIST_SET) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let list = find_bytes_attr(attrs, nfta_set_elem::NFTA_SET_ELEM_LIST_ELEMENTS)
                .unwrap_or(&[]);
            let mut keys = Vec::new();
            walk_setelem_list(list, |k, _d| {
                keys.push(k.to_vec());
            });
            let total = set_elems_remove_in(namespace, nfg.nfgen_family, table, set, &keys);
            nlmsg_ack(req, if total > 0 { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETSETELEM => {
            let table = find_str_attr(attrs, nfta_set_elem::NFTA_SET_ELEM_LIST_TABLE);
            let set = find_str_attr(attrs, nfta_set_elem::NFTA_SET_ELEM_LIST_SET);
            match (table, set) {
                (Some(t), Some(s)) => build_setelems_reply(
                    namespace, req.nlmsg_seq, req.nlmsg_pid, t, s, nfg.nfgen_family, false),
                _ => nlmsg_ack(req, -22),
            }
        }
        _ => nlmsg_ack(req, 0), // batches: future PR
    }
}
