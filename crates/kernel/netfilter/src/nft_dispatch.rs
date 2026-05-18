use super::*;

/// Build a NFT_MSG_NEWGEN reply with the current generation id.
/// # C: O(1)
fn build_newgen_reply(seq: u32, pid: u32) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(32);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: 0, version: 0, res_id: 0 }.write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);
    put_nlattr_u32(&mut body, nfta_gen::NFTA_GEN_ID, gen_current());

    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8)
                   | (nft_msg::NFT_MSG_NEWGEN as u16);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32, nlmsg_type,
        nlmsg_flags: 0, nlmsg_seq: seq, nlmsg_pid: pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// Build a NFT_MSG_NEWOBJ reply for one stateful object.
/// # C: O(1)
fn build_newobj_reply(seq: u32, pid: u32, o: &NftObject, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(64);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: o.table_family, version: 0, res_id: 0 }
        .write_to(&mut nfg_buf);
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
        nlmsg_len: total as u32, nlmsg_type,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq: seq, nlmsg_pid: pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// Build a NFT_MSG_NEWSETELEM reply listing every elem in a set.
/// # C: O(n_elems)
fn build_setelems_reply(seq: u32, pid: u32, table: &str, set: &str,
                        family: u8, multi: bool) -> Vec<u8> {
    let mut body: Vec<u8> = Vec::with_capacity(128);
    let mut nfg_buf = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: family, version: 0, res_id: 0 }
        .write_to(&mut nfg_buf);
    body.extend_from_slice(&nfg_buf);
    put_nlattr_str(&mut body, nfta_set_elem::NFTA_SET_ELEM_LIST_TABLE, table);
    put_nlattr_str(&mut body, nfta_set_elem::NFTA_SET_ELEM_LIST_SET, set);

    let mut list_payload: Vec<u8> = Vec::new();
    for e in set_elems_snapshot().iter()
        .filter(|e| e.table_family == family
                 && e.table_name == table
                 && e.set_name == set)
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
        // NFTA_LIST_ELEM = 1 — wraps each set-elem inside the
        // NFTA_SET_ELEM_LIST_ELEMENTS payload.
        put_nlattr(&mut list_payload, 1, &elem);
    }
    put_nlattr(&mut body,
               nfta_set_elem::NFTA_SET_ELEM_LIST_ELEMENTS,
               &list_payload);

    let nlmsg_type = ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8)
                   | (nft_msg::NFT_MSG_NEWSETELEM as u16);
    let total = Nlmsghdr::SIZE + body.len();
    let hdr = Nlmsghdr {
        nlmsg_len: total as u32, nlmsg_type,
        nlmsg_flags: if multi { flags::NLM_F_MULTI } else { 0 },
        nlmsg_seq: seq, nlmsg_pid: pid,
    };
    let mut out: Vec<u8> = Vec::with_capacity(total);
    let mut hdr_buf = [0u8; Nlmsghdr::SIZE];
    hdr.write_to(&mut hdr_buf);
    out.extend_from_slice(&hdr_buf);
    out.extend_from_slice(&body);
    while out.len() % 4 != 0 { out.push(0); }
    out
}

/// Walk a NFTA_SET_ELEM_LIST_ELEMENTS payload, calling `f` with
/// each (key, data) tuple. Returns the count seen. Used by both
/// NEWSETELEM (insert) and DELSETELEM (remove by key).
fn walk_setelem_list<F: FnMut(&[u8], &[u8])>(payload: &[u8], mut f: F) -> usize {
    let mut count = 0usize;
    let mut off = 0;
    while off + 4 <= payload.len() {
        let nla_len = u16::from_ne_bytes([payload[off], payload[off + 1]]) as usize;
        if nla_len < 4 || off + nla_len > payload.len() { break; }
        let elem = &payload[off + 4 .. off + nla_len];

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
        if nla_len < 4 || off + nla_len > attrs.len() { break; }
        if nla_type == target {
            return Some(&attrs[off + 4 .. off + nla_len]);
        }
        off += nlmsg_align(nla_len);
    }
    None
}

pub(super) fn handle_nft(req: &Nlmsghdr, nfg: &Nfgenmsg, cmd: u8, attrs: &[u8]) -> Vec<u8> {
    match cmd {
        nft_msg::NFT_MSG_GETGEN => build_newgen_reply(req.nlmsg_seq, req.nlmsg_pid),
        nft_msg::NFT_MSG_GETTABLE => {
            // Single table lookup or full dump.
            if let Some(name) = find_str_attr(attrs, nfta_table::NFTA_TABLE_NAME) {
                let g = TABLES.lock();
                let found = g.iter().find(|t|
                    t.family == nfg.nfgen_family && t.name == name).cloned();
                drop(g);
                match found {
                    Some(t) => build_newtable_reply(req.nlmsg_seq, req.nlmsg_pid, &t, false),
                    None    => nlmsg_ack(req, -2 /* ENOENT */),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for t in tables_snapshot().iter() {
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
            table_insert(NftTable {
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
            let n = table_remove(nfg.nfgen_family, name);
            nlmsg_ack(req, if n > 0 { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETCHAIN => {
            let table_name = find_str_attr(attrs, nfta_chain::NFTA_CHAIN_TABLE);
            let chain_name = find_str_attr(attrs, nfta_chain::NFTA_CHAIN_NAME);
            if let (Some(tn), Some(cn)) = (table_name, chain_name) {
                let g = CHAINS.lock();
                let found = g.iter().find(|c|
                    c.table_family == nfg.nfgen_family
                    && c.table_name == tn
                    && c.name == cn).cloned();
                drop(g);
                match found {
                    Some(c) => build_newchain_reply(req.nlmsg_seq, req.nlmsg_pid, &c, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for c in chains_snapshot().iter()
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
            chain_insert(NftChain {
                table_family: nfg.nfgen_family,
                table_name:   String::from(table_name),
                name:         String::from(chain_name),
                hook:         hook_id,
                priority,
                policy,
            });
            gen_bump();
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELCHAIN => {
            let table_name = match find_str_attr(attrs, nfta_chain::NFTA_CHAIN_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let chain_name = match find_str_attr(attrs, nfta_chain::NFTA_CHAIN_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let n = chain_remove(nfg.nfgen_family, table_name, chain_name);
            nlmsg_ack(req, if n > 0 { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETRULE => {
            let table_name = find_str_attr(attrs, nfta_rule::NFTA_RULE_TABLE);
            let chain_name = find_str_attr(attrs, nfta_rule::NFTA_RULE_CHAIN);
            let want_handle = find_u64_attr(attrs, nfta_rule::NFTA_RULE_HANDLE);
            if let (Some(tn), Some(cn), Some(h)) = (table_name, chain_name, want_handle) {
                let g = RULES.lock();
                let found = g.iter().find(|r|
                    r.table_family == nfg.nfgen_family
                    && r.table_name == tn
                    && r.chain_name == cn
                    && r.handle == h).cloned();
                drop(g);
                match found {
                    Some(r) => build_newrule_reply(req.nlmsg_seq, req.nlmsg_pid, &r, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for r in rules_snapshot().iter().filter(|r|
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
            rule_insert(NftRule {
                table_family: nfg.nfgen_family,
                table_name:   String::from(table_name),
                chain_name:   String::from(chain_name),
                handle:       next_rule_handle(),
                raw_expr,
            });
            nlmsg_ack(req, 0)
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
                Some(h) => rule_remove(nfg.nfgen_family, table_name, chain_name, h),
                None => {
                    let mut g = RULES.lock();
                    let before = g.len();
                    g.retain(|r| !(r.table_family == nfg.nfgen_family
                                   && r.table_name == table_name
                                   && r.chain_name == chain_name));
                    before - g.len()
                }
            };
            nlmsg_ack(req, if n > 0 || handle.is_none() { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETSET => {
            let tn = find_str_attr(attrs, nfta_set::NFTA_SET_TABLE);
            let sn = find_str_attr(attrs, nfta_set::NFTA_SET_NAME);
            if let (Some(tn), Some(sn)) = (tn, sn) {
                let g = SETS.lock();
                let found = g.iter().find(|s|
                    s.table_family == nfg.nfgen_family
                    && s.table_name == tn
                    && s.name == sn).cloned();
                drop(g);
                match found {
                    Some(s) => build_newset_reply(req.nlmsg_seq, req.nlmsg_pid, &s, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for s in sets_snapshot().iter().filter(|s|
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
            set_insert(NftSet {
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
            let n = set_remove(nfg.nfgen_family, table_name, set_name);
            nlmsg_ack(req, if n > 0 { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETOBJ => {
            let tn = find_str_attr(attrs, nfta_obj::NFTA_OBJ_TABLE);
            let on = find_str_attr(attrs, nfta_obj::NFTA_OBJ_NAME);
            if let (Some(tn), Some(on)) = (tn, on) {
                let g = OBJECTS.lock();
                let found = g.iter().find(|o|
                    o.table_family == nfg.nfgen_family
                    && o.table_name == tn
                    && o.name == on).cloned();
                drop(g);
                match found {
                    Some(o) => build_newobj_reply(req.nlmsg_seq, req.nlmsg_pid, &o, false),
                    None    => nlmsg_ack(req, -2),
                }
            } else {
                let mut reply: Vec<u8> = Vec::with_capacity(256);
                for o in objects_snapshot().iter().filter(|o|
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
            object_insert(NftObject {
                table_family: nfg.nfgen_family,
                table_name:   String::from(table_name),
                name:         String::from(obj_name),
                ty, data,
            });
            gen_bump();
            nlmsg_ack(req, 0)
        }
        nft_msg::NFT_MSG_DELOBJ => {
            let table_name = match find_str_attr(attrs, nfta_obj::NFTA_OBJ_TABLE) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let obj_name = match find_str_attr(attrs, nfta_obj::NFTA_OBJ_NAME) {
                Some(s) => s, None => return nlmsg_ack(req, -22),
            };
            let n = object_remove(nfg.nfgen_family, table_name, obj_name);
            if n > 0 { gen_bump(); }
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
            walk_setelem_list(list, |k, d| {
                set_elem_insert(NftSetElem {
                    table_family: nfg.nfgen_family,
                    table_name:   String::from(table),
                    set_name:     String::from(set),
                    key:  k.to_vec(),
                    data: d.to_vec(),
                });
            });
            gen_bump();
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
            let mut total = 0usize;
            walk_setelem_list(list, |k, _d| {
                total += set_elem_remove(nfg.nfgen_family, table, set, k);
            });
            if total > 0 { gen_bump(); }
            nlmsg_ack(req, if total > 0 { 0 } else { -2 })
        }
        nft_msg::NFT_MSG_GETSETELEM => {
            let table = find_str_attr(attrs, nfta_set_elem::NFTA_SET_ELEM_LIST_TABLE);
            let set = find_str_attr(attrs, nfta_set_elem::NFTA_SET_ELEM_LIST_SET);
            match (table, set) {
                (Some(t), Some(s)) => build_setelems_reply(
                    req.nlmsg_seq, req.nlmsg_pid, t, s, nfg.nfgen_family, false),
                _ => nlmsg_ack(req, -22),
            }
        }
        _ => nlmsg_ack(req, 0), // batches: future PR
    }
}

