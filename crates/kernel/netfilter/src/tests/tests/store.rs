use super::*;

#[test]
fn nfgenmsg_roundtrip() {
    let n = Nfgenmsg { nfgen_family: 2, version: 0, res_id: 0x1234 };
    let mut buf = [0u8; Nfgenmsg::SIZE];
    n.write_to(&mut buf);
    let p = Nfgenmsg::parse(&buf).unwrap();
    assert_eq!(p.nfgen_family, 2);
    assert_eq!(p.version, 0);
    assert_eq!(p.res_id, 0x1234);
}

#[test]
fn table_insert_dedup_remove() {
    let _g = store_guard();
    let t = NftTable { family: 2, name: String::from("oxide-test-t"), flags: 0 };
    let before = tables_snapshot().len();
    table_insert(t.clone());
    table_insert(t.clone());
    assert_eq!(tables_snapshot().len(), before + 1);
    let n = table_remove(2, "oxide-test-t");
    assert_eq!(n, 1);
    assert_eq!(tables_snapshot().len(), before);
}

#[test]
fn object_insert_dedup_remove() {
    let _g = store_guard();
    let o = NftObject {
        table_family: 2, table_name: String::from("oxide-test-t"), name: String::from("conn_counter"),
        ty: 1, data: vec![], state: alloc::sync::Arc::new(crate::nft_expr::ObjectState::Unsupported),
    };
    let before = objects_snapshot().len();
    object_insert(o.clone());
    object_insert(o);
    assert_eq!(objects_snapshot().len(), before + 1);
    let n = object_remove(2, "oxide-test-t", "conn_counter");
    assert_eq!(n, 1);
    assert_eq!(objects_snapshot().len(), before);
}

#[test]
fn ruleset_mutation_generation_is_monotonic() {
    let _g = store_guard();
    let a = gen_current();
    table_insert(NftTable { family: 2, name: String::from("oxide-test-gen"), flags: 0 });
    let b = gen_current();
    assert!(b > a);
    assert_eq!(table_remove(2, "oxide-test-gen"), 1);
    assert!(gen_current() > b);
}

#[test]
fn set_insert_dedup_remove() {
    let _g = store_guard();
    let s = NftSet { table_family: 2, table_name: String::from("oxide-test-t"), name: String::from("blocked_ips"),
        key_type: 7, key_len: 4, data_type: 0, data_len: 0, flags: 0, obj_type: 0 };
    let before = sets_snapshot().len();
    set_insert(s.clone());
    set_insert(s);
    assert_eq!(sets_snapshot().len(), before + 1);
    assert_eq!(set_remove(2, "oxide-test-t", "blocked_ips"), Ok(1));
    assert_eq!(sets_snapshot().len(), before);
}

#[test]
fn rule_insert_and_remove_round_trip() {
    let _g = store_guard();
    let h = next_rule_handle();
    let r = NftRule { table_family: 2, table_name: String::from("oxide-test-t"), chain_name: String::from("input"), handle: h, raw_expr: Vec::new() };
    let before = rules_snapshot().len();
    rule_insert(r).unwrap();
    assert_eq!(rules_snapshot().len(), before + 1);
    assert_eq!(rule_remove(2, "oxide-test-t", "input", h), 1);
    assert_eq!(rules_snapshot().len(), before);
}

#[test]
fn malformed_rule_is_not_published() {
    let _g = store_guard();
    let before_rules = rules_snapshot().len();
    let before_gen = gen_current();
    let result = rule_insert(NftRule { table_family: 2, table_name: String::from("oxide-test-invalid"), chain_name: String::from("input"), handle: next_rule_handle(), raw_expr: vec![8, 0, 1, 0] });
    assert_eq!(result, Err(nft_expr::ParseError::Malformed));
    assert_eq!(rules_snapshot().len(), before_rules);
    assert_eq!(gen_current(), before_gen);
}

#[test]
fn chain_insert_dedup_remove() {
    let _g = store_guard();
    let c = NftChain { table_family: 2, table_name: String::from("oxide-test-t"), name: String::from("input"), hook: None, priority: 0, policy: NFT_CHAIN_POLICY_ACCEPT };
    let before = chains_snapshot().len();
    chain_insert(c.clone());
    chain_insert(c);
    assert_eq!(chains_snapshot().len(), before + 1);
    assert_eq!(chain_remove(2, "oxide-test-t", "input"), 1);
    assert_eq!(chains_snapshot().len(), before);
}

#[test]
fn setelem_insert_dedup_remove_round_trip() {
    let _g = store_guard();
    let e = NftSetElem { table_family: 2, table_name: String::from("oxide-test-elT"), set_name: String::from("blocked"), key: vec![10, 0, 0, 5], data: vec![], objref: None };
    let before = set_elems_snapshot().len();
    set_elem_insert(e.clone());
    set_elem_insert(e);
    assert_eq!(set_elems_snapshot().len(), before + 1);
    assert_eq!(set_elem_remove(2, "oxide-test-elT", "blocked", &[10, 0, 0, 5]), 1);
    assert_eq!(set_elems_snapshot().len(), before);
}

#[test]
fn setelem_lookup_round_trips_with_data() {
    let _g = store_guard();
    let e = NftSetElem { table_family: 2, table_name: String::from("oxide-test-elT2"), set_name: String::from("blocked"), key: vec![1, 2, 3, 4], data: vec![0xff], objref: None };
    set_elem_insert(e);
    assert_eq!(set_elem_lookup(2, "oxide-test-elT2", "blocked", &[1, 2, 3, 4]), Some(vec![0xff]));
    assert_eq!(set_elem_lookup(2, "oxide-test-elT2", "blocked", &[9, 9, 9, 9]), None);
    let _ = set_elem_remove(2, "oxide-test-elT2", "blocked", &[1, 2, 3, 4]);
}

#[test]
fn find_attr_strips_nla_f_nested_bit() {
    let mut buf = Vec::new();
    let payload = b"foo\0";
    let total = 4 + payload.len();
    buf.extend_from_slice(&(total as u16).to_ne_bytes());
    buf.extend_from_slice(&(0x8000u16 | nfta_rule::NFTA_RULE_TABLE).to_ne_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % 4 != 0 { buf.push(0); }
    assert_eq!(find_str_attr(&buf, nfta_rule::NFTA_RULE_TABLE), Some("foo"));
}

#[test]
fn rule_handles_are_unique() {
    assert_ne!(next_rule_handle(), next_rule_handle());
}
