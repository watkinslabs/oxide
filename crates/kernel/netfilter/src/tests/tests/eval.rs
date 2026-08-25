use super::*;

#[test]
fn verdict_encoding_matches_linux() {
    assert_eq!(Verdict::Drop.as_u32(), 0);
    assert_eq!(Verdict::Accept.as_u32(), 1);
    assert_eq!(Verdict::Stolen.as_u32(), 2);
    assert_eq!(Verdict::Queue(7).as_u32(), 3 | (7u32 << 16));
    assert_eq!(Verdict::Repeat.as_u32(), 4);
}

#[test]
fn eval_accepts_when_no_base_chain_on_hook() {
    assert_eq!(eval(4242, &[], nft_expr::NFPROTO_IPV4), Verdict::Accept);
    assert!(eval_in_with_mark(0, 4242, &[], nft_expr::NFPROTO_IPV4, 0).actions.is_empty());
}

#[test]
fn eval_drop_policy_drops_packet() {
    let _g = store_guard();
    chain_insert(NftChain { table_family: 2, table_name: String::from("oxide-test-hookT"), name: String::from("input"), hook: Some(7777), priority: 0, policy: NFT_CHAIN_POLICY_DROP });
    assert_eq!(eval(7777, &[], nft_expr::NFPROTO_IPV4), Verdict::Drop);
    let _ = chain_remove(2, "oxide-test-hookT", "input");
}

#[test]
fn control_and_packet_policy_are_isolated_by_network_namespace() {
    let _g = store_guard();
    const OWNER: u64 = 0x1873_01;
    const OTHER: u64 = 0x1873_02;
    const HOOK: u32 = 7779;
    let name = "oxide-test-netns-policy";
    let before_other = gen_current_in(OTHER);
    chain_insert_in(OWNER, NftChain { table_family: nft_expr::NFPROTO_IPV4, table_name: name.into(), name: "input".into(), hook: Some(HOOK), priority: 0, policy: NFT_CHAIN_POLICY_DROP });
    assert_eq!(eval_in(OWNER, HOOK, &[], nft_expr::NFPROTO_IPV4), Verdict::Drop);
    assert_eq!(eval_in(OTHER, HOOK, &[], nft_expr::NFPROTO_IPV4), Verdict::Accept);
    assert!(chains_snapshot_in(OTHER).is_empty());
    assert_eq!(gen_current_in(OTHER), before_other);
    assert_eq!(chain_remove_in(OWNER, nft_expr::NFPROTO_IPV4, name, "input"), 1);
}

#[test]
fn eval_runs_rule_immediate_drop() {
    let _g = store_guard();
    use super::nft_expr::*;
    fn nla(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) { let total = 4 + payload.len(); buf.extend_from_slice(&(total as u16).to_ne_bytes()); buf.extend_from_slice(&ty.to_ne_bytes()); buf.extend_from_slice(payload); while buf.len() % 4 != 0 { buf.push(0); } }
    fn nested(buf: &mut Vec<u8>, ty: u16, inner: &[u8]) { nla(buf, ty | 0x8000, inner); }
    fn u32be(buf: &mut Vec<u8>, ty: u16, v: u32) { nla(buf, ty, &v.to_be_bytes()); }
    fn s(buf: &mut Vec<u8>, ty: u16, st: &str) { let mut p = st.as_bytes().to_vec(); p.push(0); nla(buf, ty, &p); }
    let mut verdict = Vec::new(); u32be(&mut verdict, NFTA_VERDICT_CODE, NF_DROP as u32);
    let mut data = Vec::new(); nested(&mut data, NFTA_DATA_VERDICT, &verdict);
    let mut idata = Vec::new(); u32be(&mut idata, NFTA_IMMEDIATE_DREG, 0); nested(&mut idata, NFTA_IMMEDIATE_DATA, &data);
    let mut expr = Vec::new(); s(&mut expr, NFTA_EXPR_NAME, "immediate"); nested(&mut expr, NFTA_EXPR_DATA, &idata);
    let mut raw_expr = Vec::new(); nested(&mut raw_expr, NFTA_LIST_ELEM, &expr);
    let table = String::from("oxide-test-evalT");
    chain_insert(NftChain { table_family: 2, table_name: table.clone(), name: String::from("input"), hook: Some(8881), priority: 0, policy: NFT_CHAIN_POLICY_ACCEPT });
    rule_insert(NftRule { table_family: 2, table_name: table.clone(), chain_name: String::from("input"), handle: next_rule_handle(), raw_expr }).unwrap();
    let generation = active_generation(8881).expect("compiled generation");
    let expr_ptr = generation.namespace(0).unwrap().hooks.iter().find(|hook| hook.id == 8881).unwrap().chains[0].rules[0].exprs.as_ptr();
    drop(generation);
    for _ in 0..64 { assert_eq!(eval(8881, &[], nft_expr::NFPROTO_IPV4), Verdict::Drop); }
    let generation = active_generation(8881).expect("same compiled generation");
    let after_ptr = generation.namespace(0).unwrap().hooks.iter().find(|hook| hook.id == 8881).unwrap().chains[0].rules[0].exprs.as_ptr();
    assert_eq!(after_ptr, expr_ptr);
    drop(generation);
    assert_eq!(eval(8881, &[], nft_expr::NFPROTO_IPV6), Verdict::Accept);
    let _ = chain_remove(2, &table, "input");
}

#[test]
fn eval_accept_policy_passes_through() {
    let _g = store_guard();
    chain_insert(NftChain { table_family: 2, table_name: String::from("oxide-test-hookT2"), name: String::from("input"), hook: Some(7778), priority: 0, policy: NFT_CHAIN_POLICY_ACCEPT });
    assert_eq!(eval(7778, &[], nft_expr::NFPROTO_IPV4), Verdict::Accept);
    let _ = chain_remove(2, "oxide-test-hookT2", "input");
}
