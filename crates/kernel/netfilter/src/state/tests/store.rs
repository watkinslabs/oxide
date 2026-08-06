use super::*;

fn nla(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
    let len = 4 + payload.len();
    buf.extend_from_slice(&(len as u16).to_ne_bytes());
    buf.extend_from_slice(&ty.to_ne_bytes());
    buf.extend_from_slice(payload);
    while buf.len() % 4 != 0 { buf.push(0); }
}

fn lookup(set: &str) -> Vec<u8> {
    let mut data = Vec::new();
    let mut name = set.as_bytes().to_vec();
    name.push(0);
    nla(&mut data, nft_expr::NFTA_LOOKUP_SET, &name);
    nla(&mut data, nft_expr::NFTA_LOOKUP_SREG, &1u32.to_be_bytes());
    let mut expr = Vec::new();
    nla(&mut expr, nft_expr::NFTA_EXPR_NAME, b"lookup\0");
    nla(&mut expr, nft_expr::NFTA_EXPR_DATA | 0x8000, &data);
    let mut list = Vec::new();
    nla(&mut list, nft_expr::NFTA_LIST_ELEM | 0x8000, &expr);
    list
}

fn set(table: &str, name: &str) -> NftSet {
    NftSet {
        table_family: 2, table_name: table.into(), name: name.into(),
        key_type: 0, key_len: 4, data_type: 0, data_len: 0, flags: 0,
    }
}

#[test]
fn lookup_install_binds_set_until_rule_removal() {
    let table = "oxide-compiled-set-binding";
    let set_name = "blocked";
    let handle = next_rule_handle();
    set_insert(set(table, set_name));
    rule_insert(NftRule {
        table_family: 2, table_name: table.into(), chain_name: "input".into(),
        handle, raw_expr: lookup(set_name),
    }).unwrap();

    assert_eq!(set_remove(2, table, set_name), Err(SetRemoveError::Busy));
    assert_eq!(rule_remove(2, table, "input", handle), 1);
    assert_eq!(set_remove(2, table, set_name), Ok(1));
}

#[test]
fn missing_lookup_set_rejects_whole_rule_without_publication() {
    const NAMESPACE: u64 = 0x1873_0001;
    let table = "oxide-missing-compiled-set";
    let before = gen_current_in(NAMESPACE);
    let result = rule_insert_in(NAMESPACE, NftRule {
        table_family: 2, table_name: table.into(), chain_name: "input".into(),
        handle: next_rule_handle(), raw_expr: lookup("absent"),
    });
    assert_eq!(result, Err(nft_expr::ParseError::MissingSet));
    assert_eq!(gen_current_in(NAMESPACE), before);
    assert!(!rules_snapshot_in(NAMESPACE).iter().any(|rule| rule.table_name == table));
}
