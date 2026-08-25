use super::*;

fn append_nlmsg(datagram: &mut Vec<u8>, ty: u16, seq: u32, body: &[u8]) {
    let len = netlink::Nlmsghdr::SIZE + body.len();
    let header = netlink::Nlmsghdr { nlmsg_len: len as u32, nlmsg_type: ty, nlmsg_flags: netlink::flags::NLM_F_REQUEST, nlmsg_seq: seq, nlmsg_pid: 7 };
    let mut bytes = [0u8; netlink::Nlmsghdr::SIZE];
    header.write_to(&mut bytes);
    datagram.extend_from_slice(&bytes);
    datagram.extend_from_slice(body);
    while datagram.len() % 4 != 0 { datagram.push(0); }
}

fn append_newtable(datagram: &mut Vec<u8>, seq: u32, name: &str) {
    let mut body = Vec::new();
    let mut nfg = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: 2, version: 0, res_id: 0 }.write_to(&mut nfg);
    body.extend_from_slice(&nfg);
    put_nlattr_str(&mut body, nfta_table::NFTA_TABLE_NAME, name);
    append_nlmsg(datagram, ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8) | nft_msg::NFT_MSG_NEWTABLE as u16, seq, &body);
}

fn append_malformed_rule(datagram: &mut Vec<u8>, seq: u32, table: &str) {
    let mut body = Vec::new();
    let mut nfg = [0u8; Nfgenmsg::SIZE];
    Nfgenmsg { nfgen_family: 2, version: 0, res_id: 0 }.write_to(&mut nfg);
    body.extend_from_slice(&nfg);
    put_nlattr_str(&mut body, nfta_rule::NFTA_RULE_TABLE, table);
    put_nlattr_str(&mut body, nfta_rule::NFTA_RULE_CHAIN, "input");
    put_nlattr(&mut body, nfta_rule::NFTA_RULE_EXPRESSIONS, &[8, 0, 1, 0]);
    append_nlmsg(datagram, ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8) | nft_msg::NFT_MSG_NEWRULE as u16, seq, &body);
}

#[test]
fn nfnetlink_batch_publishes_one_atomic_generation() {
    let _g = store_guard();
    let first = "oxide-batch-first"; let second = "oxide-batch-second";
    let _ = table_remove(2, first); let _ = table_remove(2, second);
    let before = gen_current();
    let mut datagram = Vec::new();
    append_nlmsg(&mut datagram, netlink::msg::NLMSG_MIN_TYPE, 1, &[]);
    append_newtable(&mut datagram, 2, first); append_newtable(&mut datagram, 3, second);
    append_nlmsg(&mut datagram, netlink::msg::NLMSG_MIN_TYPE + 1, 4, &[]);
    let _ = handle(&datagram, 0);
    assert_eq!(gen_current(), before + 1);
    let tables = tables_snapshot();
    assert!(tables.iter().any(|table| table.family == 2 && table.name == first));
    assert!(tables.iter().any(|table| table.family == 2 && table.name == second));
    let _ = table_remove(2, first); let _ = table_remove(2, second);
}

#[test]
fn unbatched_messages_remain_independent_transactions() {
    let _g = store_guard();
    let first = "oxide-unbatched-first"; let second = "oxide-unbatched-second";
    let _ = table_remove(2, first); let _ = table_remove(2, second);
    let before = gen_current();
    let mut datagram = Vec::new(); append_newtable(&mut datagram, 1, first); append_newtable(&mut datagram, 2, second);
    let _ = handle(&datagram, 0);
    assert_eq!(gen_current(), before + 2);
    let _ = table_remove(2, first); let _ = table_remove(2, second);
}

#[test]
fn nfnetlink_batch_error_rolls_back_without_publication() {
    let _g = store_guard();
    let table = "oxide-batch-rollback"; let _ = table_remove(2, table);
    let before = gen_current();
    let mut datagram = Vec::new();
    append_nlmsg(&mut datagram, netlink::msg::NLMSG_MIN_TYPE, 1, &[]);
    append_newtable(&mut datagram, 2, table); append_malformed_rule(&mut datagram, 3, table);
    append_nlmsg(&mut datagram, netlink::msg::NLMSG_MIN_TYPE + 1, 4, &[]);
    let reply = handle(&datagram, 0);
    assert!(reply.windows(4).any(|bytes| i32::from_ne_bytes(bytes.try_into().unwrap()) == -22));
    assert_eq!(gen_current(), before);
    assert!(!tables_snapshot().iter().any(|item| item.family == 2 && item.name == table));
}

#[test]
#[ignore = "manual release-mode packet-path performance measurement"]
fn packet_path_benchmark_64_rules() {
    let _g = store_guard();
    const HOOK: u32 = 15_555; const RULES: usize = 64; const ITERATIONS: usize = 100_000;
    let table = "oxide-bench-nft"; let chain = "input";
    chain_insert(NftChain { table_family: nft_expr::NFPROTO_IPV4, table_name: table.into(), name: chain.into(), hook: Some(HOOK), priority: 0, policy: NFT_CHAIN_POLICY_DROP });
    let mut handles = Vec::with_capacity(RULES);
    for _ in 0..RULES {
        let handle = next_rule_handle(); handles.push(handle);
        rule_insert(NftRule { table_family: nft_expr::NFPROTO_IPV4, table_name: table.into(), chain_name: chain.into(), handle, raw_expr: Vec::new() }).unwrap();
    }
    assert_eq!(eval(HOOK, &[], nft_expr::NFPROTO_IPV4), Verdict::Drop);
    let start = std::time::Instant::now();
    for _ in 0..ITERATIONS { std::hint::black_box(eval(HOOK, &[], nft_expr::NFPROTO_IPV4)); }
    let elapsed = start.elapsed().as_nanos();
    std::println!("NFT_EVAL_64_RULES iterations={ITERATIONS} elapsed_ns={elapsed} ns_per_packet={}", elapsed / ITERATIONS as u128);
    for handle in handles { let _ = rule_remove(nft_expr::NFPROTO_IPV4, table, chain, handle); }
    let _ = chain_remove(nft_expr::NFPROTO_IPV4, table, chain);
}
