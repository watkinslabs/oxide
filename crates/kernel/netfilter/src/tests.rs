use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use sync::{Socket as SockLockClass, Spinlock};

use super::*;

    // Count-based tests below assert on whole-store snapshots of shared global
    // Spinlock tables; cargo test runs them in parallel, so two touching the
    // same static race (one's insert lands between another's `before` snapshot
    // and its assert). Serialize them with this lock. Crate is #![no_std], so
    // reuse the same Spinlock the stores use rather than std::sync::Mutex; its
    // guard Drop releases on a test panic-unwind, so no poison cascade.
    static STORE_LOCK: Spinlock<(), SockLockClass> = Spinlock::new(());
    fn store_guard() -> sync::Guard<'static, (), SockLockClass> { STORE_LOCK.lock() }

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
        table_insert(t.clone()); // dedup
        assert_eq!(tables_snapshot().len(), before + 1);
        let n = table_remove(2, "oxide-test-t");
        assert_eq!(n, 1);
        assert_eq!(tables_snapshot().len(), before);
    }

    #[test]
    fn object_insert_dedup_remove() {
        let _g = store_guard();
        let o = NftObject {
            table_family: 2,
            table_name:   String::from("oxide-test-t"),
            name:         String::from("conn_counter"),
            ty: 1, data: vec![],
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
        let c = gen_current();
        assert!(c > b);
    }

    #[test]
    fn set_insert_dedup_remove() {
        let _g = store_guard();
        let s = NftSet {
            table_family: 2,
            table_name:   String::from("oxide-test-t"),
            name:         String::from("blocked_ips"),
            key_type: 7, key_len: 4, data_type: 0, data_len: 0, flags: 0,
        };
        let before = sets_snapshot().len();
        set_insert(s.clone());
        set_insert(s);
        assert_eq!(sets_snapshot().len(), before + 1);
        let n = set_remove(2, "oxide-test-t", "blocked_ips");
        assert_eq!(n, Ok(1));
        assert_eq!(sets_snapshot().len(), before);
    }

    #[test]
    fn rule_insert_and_remove_round_trip() {
        let _g = store_guard();
        let h = next_rule_handle();
        let r = NftRule {
            table_family: 2,
            table_name:   String::from("oxide-test-t"),
            chain_name:   String::from("input"),
            handle:       h,
            raw_expr:     Vec::new(),
        };
        let before = rules_snapshot().len();
        rule_insert(r).unwrap();
        assert_eq!(rules_snapshot().len(), before + 1);
        let n = rule_remove(2, "oxide-test-t", "input", h);
        assert_eq!(n, 1);
        assert_eq!(rules_snapshot().len(), before);
    }

    #[test]
    fn malformed_rule_is_not_published() {
        let _g = store_guard();
        let before_rules = rules_snapshot().len();
        let before_gen = gen_current();
        let result = rule_insert(NftRule {
            table_family: 2,
            table_name: String::from("oxide-test-invalid"),
            chain_name: String::from("input"),
            handle: next_rule_handle(),
            raw_expr: vec![8, 0, 1, 0],
        });
        assert_eq!(result, Err(nft_expr::ParseError::Malformed));
        assert_eq!(rules_snapshot().len(), before_rules);
        assert_eq!(gen_current(), before_gen, "a rejected rule must not publish a generation");
    }

    #[test]
    fn verdict_encoding_matches_linux() {
        assert_eq!(Verdict::Drop.as_u32(),     0);
        assert_eq!(Verdict::Accept.as_u32(),   1);
        assert_eq!(Verdict::Stolen.as_u32(),   2);
        assert_eq!(Verdict::Queue(7).as_u32(), 3 | (7u32 << 16));
        assert_eq!(Verdict::Repeat.as_u32(),   4);
    }

    #[test]
    fn eval_accepts_when_no_base_chain_on_hook() {
        // No chain registered on a fresh hook id ⇒ default Accept.
        // 4242 is well outside any real hook value to avoid colliding
        // with other tests' inserts.
        assert_eq!(eval(4242, &[], nft_expr::NFPROTO_IPV4), Verdict::Accept);
    }

    #[test]
    fn eval_drop_policy_drops_packet() {
        let _g = store_guard();
        // Insert a base chain bound to a synthetic hook id with
        // policy=DROP. eval() should return Drop. Use a per-test
        // hook id so parallel tests don't trample.
        let c = NftChain {
            table_family: 2,
            table_name:   String::from("oxide-test-hookT"),
            name:         String::from("input"),
            hook:         Some(7777),
            priority:     0,
            policy:       NFT_CHAIN_POLICY_DROP,
        };
        chain_insert(c);
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
        chain_insert_in(OWNER, NftChain {
            table_family: nft_expr::NFPROTO_IPV4,
            table_name: name.into(),
            name: "input".into(),
            hook: Some(HOOK),
            priority: 0,
            policy: NFT_CHAIN_POLICY_DROP,
        });

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
        // Build a rule that unconditionally drops via NFTA_RULE_EXPRESSIONS.
        fn nla(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
            let total = 4 + payload.len();
            buf.extend_from_slice(&(total as u16).to_ne_bytes());
            buf.extend_from_slice(&ty.to_ne_bytes());
            buf.extend_from_slice(payload);
            while buf.len() % 4 != 0 { buf.push(0); }
        }
        fn nested(buf: &mut Vec<u8>, ty: u16, inner: &[u8]) { nla(buf, ty | 0x8000, inner); }
        fn u32be(buf: &mut Vec<u8>, ty: u16, v: u32) { nla(buf, ty, &v.to_be_bytes()); }
        fn s(buf: &mut Vec<u8>, ty: u16, st: &str) {
            let mut p = st.as_bytes().to_vec(); p.push(0);
            nla(buf, ty, &p);
        }
        let mut verdict = Vec::new();
        u32be(&mut verdict, NFTA_VERDICT_CODE, NF_DROP as u32);
        let mut data = Vec::new();
        nested(&mut data, NFTA_DATA_VERDICT, &verdict);
        let mut idata = Vec::new();
        u32be(&mut idata, NFTA_IMMEDIATE_DREG, 0);
        nested(&mut idata, NFTA_IMMEDIATE_DATA, &data);
        let mut expr = Vec::new();
        s(&mut expr, NFTA_EXPR_NAME, "immediate");
        nested(&mut expr, NFTA_EXPR_DATA, &idata);
        let mut raw_expr = Vec::new();
        nested(&mut raw_expr, NFTA_LIST_ELEM, &expr);

        let c = NftChain {
            table_family: 2,
            table_name:   String::from("oxide-test-evalT"),
            name:         String::from("input"),
            hook:         Some(8881),
            priority:     0,
            policy:       NFT_CHAIN_POLICY_ACCEPT,
        };
        chain_insert(c);
        let r = NftRule {
            table_family: 2,
            table_name:   String::from("oxide-test-evalT"),
            chain_name:   String::from("input"),
            handle:       next_rule_handle(),
            raw_expr,
        };
        rule_insert(r).unwrap();
        let generation = active_generation(8881).expect("compiled generation");
        let expr_ptr = generation.namespace(0).unwrap().hooks.iter()
            .find(|hook| hook.id == 8881).unwrap()
            .chains[0].rules[0].exprs.as_ptr();
        drop(generation);
        for _ in 0..64 {
            assert_eq!(eval(8881, &[], nft_expr::NFPROTO_IPV4), Verdict::Drop);
        }
        let generation = active_generation(8881).expect("same compiled generation");
        let after_ptr = generation.namespace(0).unwrap().hooks.iter()
            .find(|hook| hook.id == 8881).unwrap()
            .chains[0].rules[0].exprs.as_ptr();
        assert_eq!(after_ptr, expr_ptr, "packet evaluation must reuse the compiled expression blob");
        drop(generation);
        assert_eq!(eval(8881, &[], nft_expr::NFPROTO_IPV6), Verdict::Accept,
            "an IPv4 base chain must not run in the IPv6 hook family");
        let _ = chain_remove(2, "oxide-test-evalT", "input");
    }

    #[test]
    fn eval_accept_policy_passes_through() {
        let _g = store_guard();
        let c = NftChain {
            table_family: 2,
            table_name:   String::from("oxide-test-hookT2"),
            name:         String::from("input"),
            hook:         Some(7778),
            priority:     0,
            policy:       NFT_CHAIN_POLICY_ACCEPT,
        };
        chain_insert(c);
        assert_eq!(eval(7778, &[], nft_expr::NFPROTO_IPV4), Verdict::Accept);
        let _ = chain_remove(2, "oxide-test-hookT2", "input");
    }

    #[test]
    fn chain_insert_dedup_remove() {
        let _g = store_guard();
        let c = NftChain {
            table_family: 2,
            table_name:   String::from("oxide-test-t"),
            name:         String::from("input"),
            hook:         None,
            priority:     0,
            policy:       NFT_CHAIN_POLICY_ACCEPT,
        };
        let before = chains_snapshot().len();
        chain_insert(c.clone());
        chain_insert(c.clone());
        assert_eq!(chains_snapshot().len(), before + 1);
        let n = chain_remove(2, "oxide-test-t", "input");
        assert_eq!(n, 1);
        assert_eq!(chains_snapshot().len(), before);
    }

    #[test]
    fn setelem_insert_dedup_remove_round_trip() {
        let _g = store_guard();
        let e = NftSetElem {
            table_family: 2,
            table_name:   String::from("oxide-test-elT"),
            set_name:     String::from("blocked"),
            key:          alloc::vec![10, 0, 0, 5],
            data:         alloc::vec![],
        };
        let before = set_elems_snapshot().len();
        set_elem_insert(e.clone());
        set_elem_insert(e.clone()); // dedup
        assert_eq!(set_elems_snapshot().len(), before + 1);
        let n = set_elem_remove(2, "oxide-test-elT", "blocked", &[10, 0, 0, 5]);
        assert_eq!(n, 1);
        assert_eq!(set_elems_snapshot().len(), before);
    }

    #[test]
    fn setelem_lookup_round_trips_with_data() {
        let _g = store_guard();
        let e = NftSetElem {
            table_family: 2,
            table_name:   String::from("oxide-test-elT2"),
            set_name:     String::from("blocked"),
            key:          alloc::vec![1, 2, 3, 4],
            data:         alloc::vec![0xff],
        };
        set_elem_insert(e);
        let got = set_elem_lookup(2, "oxide-test-elT2", "blocked", &[1, 2, 3, 4]);
        assert_eq!(got, Some(alloc::vec![0xff]));
        let miss = set_elem_lookup(2, "oxide-test-elT2", "blocked", &[9, 9, 9, 9]);
        assert_eq!(miss, None);
        let _ = set_elem_remove(2, "oxide-test-elT2", "blocked", &[1, 2, 3, 4]);
    }

    #[test]
    fn find_attr_strips_nla_f_nested_bit() {
        // Build attrs with the F_NESTED bit set on the type field
        // and confirm find_str_attr / find_bytes_attr still locate
        // the payload after the F114 mask sweep.
        let mut buf: Vec<u8> = Vec::new();
        // type = NFTA_RULE_TABLE | NLA_F_NESTED (just to test the mask)
        let payload = b"foo\0";
        let total = 4 + payload.len();
        buf.extend_from_slice(&(total as u16).to_ne_bytes());
        buf.extend_from_slice(&(0x8000u16 | super::nfta_rule::NFTA_RULE_TABLE).to_ne_bytes());
        buf.extend_from_slice(payload);
        while buf.len() % 4 != 0 { buf.push(0); }
        assert_eq!(super::find_str_attr(&buf, super::nfta_rule::NFTA_RULE_TABLE), Some("foo"));
    }

    #[test]
    fn rule_handles_are_unique() {
        let a = next_rule_handle();
        let b = next_rule_handle();
        assert_ne!(a, b);
    }

    fn append_nlmsg(datagram: &mut Vec<u8>, ty: u16, seq: u32, body: &[u8]) {
        let len = netlink::Nlmsghdr::SIZE + body.len();
        let header = netlink::Nlmsghdr {
            nlmsg_len: len as u32,
            nlmsg_type: ty,
            nlmsg_flags: netlink::flags::NLM_F_REQUEST,
            nlmsg_seq: seq,
            nlmsg_pid: 7,
        };
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
        super::put_nlattr_str(&mut body, nfta_table::NFTA_TABLE_NAME, name);
        append_nlmsg(
            datagram,
            ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8) | nft_msg::NFT_MSG_NEWTABLE as u16,
            seq,
            &body,
        );
    }

    fn append_malformed_rule(datagram: &mut Vec<u8>, seq: u32, table: &str) {
        let mut body = Vec::new();
        let mut nfg = [0u8; Nfgenmsg::SIZE];
        Nfgenmsg { nfgen_family: 2, version: 0, res_id: 0 }.write_to(&mut nfg);
        body.extend_from_slice(&nfg);
        super::put_nlattr_str(&mut body, nfta_rule::NFTA_RULE_TABLE, table);
        super::put_nlattr_str(&mut body, nfta_rule::NFTA_RULE_CHAIN, "input");
        super::put_nlattr(&mut body, nfta_rule::NFTA_RULE_EXPRESSIONS, &[8, 0, 1, 0]);
        append_nlmsg(
            datagram,
            ((subsys::NFNL_SUBSYS_NFTABLES as u16) << 8) | nft_msg::NFT_MSG_NEWRULE as u16,
            seq,
            &body,
        );
    }

    #[test]
    fn nfnetlink_batch_publishes_one_atomic_generation() {
        let _g = store_guard();
        let first = "oxide-batch-first";
        let second = "oxide-batch-second";
        let _ = table_remove(2, first);
        let _ = table_remove(2, second);
        let before = gen_current();
        let mut datagram = Vec::new();
        append_nlmsg(&mut datagram, netlink::msg::NLMSG_MIN_TYPE, 1, &[]);
        append_newtable(&mut datagram, 2, first);
        append_newtable(&mut datagram, 3, second);
        append_nlmsg(&mut datagram, netlink::msg::NLMSG_MIN_TYPE + 1, 4, &[]);
        let _ = handle(&datagram, 0);
        assert_eq!(gen_current(), before + 1, "one batch must publish one generation");
        let tables = tables_snapshot();
        assert!(tables.iter().any(|table| table.family == 2 && table.name == first));
        assert!(tables.iter().any(|table| table.family == 2 && table.name == second));
        let _ = table_remove(2, first);
        let _ = table_remove(2, second);
    }

    #[test]
    fn unbatched_messages_remain_independent_transactions() {
        let _g = store_guard();
        let first = "oxide-unbatched-first";
        let second = "oxide-unbatched-second";
        let _ = table_remove(2, first);
        let _ = table_remove(2, second);
        let before = gen_current();
        let mut datagram = Vec::new();
        append_newtable(&mut datagram, 1, first);
        append_newtable(&mut datagram, 2, second);
        let _ = handle(&datagram, 0);
        assert_eq!(gen_current(), before + 2,
            "without batch markers each request is its own transaction");
        let _ = table_remove(2, first);
        let _ = table_remove(2, second);
    }

    #[test]
    fn nfnetlink_batch_error_rolls_back_without_publication() {
        let _g = store_guard();
        let table = "oxide-batch-rollback";
        let _ = table_remove(2, table);
        let before = gen_current();
        let mut datagram = Vec::new();
        append_nlmsg(&mut datagram, netlink::msg::NLMSG_MIN_TYPE, 1, &[]);
        append_newtable(&mut datagram, 2, table);
        append_malformed_rule(&mut datagram, 3, table);
        append_nlmsg(&mut datagram, netlink::msg::NLMSG_MIN_TYPE + 1, 4, &[]);
        let reply = handle(&datagram, 0);
        assert!(reply.windows(4).any(|bytes| i32::from_ne_bytes(bytes.try_into().unwrap()) == -22),
            "malformed rule must return EINVAL");
        assert_eq!(gen_current(), before, "failed batch must not publish");
        assert!(!tables_snapshot().iter().any(|item| item.family == 2 && item.name == table),
            "failed batch must restore the canonical control state");
    }

    #[test]
    #[ignore = "manual release-mode packet-path performance measurement"]
    fn packet_path_benchmark_64_rules() {
        let _g = store_guard();
        const HOOK: u32 = 15_555;
        const RULES: usize = 64;
        const ITERATIONS: usize = 100_000;
        let table = "oxide-bench-nft";
        let chain = "input";
        chain_insert(NftChain {
            table_family: nft_expr::NFPROTO_IPV4,
            table_name: table.into(),
            name: chain.into(),
            hook: Some(HOOK),
            priority: 0,
            policy: NFT_CHAIN_POLICY_DROP,
        });
        let mut handles = Vec::with_capacity(RULES);
        for _ in 0..RULES {
            let handle = next_rule_handle();
            handles.push(handle);
            rule_insert(NftRule {
                table_family: nft_expr::NFPROTO_IPV4,
                table_name: table.into(),
                chain_name: chain.into(),
                handle,
                raw_expr: Vec::new(),
            }).unwrap();
        }
        assert_eq!(eval(HOOK, &[], nft_expr::NFPROTO_IPV4), Verdict::Drop);
        let start = std::time::Instant::now();
        for _ in 0..ITERATIONS {
            std::hint::black_box(eval(HOOK, &[], nft_expr::NFPROTO_IPV4));
        }
        let elapsed = start.elapsed().as_nanos();
        std::println!(
            "NFT_EVAL_64_RULES iterations={ITERATIONS} elapsed_ns={elapsed} ns_per_packet={}",
            elapsed / ITERATIONS as u128,
        );
        for handle in handles {
            let _ = rule_remove(nft_expr::NFPROTO_IPV4, table, chain, handle);
        }
        let _ = chain_remove(nft_expr::NFPROTO_IPV4, table, chain);
    }
