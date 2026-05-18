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
    fn gen_bump_is_monotonic() {
        let a = gen_current();
        let b = gen_bump();
        assert!(b > a);
        let c = gen_bump();
        assert!(c > b);
    }

    #[test]
    fn set_insert_dedup_remove() {
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
        assert_eq!(n, 1);
        assert_eq!(sets_snapshot().len(), before);
    }

    #[test]
    fn rule_insert_and_remove_round_trip() {
        let h = next_rule_handle();
        let r = NftRule {
            table_family: 2,
            table_name:   String::from("oxide-test-t"),
            chain_name:   String::from("input"),
            handle:       h,
            raw_expr:     vec![1, 2, 3],
        };
        let before = rules_snapshot().len();
        rule_insert(r);
        assert_eq!(rules_snapshot().len(), before + 1);
        let n = rule_remove(2, "oxide-test-t", "input", h);
        assert_eq!(n, 1);
        assert_eq!(rules_snapshot().len(), before);
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
        assert_eq!(eval(4242, &[]), Verdict::Accept);
    }

    #[test]
    fn eval_drop_policy_drops_packet() {
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
        assert_eq!(eval(7777, &[]), Verdict::Drop);
        let _ = chain_remove(2, "oxide-test-hookT", "input");
    }

    #[test]
    fn eval_runs_rule_immediate_drop() {
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
        rule_insert(r);
        assert_eq!(eval(8881, &[]), Verdict::Drop);
        let _ = chain_remove(2, "oxide-test-evalT", "input");
    }

    #[test]
    fn eval_accept_policy_passes_through() {
        let c = NftChain {
            table_family: 2,
            table_name:   String::from("oxide-test-hookT2"),
            name:         String::from("input"),
            hook:         Some(7778),
            priority:     0,
            policy:       NFT_CHAIN_POLICY_ACCEPT,
        };
        chain_insert(c);
        assert_eq!(eval(7778, &[]), Verdict::Accept);
        let _ = chain_remove(2, "oxide-test-hookT2", "input");
    }

    #[test]
    fn chain_insert_dedup_remove() {
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
    fn rule_handles_are_unique() {
        let a = next_rule_handle();
        let b = next_rule_handle();
        assert_ne!(a, b);
    }
