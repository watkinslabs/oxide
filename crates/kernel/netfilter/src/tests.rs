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
    fn chain_insert_dedup_remove() {
        let c = NftChain {
            table_family: 2,
            table_name:   String::from("oxide-test-t"),
            name:         String::from("input"),
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
