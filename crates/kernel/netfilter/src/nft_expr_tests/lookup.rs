use super::*;

fn build_lookup_rule(set_name: &str, invert: bool) -> Vec<u8> {
        // payload (NETWORK 12, 4) -> reg 1; lookup (set, reg 1); drop
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 12);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 4);
        let mut p_expr = Vec::new();
        nla_str(&mut p_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut p_expr, NFTA_EXPR_DATA, &pdata);

        let mut ldata = Vec::new();
        let mut sname = set_name.as_bytes().to_vec();
        sname.push(0);
        nla(&mut ldata, NFTA_LOOKUP_SET, &sname);
        nla_u32_be(&mut ldata, NFTA_LOOKUP_SREG, 1);
        nla_u32_be(&mut ldata, NFTA_LOOKUP_FLAGS, if invert { NFT_LOOKUP_F_INV } else { 0 });
        let mut l_expr = Vec::new();
        nla_str(&mut l_expr, NFTA_EXPR_NAME, "lookup");
        nla_nested(&mut l_expr, NFTA_EXPR_DATA, &ldata);

        let imm = build_immediate_drop();
        let mut out = Vec::new();
        nla_nested(&mut out, NFTA_LIST_ELEM, &p_expr);
        nla_nested(&mut out, NFTA_LIST_ELEM, &l_expr);
        out.extend_from_slice(&imm);
        out
    }

    #[test]
    fn lookup_hit_drops() {
        let rule = build_lookup_rule("blocked", false);
        let exprs = parse_exprs(&rule);
        let look = |_id: Option<usize>, _set: &str, key: &[u8]| -> bool {
            &key[..4] == &[10, 0, 0, 5]
        };
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule_with_lookup(&exprs, &pkt, Some(&look)), Some(NF_DROP));
    }

    #[test]
    fn lookup_miss_falls_through() {
        let rule = build_lookup_rule("blocked", false);
        let exprs = parse_exprs(&rule);
        let look = |_id: Option<usize>, _s: &str, _k: &[u8]| -> bool { false };
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule_with_lookup(&exprs, &pkt, Some(&look)), None);
    }

    #[test]
    fn lookup_inverted_miss_drops() {
        let rule = build_lookup_rule("allowed", true);
        let exprs = parse_exprs(&rule);
        let look = |_id: Option<usize>, _s: &str, _k: &[u8]| -> bool { false };
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule_with_lookup(&exprs, &pkt, Some(&look)), Some(NF_DROP));
    }

    #[test]
    fn neq_inverts_match() {
        // Build a rule with NEQ on src=10.0.0.5 then immediate drop.
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 12);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 4);
        let mut p_expr = Vec::new();
        nla_str(&mut p_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut p_expr, NFTA_EXPR_DATA, &pdata);

        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &[10, 0, 0, 5]);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP, NFT_CMP_NEQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();

        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &p_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);

        let exprs = parse_exprs(&rule);
        // pkt with a different src — NEQ matches — should drop
        let pkt = ipv4_pkt_with_src([10, 0, 0, 6]);
        assert_eq!(run_rule(&exprs, &pkt), Some(NF_DROP));
        // pkt with same src — NEQ doesn't match — skip
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule(&exprs, &pkt), None);
    }
