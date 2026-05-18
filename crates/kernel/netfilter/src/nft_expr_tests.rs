use super::*;

    fn nla(buf: &mut Vec<u8>, ty: u16, payload: &[u8]) {
        let total = 4 + payload.len();
        buf.extend_from_slice(&(total as u16).to_ne_bytes());
        buf.extend_from_slice(&ty.to_ne_bytes());
        buf.extend_from_slice(payload);
        while buf.len() % 4 != 0 { buf.push(0); }
    }

    fn nla_u32_be(buf: &mut Vec<u8>, ty: u16, v: u32) {
        nla(buf, ty, &v.to_be_bytes());
    }

    fn nla_str(buf: &mut Vec<u8>, ty: u16, s: &str) {
        let mut p = s.as_bytes().to_vec();
        p.push(0);
        nla(buf, ty, &p);
    }

    fn nla_nested(buf: &mut Vec<u8>, ty: u16, inner: &[u8]) {
        nla(buf, ty | 0x8000, inner);
    }

    fn build_immediate_drop() -> Vec<u8> {
        // NFTA_LIST_ELEM { NFTA_EXPR_NAME="immediate", NFTA_EXPR_DATA{ ... } }
        let mut verdict = Vec::new();
        nla_u32_be(&mut verdict, NFTA_VERDICT_CODE, NF_DROP as u32);
        let mut data = Vec::new();
        nla_nested(&mut data, NFTA_DATA_VERDICT, &verdict);
        let mut idata = Vec::new();
        nla_u32_be(&mut idata, NFTA_IMMEDIATE_DREG, 0); // VERDICT
        nla_nested(&mut idata, NFTA_IMMEDIATE_DATA, &data);
        let mut expr = Vec::new();
        nla_str(&mut expr, NFTA_EXPR_NAME, "immediate");
        nla_nested(&mut expr, NFTA_EXPR_DATA, &idata);
        let mut out = Vec::new();
        nla_nested(&mut out, NFTA_LIST_ELEM, &expr);
        out
    }

    #[test]
    fn parse_immediate_drop_round_trip() {
        let bytes = build_immediate_drop();
        let exprs = parse_exprs(&bytes);
        assert_eq!(exprs.len(), 1);
        assert!(matches!(exprs[0], Expr::Immediate { dreg: 0, verdict: Some(0), .. }));
    }

    #[test]
    fn run_immediate_drop_returns_drop() {
        let bytes = build_immediate_drop();
        let exprs = parse_exprs(&bytes);
        assert_eq!(run_rule(&exprs, &[]), Some(NF_DROP));
    }

    fn build_payload_cmp_drop_for_src_ipv4(src: [u8; 4]) -> Vec<u8> {
        // payload (NETWORK, offset 12, len 4) -> reg 1
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 12);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 4);
        let mut payload_expr = Vec::new();
        nla_str(&mut payload_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut payload_expr, NFTA_EXPR_DATA, &pdata);

        // cmp (EQ, reg 1, src)
        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &src);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP, NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut cmp_expr = Vec::new();
        nla_str(&mut cmp_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut cmp_expr, NFTA_EXPR_DATA, &cdata);

        // immediate drop
        let imm = build_immediate_drop();
        // imm wraps a single LIST_ELEM already — strip it: extract
        // the LIST_ELEM body. Simpler: rebuild flat list.

        let mut out = Vec::new();
        nla_nested(&mut out, NFTA_LIST_ELEM, &payload_expr);
        nla_nested(&mut out, NFTA_LIST_ELEM, &cmp_expr);
        out.extend_from_slice(&imm); // already a LIST_ELEM wrap
        out
    }

    fn ipv4_pkt_with_src(src: [u8; 4]) -> Vec<u8> {
        // 20-byte IPv4 header: src is at offset 12..16.
        let mut p = vec![0u8; 20];
        p[12..16].copy_from_slice(&src);
        p
    }

    #[test]
    fn drop_when_src_matches() {
        let rule = build_payload_cmp_drop_for_src_ipv4([10, 0, 0, 5]);
        let exprs = parse_exprs(&rule);
        assert_eq!(exprs.len(), 3);
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule(&exprs, &pkt), Some(NF_DROP));
    }

    #[test]
    fn skip_when_src_doesnt_match() {
        let rule = build_payload_cmp_drop_for_src_ipv4([10, 0, 0, 5]);
        let exprs = parse_exprs(&rule);
        let pkt = ipv4_pkt_with_src([10, 0, 0, 6]);
        assert_eq!(run_rule(&exprs, &pkt), None);
    }

    fn build_meta_l4proto_drop_match(want: u8) -> Vec<u8> {
        // meta l4proto -> reg1
        let mut mdata = Vec::new();
        nla_u32_be(&mut mdata, NFTA_META_DREG, 1);
        nla_u32_be(&mut mdata, NFTA_META_KEY,  NFT_META_L4PROTO);
        let mut m_expr = Vec::new();
        nla_str(&mut m_expr, NFTA_EXPR_NAME, "meta");
        nla_nested(&mut m_expr, NFTA_EXPR_DATA, &mdata);

        // cmp eq reg1, want (1 byte)
        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &[want]);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP, NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();
        let mut out = Vec::new();
        nla_nested(&mut out, NFTA_LIST_ELEM, &m_expr);
        nla_nested(&mut out, NFTA_LIST_ELEM, &c_expr);
        out.extend_from_slice(&imm);
        out
    }

    fn ipv4_pkt_proto(proto: u8) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[9] = proto;
        p
    }

    fn build_transport_port_drop(dst_port_be: [u8; 2]) -> Vec<u8> {
        // payload (TRANSPORT, offset 2, len 2) -> reg 1   (UDP dst port)
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_TRANSPORT_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 2);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 2);
        let mut p_expr = Vec::new();
        nla_str(&mut p_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut p_expr, NFTA_EXPR_DATA, &pdata);

        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &dst_port_be);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP,  NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();
        let mut out = Vec::new();
        nla_nested(&mut out, NFTA_LIST_ELEM, &p_expr);
        nla_nested(&mut out, NFTA_LIST_ELEM, &c_expr);
        out.extend_from_slice(&imm);
        out
    }

    fn ipv4_udp_pkt(dst_port: u16) -> Vec<u8> {
        // Minimal IPv4 hdr (IHL=5 → 20 bytes) + 8 byte UDP hdr.
        let mut p = vec![0u8; 28];
        p[0] = 0x45; // ver=4 IHL=5
        p[9] = 17;   // proto=UDP
        // UDP dst port at L4+2..L4+4
        let dp = dst_port.to_be_bytes();
        p[22] = dp[0]; p[23] = dp[1];
        p
    }

    #[test]
    fn payload_transport_filters_udp_dst_port() {
        let rule = build_transport_port_drop([0, 53]); // DNS
        let exprs = parse_exprs(&rule);
        assert_eq!(run_rule(&exprs, &ipv4_udp_pkt(53)), Some(NF_DROP));
        assert_eq!(run_rule(&exprs, &ipv4_udp_pkt(80)), None);
    }

    #[test]
    fn payload_transport_honors_variable_ihl() {
        // IHL=6 (24 bytes of IPv4 hdr w/ 4-byte options). Put port
        // at offset 24+2=26.
        let rule = build_transport_port_drop([0, 22]);
        let exprs = parse_exprs(&rule);
        let mut p = vec![0u8; 32];
        p[0] = 0x46; // ver=4 IHL=6
        p[9] = 6;    // TCP
        p[26] = 0; p[27] = 22;
        assert_eq!(run_rule(&exprs, &p), Some(NF_DROP));
    }

    #[test]
    fn meta_l4proto_matches_tcp() {
        let rule = build_meta_l4proto_drop_match(6); // TCP
        let exprs = parse_exprs(&rule);
        assert_eq!(run_rule(&exprs, &ipv4_pkt_proto(6)), Some(NF_DROP));
        assert_eq!(run_rule(&exprs, &ipv4_pkt_proto(17)), None);
    }

    #[test]
    fn meta_len_loads_pkt_len() {
        // Standalone parse-and-run of just meta + cmp on pkt len.
        let mut mdata = Vec::new();
        nla_u32_be(&mut mdata, NFTA_META_DREG, 1);
        nla_u32_be(&mut mdata, NFTA_META_KEY,  NFT_META_LEN);
        let mut m_expr = Vec::new();
        nla_str(&mut m_expr, NFTA_EXPR_NAME, "meta");
        nla_nested(&mut m_expr, NFTA_EXPR_DATA, &mdata);

        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &(20u32).to_le_bytes());
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP,  NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();
        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &m_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);

        let exprs = parse_exprs(&rule);
        assert_eq!(run_rule(&exprs, &vec![0u8; 20]), Some(NF_DROP));
        assert_eq!(run_rule(&exprs, &vec![0u8; 40]), None);
    }

    #[test]
    fn byteorder_reverses_pairs() {
        // sreg=1, dreg=1, len=4, size=2 — reverse each 2-byte half.
        let mut bdata = Vec::new();
        nla_u32_be(&mut bdata, NFTA_BYTEORDER_SREG, 1);
        nla_u32_be(&mut bdata, NFTA_BYTEORDER_DREG, 1);
        nla_u32_be(&mut bdata, NFTA_BYTEORDER_OP, 0);
        nla_u32_be(&mut bdata, NFTA_BYTEORDER_LEN, 4);
        nla_u32_be(&mut bdata, NFTA_BYTEORDER_SIZE, 2);
        let mut b_expr = Vec::new();
        nla_str(&mut b_expr, NFTA_EXPR_NAME, "byteorder");
        nla_nested(&mut b_expr, NFTA_EXPR_DATA, &bdata);
        // Load 0x11 0x22 0x33 0x44 → expect 0x22 0x11 0x44 0x33
        // We bake load via payload at offset 0 from a synthetic
        // L3 buffer.
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 0);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 4);
        let mut p_expr = Vec::new();
        nla_str(&mut p_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut p_expr, NFTA_EXPR_DATA, &pdata);

        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &[0x22, 0x11, 0x44, 0x33]);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP,  NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();
        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &p_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &b_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);

        let exprs = parse_exprs(&rule);
        let pkt = vec![0x11, 0x22, 0x33, 0x44, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(run_rule(&exprs, &pkt), Some(NF_DROP));
    }

    #[test]
    fn bitwise_masks_then_xors() {
        // payload(NETWORK, 12, 4) -> reg1 ; bitwise reg1 mask 0xff_ff_00_00 xor 0 -> reg1 ;
        // cmp reg1 == 10.0.0.0 ; drop
        let mut pdata = Vec::new();
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_DREG, 1);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_OFFSET, 12);
        nla_u32_be(&mut pdata, NFTA_PAYLOAD_LEN, 4);
        let mut p_expr = Vec::new();
        nla_str(&mut p_expr, NFTA_EXPR_NAME, "payload");
        nla_nested(&mut p_expr, NFTA_EXPR_DATA, &pdata);

        let mut maskval = Vec::new();
        nla(&mut maskval, NFTA_DATA_VALUE, &[0xff, 0xff, 0x00, 0x00]);
        let mut xorval = Vec::new();
        nla(&mut xorval, NFTA_DATA_VALUE, &[0, 0, 0, 0]);
        let mut bdata = Vec::new();
        nla_u32_be(&mut bdata, NFTA_BITWISE_SREG, 1);
        nla_u32_be(&mut bdata, NFTA_BITWISE_DREG, 1);
        nla_u32_be(&mut bdata, NFTA_BITWISE_LEN, 4);
        nla_nested(&mut bdata, NFTA_BITWISE_MASK, &maskval);
        nla_nested(&mut bdata, NFTA_BITWISE_XOR,  &xorval);
        let mut b_expr = Vec::new();
        nla_str(&mut b_expr, NFTA_EXPR_NAME, "bitwise");
        nla_nested(&mut b_expr, NFTA_EXPR_DATA, &bdata);

        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &[10, 0, 0, 0]);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP,  NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &cdata);

        let imm = build_immediate_drop();
        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &p_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &b_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);

        let exprs = parse_exprs(&rule);
        let pkt_in = ipv4_pkt_with_src([10, 0, 5, 7]); // /16 → 10.0.0.0
        assert_eq!(run_rule(&exprs, &pkt_in), Some(NF_DROP));
        let pkt_out = ipv4_pkt_with_src([192, 168, 1, 1]);
        assert_eq!(run_rule(&exprs, &pkt_out), None);
    }

    #[test]
    fn counter_increments_on_reach() {
        // counter ; immediate drop
        let mut counter_data = Vec::new(); // counter expr has no body in v1
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "counter");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &counter_data);
        let imm = build_immediate_drop();
        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);
        let exprs = parse_exprs(&rule);

        let mut packets = 0u64;
        let mut bytes = 0u64;
        let pkt = vec![0u8; 40];
        assert_eq!(run_rule_full(&exprs, &pkt, None, &mut packets, &mut bytes),
                   Some(NF_DROP));
        assert_eq!(packets, 1);
        assert_eq!(bytes, 40);
        // Run again — accumulates
        assert_eq!(run_rule_full(&exprs, &pkt, None, &mut packets, &mut bytes),
                   Some(NF_DROP));
        assert_eq!(packets, 2);
        assert_eq!(bytes, 80);
        let _ = counter_data.is_empty();
    }

    #[test]
    fn counter_not_bumped_when_cmp_fails_before() {
        // cmp(reg1, eq, 0xff) — fails because reg starts 0; counter; drop
        // The counter sits after cmp, so it should NOT execute.
        let mut cmp_value = Vec::new();
        nla(&mut cmp_value, NFTA_DATA_VALUE, &[0xff, 0xff, 0xff, 0xff]);
        let mut cdata = Vec::new();
        nla_u32_be(&mut cdata, NFTA_CMP_SREG, 1);
        nla_u32_be(&mut cdata, NFTA_CMP_OP, NFT_CMP_EQ);
        nla_nested(&mut cdata, NFTA_CMP_DATA, &cmp_value);
        let mut cmp_expr = Vec::new();
        nla_str(&mut cmp_expr, NFTA_EXPR_NAME, "cmp");
        nla_nested(&mut cmp_expr, NFTA_EXPR_DATA, &cdata);

        let mut counter_data = Vec::new();
        let mut c_expr = Vec::new();
        nla_str(&mut c_expr, NFTA_EXPR_NAME, "counter");
        nla_nested(&mut c_expr, NFTA_EXPR_DATA, &counter_data);

        let imm = build_immediate_drop();
        let mut rule = Vec::new();
        nla_nested(&mut rule, NFTA_LIST_ELEM, &cmp_expr);
        nla_nested(&mut rule, NFTA_LIST_ELEM, &c_expr);
        rule.extend_from_slice(&imm);
        let exprs = parse_exprs(&rule);
        let mut p = 0u64;
        let mut b = 0u64;
        assert_eq!(run_rule_full(&exprs, &vec![0u8; 20], None, &mut p, &mut b), None);
        assert_eq!(p, 0);
        assert_eq!(b, 0);
        let _ = counter_data.is_empty();
    }

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
        let look = |_set: &str, key: &[u8]| -> Option<Vec<u8>> {
            if &key[..4] == &[10, 0, 0, 5] { Some(Vec::new()) } else { None }
        };
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule_with_lookup(&exprs, &pkt, Some(&look)), Some(NF_DROP));
    }

    #[test]
    fn lookup_miss_falls_through() {
        let rule = build_lookup_rule("blocked", false);
        let exprs = parse_exprs(&rule);
        let look = |_s: &str, _k: &[u8]| -> Option<Vec<u8>> { None };
        let pkt = ipv4_pkt_with_src([10, 0, 0, 5]);
        assert_eq!(run_rule_with_lookup(&exprs, &pkt, Some(&look)), None);
    }

    #[test]
    fn lookup_inverted_miss_drops() {
        let rule = build_lookup_rule("allowed", true);
        let exprs = parse_exprs(&rule);
        let look = |_s: &str, _k: &[u8]| -> Option<Vec<u8>> { None };
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
