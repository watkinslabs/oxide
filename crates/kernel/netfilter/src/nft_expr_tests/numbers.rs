// Every attribute number, key value, verdict code and register index, pinned
// against the contract. These are the values userspace sends; one of them
// wrong means a rule is parsed as a different rule, silently.

use crate::nft_expr::flags::NFT_PAYLOAD_L4CSUM_PSEUDOHDR;
use crate::nft_expr::limits::REG_BYTES;
use crate::nft_expr::regs::{reg_off, register_load_valid, Regs};
use crate::nft_expr::uapi::*;

#[test]
fn verdict_codes() {
    assert_eq!(NFT_CONTINUE, -1);
    assert_eq!(NFT_BREAK, -2);
    assert_eq!(NFT_JUMP, -3);
    assert_eq!(NFT_GOTO, -4);
    assert_eq!(NFT_RETURN, -5);
    // Base verdicts are non-negative, which is how an absolute verdict is
    // told from a walk-steering one.
    assert_eq!(NF_DROP, 0);
    assert_eq!(NF_ACCEPT, 1);
    assert_eq!(NF_STOLEN, 2);
    assert_eq!(NF_QUEUE, 3);
    assert_eq!(NF_REPEAT, 4);
}

#[test]
fn register_numbering_and_geometry() {
    assert_eq!(NFT_REG_VERDICT, 0);
    assert_eq!(NFT_REG_1, 1);
    assert_eq!(NFT_REG_4, 4);
    assert_eq!(NFT_REG32_00, 8);
    assert_eq!(NFT_REG32_15, 23);
    assert_eq!(NFT_REG_SIZE, 16);
    assert_eq!(NFT_REG32_SIZE, 4);
    assert_eq!(NFT_REG32_COUNT, 16);
    assert_eq!(REG_BYTES, 80);
}

#[test]
fn the_wide_and_narrow_registers_alias_the_same_bytes() {
    // Register 1 is the first 16-byte slot; the four 4-byte registers 8..11
    // are the same bytes. A rule that writes one and reads the other is legal
    // and common, so the offsets must line up exactly.
    assert_eq!(reg_off(NFT_REG_1), Some(16));
    assert_eq!(reg_off(NFT_REG32_00), Some(16));
    assert_eq!(reg_off(NFT_REG32_00 + 1), Some(20));
    assert_eq!(reg_off(NFT_REG_2), Some(32));
    assert_eq!(reg_off(NFT_REG32_00 + 4), Some(32));
    assert_eq!(reg_off(NFT_REG_4), Some(64));
    assert_eq!(reg_off(NFT_REG32_15), Some(76));
}

#[test]
fn the_verdict_register_is_not_addressable_as_data() {
    // Writing packet bytes into the verdict slot would let a payload load set
    // a verdict from attacker-controlled data.
    assert_eq!(reg_off(NFT_REG_VERDICT), None);
    assert!(!register_load_valid(NFT_REG_VERDICT, 4));
}

#[test]
fn a_load_may_not_run_off_the_end_of_the_file() {
    assert!(register_load_valid(NFT_REG_1, 16));
    assert!(!register_load_valid(NFT_REG_1, 65), "past the whole file");
    assert!(register_load_valid(NFT_REG_4, 16), "the last wide slot is exactly full");
    assert!(!register_load_valid(NFT_REG_4, 17));
    assert!(register_load_valid(NFT_REG32_15, 4));
    assert!(!register_load_valid(NFT_REG32_15, 5));
    assert!(!register_load_valid(NFT_REG_1, 0), "a zero-length load is not a load");
    assert!(!register_load_valid(24, 4), "past the last register number");
    assert!(!register_load_valid(5, 4), "between the wide and narrow ranges");
}

#[test]
fn a_register_write_is_readable_back_at_the_alias() {
    let mut r = Regs::new();
    assert!(r.store(NFT_REG_1, &[0xde, 0xad, 0xbe, 0xef]).is_some());
    assert_eq!(r.load(NFT_REG32_00, 4), Some(&[0xde, 0xad, 0xbe, 0xef][..]));
    assert!(r.store(NFT_REG32_00 + 1, &[1, 2, 3, 4]).is_some());
    assert_eq!(r.load(NFT_REG_1, 8), Some(&[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4][..]));
}

#[test]
fn a_register_starts_zeroed() {
    let r = Regs::new();
    assert_eq!(r.load(NFT_REG_1, 16), Some(&[0u8; 16][..]));
}

#[test]
fn expression_envelope_attributes() {
    assert_eq!(NFTA_LIST_ELEM, 1);
    assert_eq!(NFTA_EXPR_NAME, 1);
    assert_eq!(NFTA_EXPR_DATA, 2);
    assert_eq!(NFTA_DATA_VALUE, 1);
    assert_eq!(NFTA_DATA_VERDICT, 2);
    assert_eq!(NFTA_VERDICT_CODE, 1);
    assert_eq!(NFTA_VERDICT_CHAIN, 2);
}

#[test]
fn conntrack_attribute_and_key_numbers() {
    assert_eq!(NFTA_CT_DREG, 1);
    assert_eq!(NFTA_CT_KEY, 2);
    assert_eq!(NFTA_CT_DIRECTION, 3);
    assert_eq!(NFTA_CT_SREG, 4);
    for (key, want) in [(NFT_CT_STATE, 0u32), (NFT_CT_DIRECTION, 1), (NFT_CT_STATUS, 2),
                        (NFT_CT_MARK, 3), (NFT_CT_SECMARK, 4), (NFT_CT_EXPIRATION, 5),
                        (NFT_CT_HELPER, 6), (NFT_CT_L3PROTOCOL, 7), (NFT_CT_SRC, 8),
                        (NFT_CT_DST, 9), (NFT_CT_PROTOCOL, 10), (NFT_CT_PROTO_SRC, 11),
                        (NFT_CT_PROTO_DST, 12), (NFT_CT_LABELS, 13), (NFT_CT_PKTS, 14),
                        (NFT_CT_BYTES, 15), (NFT_CT_AVGPKT, 16), (NFT_CT_ZONE, 17),
                        (NFT_CT_EVENTMASK, 18), (NFT_CT_SRC_IP, 19), (NFT_CT_DST_IP, 20),
                        (NFT_CT_SRC_IP6, 21), (NFT_CT_DST_IP6, 22), (NFT_CT_ID, 23)]
    { assert_eq!(key, want); }
}

#[test]
fn meta_key_numbers() {
    for (key, want) in [(NFT_META_LEN, 0u32), (NFT_META_PROTOCOL, 1), (NFT_META_PRIORITY, 2),
                        (NFT_META_MARK, 3), (NFT_META_IIF, 4), (NFT_META_OIF, 5),
                        (NFT_META_IIFNAME, 6), (NFT_META_OIFNAME, 7), (NFT_META_IIFTYPE, 8),
                        (NFT_META_OIFTYPE, 9), (NFT_META_SKUID, 10), (NFT_META_SKGID, 11),
                        (NFT_META_NFTRACE, 12), (NFT_META_RTCLASSID, 13),
                        (NFT_META_SECMARK, 14), (NFT_META_NFPROTO, 15), (NFT_META_L4PROTO, 16),
                        (NFT_META_BRI_IIFNAME, 17), (NFT_META_BRI_OIFNAME, 18),
                        (NFT_META_PKTTYPE, 19), (NFT_META_CPU, 20), (NFT_META_IIFGROUP, 21),
                        (NFT_META_OIFGROUP, 22), (NFT_META_CGROUP, 23), (NFT_META_PRANDOM, 24),
                        (NFT_META_SECPATH, 25), (NFT_META_IIFKIND, 26), (NFT_META_OIFKIND, 27),
                        (NFT_META_BRI_IIFPVID, 28), (NFT_META_BRI_IIFVPROTO, 29),
                        (NFT_META_TIME_NS, 30), (NFT_META_TIME_DAY, 31),
                        (NFT_META_TIME_HOUR, 32), (NFT_META_SDIF, 33),
                        (NFT_META_SDIFNAME, 34), (NFT_META_BRI_BROUTE, 35),
                        (NFT_META_BRI_IIFHWADDR, 37)]
    { assert_eq!(key, want); }
}

#[test]
fn payload_bases_and_checksum_types() {
    assert_eq!(NFT_PAYLOAD_LL_HEADER, 0);
    assert_eq!(NFT_PAYLOAD_NETWORK_HEADER, 1);
    assert_eq!(NFT_PAYLOAD_TRANSPORT_HEADER, 2);
    assert_eq!(NFT_PAYLOAD_INNER_HEADER, 3);
    assert_eq!(NFT_PAYLOAD_TUN_HEADER, 4);
    assert_eq!(NFT_PAYLOAD_CSUM_NONE, 0);
    assert_eq!(NFT_PAYLOAD_CSUM_INET, 1);
    assert_eq!(NFT_PAYLOAD_CSUM_SCTP, 2);
    assert_eq!(NFT_PAYLOAD_L4CSUM_PSEUDOHDR, 1);
}

#[test]
fn the_remaining_expression_attribute_bases() {
    assert_eq!((NFTA_LIMIT_RATE, NFTA_LIMIT_UNIT, NFTA_LIMIT_BURST, NFTA_LIMIT_TYPE,
                NFTA_LIMIT_FLAGS), (1, 2, 3, 4, 5));
    assert_eq!((NFTA_QUOTA_BYTES, NFTA_QUOTA_FLAGS, NFTA_QUOTA_CONSUMED), (1, 2, 4));
    assert_eq!((NFTA_REJECT_TYPE, NFTA_REJECT_ICMP_CODE), (1, 2));
    assert_eq!((NFTA_QUEUE_NUM, NFTA_QUEUE_TOTAL, NFTA_QUEUE_FLAGS, NFTA_QUEUE_SREG_QNUM),
               (1, 2, 3, 4));
    assert_eq!((NFTA_RANGE_SREG, NFTA_RANGE_OP, NFTA_RANGE_FROM_DATA, NFTA_RANGE_TO_DATA),
               (1, 2, 3, 4));
    assert_eq!((NFTA_HASH_SREG, NFTA_HASH_DREG, NFTA_HASH_LEN, NFTA_HASH_MODULUS,
                NFTA_HASH_SEED, NFTA_HASH_OFFSET, NFTA_HASH_TYPE), (1, 2, 3, 4, 5, 6, 7));
    assert_eq!((NFTA_NG_DREG, NFTA_NG_MODULUS, NFTA_NG_TYPE, NFTA_NG_OFFSET), (1, 2, 3, 4));
    assert_eq!((NFTA_NAT_TYPE, NFTA_NAT_FAMILY, NFTA_NAT_REG_ADDR_MIN, NFTA_NAT_REG_ADDR_MAX,
                NFTA_NAT_REG_PROTO_MIN, NFTA_NAT_REG_PROTO_MAX, NFTA_NAT_FLAGS),
               (1, 2, 3, 4, 5, 6, 7));
    assert_eq!((NFTA_MASQ_FLAGS, NFTA_MASQ_REG_PROTO_MIN, NFTA_MASQ_REG_PROTO_MAX), (1, 2, 3));
    assert_eq!((NFTA_REDIR_REG_PROTO_MIN, NFTA_REDIR_REG_PROTO_MAX, NFTA_REDIR_FLAGS),
               (1, 2, 3));
    assert_eq!((NFTA_FIB_DREG, NFTA_FIB_RESULT, NFTA_FIB_FLAGS), (1, 2, 3));
    assert_eq!((NFTA_SOCKET_KEY, NFTA_SOCKET_DREG, NFTA_SOCKET_LEVEL), (1, 2, 3));
    assert_eq!((NFTA_RT_DREG, NFTA_RT_KEY), (1, 2));
    assert_eq!((NFTA_EXTHDR_DREG, NFTA_EXTHDR_TYPE, NFTA_EXTHDR_OFFSET, NFTA_EXTHDR_LEN,
                NFTA_EXTHDR_FLAGS, NFTA_EXTHDR_OP, NFTA_EXTHDR_SREG), (1, 2, 3, 4, 5, 6, 7));
}

#[test]
fn value_enumerations_the_rules_select_with() {
    assert_eq!((NFT_NAT_SNAT, NFT_NAT_DNAT), (0, 1));
    assert_eq!((NFT_LIMIT_PKTS, NFT_LIMIT_PKT_BYTES), (0, 1));
    assert_eq!((NFT_REJECT_ICMP_UNREACH, NFT_REJECT_TCP_RST, NFT_REJECT_ICMPX_UNREACH),
               (0, 1, 2));
    assert_eq!((NFT_HASH_JENKINS, NFT_HASH_SYM), (0, 1));
    assert_eq!((NFT_NG_INCREMENTAL, NFT_NG_RANDOM), (0, 1));
    assert_eq!((NFT_RANGE_EQ, NFT_RANGE_NEQ), (0, 1));
    assert_eq!((NFT_EXTHDR_OP_IPV6, NFT_EXTHDR_OP_TCPOPT, NFT_EXTHDR_OP_IPV4,
                NFT_EXTHDR_OP_SCTP, NFT_EXTHDR_OP_DCCP), (0, 1, 2, 3, 4));
    assert_eq!((NFT_RT_CLASSID, NFT_RT_NEXTHOP4, NFT_RT_NEXTHOP6, NFT_RT_TCPMSS, NFT_RT_XFRM),
               (0, 1, 2, 3, 4));
    assert_eq!((NFT_FIB_RESULT_OIF, NFT_FIB_RESULT_OIFNAME, NFT_FIB_RESULT_ADDRTYPE),
               (1, 2, 3));
    assert_eq!((NFT_SOCKET_TRANSPARENT, NFT_SOCKET_MARK, NFT_SOCKET_WILDCARD,
                NFT_SOCKET_CGROUPV2), (0, 1, 2, 3));
    assert_eq!((NFT_TUNNEL_PATH, NFT_TUNNEL_ID), (0, 1));
    assert_eq!((NFT_TUNNEL_MODE_NONE, NFT_TUNNEL_MODE_RX, NFT_TUNNEL_MODE_TX), (0, 1, 2));
}
