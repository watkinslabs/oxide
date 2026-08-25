    use super::ObjectState;
    use crate::nft_expr::access::CtAccess;
    use crate::nft_expr::uapi::{NFTA_CONNLIMIT_COUNT, NFTA_CT_HELPER_L3PROTO,
                                NFTA_CT_HELPER_L4PROTO, NFTA_CT_HELPER_NAME, NFTA_QUOTA_BYTES,
                                NFT_OBJECT_CONNLIMIT, NFT_OBJECT_CT_HELPER,
                                NFT_OBJECT_QUOTA, NFT_OBJECT_SYNPROXY, NFTA_SYNPROXY_MSS,
                                NFTA_SYNPROXY_WSCALE, NFTA_SYNPROXY_FLAGS, NF_STOLEN, NFT_BREAK,
                                NFT_OBJECT_CT_TIMEOUT, NFTA_CT_TIMEOUT_L4PROTO,
                                NFTA_CT_TIMEOUT_DATA, CTA_TIMEOUT_TCP_ESTABLISHED,
                                NFT_OBJECT_CT_EXPECT, NFTA_CT_EXPECT_L4PROTO,
                                NFTA_CT_EXPECT_DPORT, NFTA_CT_EXPECT_TIMEOUT,
                                NFTA_CT_EXPECT_SIZE};
    use alloc::sync::Arc;
    use alloc::string::String;
    use core::cell::Cell;
    use conntrack::tuple::Tuple;

    fn attr(kind: u16, bytes: &[u8]) -> alloc::vec::Vec<u8> {
        let len = 4 + bytes.len();
        let mut out = alloc::vec![0; (len + 3) & !3];
        out[..2].copy_from_slice(&(len as u16).to_ne_bytes());
        out[2..4].copy_from_slice(&kind.to_ne_bytes());
        out[4..len].copy_from_slice(bytes);
        out
    }

    #[test]
    fn quota_object_keeps_consumption_across_evaluations() {
        let data = attr(NFTA_QUOTA_BYTES, &10u64.to_be_bytes());
        let state = ObjectState::from_wire(NFT_OBJECT_QUOTA, &data);
        assert_eq!(state.eval(6, 0), None);
        assert_eq!(state.eval(5, 0), Some(NFT_BREAK));
    }

    #[test]
    fn synproxy_object_shares_the_packet_action_with_the_expression() {
        let mut data = attr(NFTA_SYNPROXY_MSS, &1460u16.to_be_bytes());
        data.extend(attr(NFTA_SYNPROXY_WSCALE, &[7]));
        data.extend(attr(NFTA_SYNPROXY_FLAGS, &1u32.to_be_bytes()));
        let state = ObjectState::from_wire(NFT_OBJECT_SYNPROXY, &data);
        let mut packet = alloc::vec![0; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[9] = 6;
        packet[20 + 12] = 0x50;
        packet[20 + 13] = 0x02;
        let mut actions = alloc::vec::Vec::new();
        let mut secmark = 0;
        assert_eq!(state.eval_packet(&packet, crate::nft_expr::uapi::NFPROTO_IPV4,
                                     None, 0, None, &mut actions, &mut secmark), Some(NF_STOLEN));
        assert!(matches!(&actions[..], [crate::nft_expr::action::Action::Synproxy {
            mss: 1460, wscale: 7, flags: 1
        }]));
    }

    #[test]
    fn ct_timeout_object_keeps_linux_nested_tcp_defaults_and_override() {
        let nested = attr(CTA_TIMEOUT_TCP_ESTABLISHED, &77u32.to_be_bytes());
        let mut data = attr(NFTA_CT_TIMEOUT_L4PROTO, &[6]);
        data.extend(attr(NFTA_CT_TIMEOUT_DATA, &nested));
        let state = ObjectState::from_wire(NFT_OBJECT_CT_TIMEOUT, &data);
        let ObjectState::CtTimeout { l4proto, values, .. } = state else {
            panic!("valid TCP timeout data must create a timeout object");
        };
        assert_eq!(l4proto, 6);
        assert_eq!(values[1], 120);
        assert_eq!(values[3], 77);
        assert_eq!(values[0], values[1], "Linux UNSPEC aliases SYN_SENT");
    }

    struct ExpectPacket { tuple: Tuple, called: Cell<bool> }
    impl CtAccess for ExpectPacket {
        fn ctinfo(&self) -> u8 { 0 }
        fn tuple(&self, _dir: u8) -> Option<Tuple> { Some(self.tuple) }
        fn set_expectation(&self, _l3num: u16, _l4proto: u8, _dport: u16,
                           _timeout_ms: u32, _size: u8, _now: u64) -> bool {
            self.called.set(true);
            true
        }
    }

    #[test]
    fn ct_expect_object_uses_the_canonical_expectation_owner() {
        let mut data = attr(NFTA_CT_EXPECT_L4PROTO, &[17]);
        data.extend(attr(NFTA_CT_EXPECT_DPORT, &2123u16.to_be_bytes()));
        data.extend(attr(NFTA_CT_EXPECT_TIMEOUT, &5000u32.to_be_bytes()));
        data.extend(attr(NFTA_CT_EXPECT_SIZE, &[4]));
        let state = ObjectState::from_wire(NFT_OBJECT_CT_EXPECT, &data);
        let packet = ExpectPacket { tuple: Tuple { l3num: 2, protonum: 6, ..Tuple::default() },
                                     called: Cell::new(false) };
        let mut actions = alloc::vec::Vec::new();
        let mut secmark = 0;
        assert_eq!(state.eval_packet(&[], crate::nft_expr::uapi::NFPROTO_IPV4,
                                     Some(&packet), 0, None, &mut actions, &mut secmark), None);
        assert!(packet.called.get());
    }

    #[test]
    fn secmark_object_writes_the_resolved_sid_to_packet_metadata() {
        let state = ObjectState::Secmark { context: String::from("system_u:object_r:packet_t:s0"),
                                           secid: 42 };
        let mut secmark = 0;
        let mut actions = alloc::vec::Vec::new();
        assert_eq!(state.eval_packet(&[], crate::nft_expr::uapi::NFPROTO_IPV4,
                                     None, 0, None, &mut actions, &mut secmark), None);
        assert_eq!(secmark, 42);
    }

    struct LiveFlow(Arc<conntrack::Conn>);
    impl CtAccess for LiveFlow {
        fn ctinfo(&self) -> u8 { 0 }
        fn flow(&self) -> Option<Arc<conntrack::Conn>> { Some(self.0.clone()) }
    }

    #[test]
    fn connlimit_object_counts_each_flow_once_and_has_its_own_list() {
        let data = attr(NFTA_CONNLIMIT_COUNT, &1u32.to_be_bytes());
        let state = ObjectState::from_wire(NFT_OBJECT_CONNLIMIT, &data);
        let first = LiveFlow(Arc::new(conntrack::Conn::new(1, Tuple::default(), Tuple::default(), 0)));
        let second = LiveFlow(Arc::new(conntrack::Conn::new(2, Tuple::default(), Tuple::default(), 0)));
        first.0.refresh(0, 60);
        second.0.refresh(0, 60);
        assert_eq!(state.eval_for(60, 0, Some(&first)), None);
        assert_eq!(state.eval_for(60, 0, Some(&first)), None,
                   "revisiting one conntrack flow must not grow the object list");
        assert_eq!(state.eval_for(60, 0, Some(&second)), Some(NFT_BREAK));
        second.0.set_status_bits(conntrack::uapi::IPS_DYING);
        assert_eq!(state.eval_for(60, 0, Some(&first)), None,
                   "a dying flow is reaped from the object's conncount list");
    }

    struct Untracked(Tuple);
    impl CtAccess for Untracked {
        fn ctinfo(&self) -> u8 { 0 }
        fn tuple(&self, _dir: u8) -> Option<Tuple> { Some(self.0) }
    }

    #[test]
    fn connlimit_object_counts_untracked_tuples_by_identity() {
        let data = attr(NFTA_CONNLIMIT_COUNT, &1u32.to_be_bytes());
        let state = ObjectState::from_wire(NFT_OBJECT_CONNLIMIT, &data);
        let first = Untracked(Tuple::default());
        let second = Untracked(Tuple { src: Default::default(), dst: Default::default(),
                                       l3num: 2, protonum: 6, zone: 0 });
        assert_eq!(state.eval_for(60, 0, Some(&first)), None);
        assert_eq!(state.eval_for(60, 0, Some(&first)), None);
        assert_eq!(state.eval_for(60, 0, Some(&second)), Some(NFT_BREAK));
    }

    struct HelperPacket { tuple: Tuple, attached: Cell<bool> }
    impl CtAccess for HelperPacket {
        fn ctinfo(&self) -> u8 { 0 }
        fn tuple(&self, _dir: u8) -> Option<Tuple> { Some(self.tuple) }
        fn set_helper(&self, _name: &str, _l4proto: u8) -> bool {
            self.attached.set(true);
            true
        }
    }

    #[test]
    fn conntrack_helper_object_uses_the_packet_owner_and_protocol() {
        let mut data = attr(NFTA_CT_HELPER_NAME, b"dns\0");
        data.extend(attr(NFTA_CT_HELPER_L3PROTO, &2u16.to_be_bytes()));
        data.extend(attr(NFTA_CT_HELPER_L4PROTO, &[17]));
        let state = ObjectState::from_wire(NFT_OBJECT_CT_HELPER, &data);
        let packet = HelperPacket { tuple: Tuple { l3num: 2, protonum: 17, ..Tuple::default() },
                                     attached: Cell::new(false) };
        assert_eq!(state.eval_for(60, 0, Some(&packet)), None);
        assert!(packet.attached.get());
    }
