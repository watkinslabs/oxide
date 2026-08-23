// The proc and ctnetlink surfaces. Their layout is parsed positionally by
// userspace, so a field in the wrong place is an ABI break, not cosmetics.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::ctnetlink;
use crate::core::CtNet;
use crate::entry::{Conn, LabelUpdate, ProtoState, SctpProtoInfoUpdate, SeqAdjust,
                   SynproxyState, TcpProtoInfoUpdate};
use crate::helper::Helper;
use crate::procfs;
use crate::tuple::{InetAddr, ProtoPart, Tuple, TupleEnd};
use crate::uapi::*;
use super::tuple::{v4_icmp, v4_tcp, v4_udp};

fn entry(orig: Tuple) -> Arc<Conn> {
    let c = Conn::new(42, orig, orig.invert().unwrap(), 0);
    c.refresh(0, 100);
    Arc::new(c)
}

#[test]
fn a_tcp_line_carries_both_tuples_and_the_state() {
    let c = entry(v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80));
    let line = procfs::render_entry(&c, 0, false);
    assert!(line.contains("tcp"), "{line}");
    assert!(line.contains("src=10.0.0.1 dst=10.0.0.2 sport=1234 dport=80"), "{line}");
    assert!(line.contains("src=10.0.0.2 dst=10.0.0.1 sport=80 dport=1234"), "{line}");
    assert!(line.contains("[UNREPLIED]"), "an unanswered flow is marked: {line}");
    assert!(line.contains("100"), "the remaining timeout is reported: {line}");
}

#[test]
fn a_replied_assured_flow_drops_unreplied_and_gains_assured() {
    let c = entry(v4_udp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 53));
    c.set_status_bits(IPS_SEEN_REPLY | IPS_ASSURED);
    let line = procfs::render_entry(&c, 0, false);
    assert!(!line.contains("[UNREPLIED]"), "{line}");
    assert!(line.contains("[ASSURED]"), "{line}");
}

#[test]
fn icmp_reports_type_code_and_id_instead_of_ports() {
    let c = entry(v4_icmp([10, 0, 0, 1], [10, 0, 0, 2], 0x1234, 8));
    let line = procfs::render_entry(&c, 0, false);
    assert!(line.contains("type=8 code=0 id=4660"), "{line}");
    assert!(!line.contains("sport="), "an ICMP flow has no ports: {line}");
    assert!(line.contains("type=0 "), "the reply half is the echo reply: {line}");
}

#[test]
fn accounting_appears_only_when_enabled() {
    let c = entry(v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80));
    c.counters[IP_CT_DIR_ORIGINAL as usize].account(1500);
    c.counters[IP_CT_DIR_REPLY as usize].account(60);
    assert!(!procfs::render_entry(&c, 0, false).contains("packets="));
    let on = procfs::render_entry(&c, 0, true);
    assert!(on.contains("packets=1 bytes=1500"), "{on}");
    assert!(on.contains("packets=1 bytes=60"), "{on}");
}

#[test]
fn ctnetlink_ctrzero_returns_and_resets_both_accounting_directions() {
    let c = entry(v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80));
    c.counters[IP_CT_DIR_ORIGINAL as usize].account(1500);
    c.counters[IP_CT_DIR_REPLY as usize].account(60);
    let saved = c.counters_read_and_zero();
    assert_eq!(saved, [(1, 1500), (1, 60)]);
    assert_eq!(c.counters[IP_CT_DIR_ORIGINAL as usize].read(), (0, 0));
    assert_eq!(c.counters[IP_CT_DIR_REPLY as usize].read(), (0, 0));
    let wire = ctnetlink::encode_entry_with_counters(&c, 0, true, Some(saved));
    assert!(wire.windows(8).any(|window| window == 1500u64.to_be_bytes()));
    assert!(wire.windows(8).any(|window| window == 60u64.to_be_bytes()));
}

#[test]
fn an_ipv6_address_renders_in_its_own_family_form() {
    let mut a = [0u8; 16]; a[0] = 0x20; a[1] = 0x01; a[15] = 1;
    let mut b = [0u8; 16]; b[0] = 0x20; b[1] = 0x01; b[15] = 2;
    let t = Tuple {
        src: TupleEnd { addr: InetAddr::v6(a), proto: ProtoPart::port(1234) },
        dst: TupleEnd { addr: InetAddr::v6(b), proto: ProtoPart::port(80) },
        l3num: NFPROTO_IPV6, protonum: IPPROTO_TCP, zone: 0,
    };
    let line = procfs::render_entry(&entry(t), 0, false);
    assert!(line.contains("ipv6"), "{line}");
    assert!(line.contains("2001:0:0:0:0:0:0:1"), "{line}");
}

#[test]
fn the_whole_body_is_one_line_per_entry() {
    let a = entry(v4_tcp([10, 0, 0, 1], 1, [10, 0, 0, 2], 80));
    let b = entry(v4_tcp([10, 0, 0, 1], 2, [10, 0, 0, 2], 80));
    let body = procfs::render(&[a, b], 0, false);
    assert_eq!(body.lines().count(), 2);
    assert!(body.ends_with('\n'));
}

#[test]
fn ctnetlink_nests_both_tuples_with_the_nested_bit() {
    let c = entry(v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80));
    let buf = ctnetlink::encode_entry(&c, 0, false);
    // Walk the top level and collect the attribute kinds.
    let mut kinds = alloc::vec::Vec::new();
    let mut off = 0;
    while off + 4 <= buf.len() {
        let len = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
        let kind = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]);
        assert!(len >= 4 && off + len <= buf.len(), "attribute length must be sane");
        kinds.push(kind);
        off += (len + 3) & !3;
    }
    assert_eq!(off, buf.len(), "the walk must consume the buffer exactly");
    assert!(kinds.contains(&(CTA_TUPLE_ORIG | ctnetlink::NLA_F_NESTED)));
    assert!(kinds.contains(&(CTA_TUPLE_REPLY | ctnetlink::NLA_F_NESTED)));
    assert!(kinds.contains(&CTA_STATUS));
    assert!(kinds.contains(&CTA_TIMEOUT));
    assert!(kinds.contains(&CTA_ID));
}

#[test]
fn ctnetlink_dumps_both_sequence_adjustment_records() {
    let c = entry(v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80));
    assert!(c.seqadj_replace(IP_CT_DIR_ORIGINAL, SeqAdjust {
        correction_pos: 100, offset_before: -4, offset_after: 8, active: true,
    }));
    assert!(c.seqadj_replace(IP_CT_DIR_REPLY, SeqAdjust {
        correction_pos: 200, offset_before: 8, offset_after: -4, active: true,
    }));
    let buf = ctnetlink::encode_entry(&c, 0, false);
    let orig = (CTA_SEQ_ADJ_ORIG | ctnetlink::NLA_F_NESTED).to_ne_bytes();
    let reply = (CTA_SEQ_ADJ_REPLY | ctnetlink::NLA_F_NESTED).to_ne_bytes();
    assert!(buf.windows(2).any(|w| w == &100u32.to_be_bytes()[2..]));
    assert!(buf.windows(2).any(|w| w == orig));
    assert!(buf.windows(2).any(|w| w == reply));
    assert!(buf.windows(4).any(|w| w == &(-4i32 as u32).to_be_bytes()));
}

#[test]
fn ctnetlink_helper_dump_is_a_nul_terminated_nested_name() {
    let c = entry(v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80));
    *c.helper.lock() = Some(String::from("ftp"));
    let buf = ctnetlink::encode_entry(&c, 0, false);
    let mut off = 0;
    let mut found = false;
    while off + 4 <= buf.len() {
        let len = u16::from_ne_bytes([buf[off], buf[off + 1]]) as usize;
        let kind = u16::from_ne_bytes([buf[off + 2], buf[off + 3]]);
        assert!(len >= 4 && off + len <= buf.len());
        if kind == (CTA_HELP | ctnetlink::NLA_F_NESTED) {
            let nested = &buf[off + 4..off + len];
            let name_len = u16::from_ne_bytes([nested[0], nested[1]]) as usize;
            let name_kind = u16::from_ne_bytes([nested[2], nested[3]]);
            assert_eq!(name_kind, CTA_HELP_NAME);
            assert_eq!(&nested[4..name_len], b"ftp\0");
            found = true;
        }
        off += (len + 3) & !3;
    }
    assert!(found, "helper dump must carry CTA_HELP");
}

#[test]
fn ports_are_encoded_in_network_order() {
    let c = entry(v4_tcp([10, 0, 0, 1], 0x1234, [10, 0, 0, 2], 0x0050));
    let buf = ctnetlink::encode_entry(&c, 0, false);
    // 0x1234 big-endian is 12 34; little-endian would be 34 12.
    let needle = [0x12u8, 0x34];
    assert!(buf.windows(2).any(|w| w == needle),
        "a host-order port would be read as a different port by userspace");
}

#[test]
fn userspace_cannot_write_the_kernel_owned_status_bits() {
    let requested = IPS_CONFIRMED | IPS_DYING | IPS_SRC_NAT | IPS_SRC_NAT_DONE
        | IPS_EXPECTED | IPS_TEMPLATE | IPS_OFFLOAD | IPS_SEEN_REPLY | IPS_ASSURED;
    let allowed = ctnetlink::writable_status(requested);
    assert_eq!(allowed & IPS_CONFIRMED, 0);
    assert_eq!(allowed & IPS_DYING, 0);
    assert_eq!(allowed & IPS_SRC_NAT, 0);
    assert_eq!(allowed & IPS_SRC_NAT_DONE, 0);
    assert_eq!(allowed & IPS_EXPECTED, 0);
    assert_eq!(allowed & IPS_TEMPLATE, 0);
    assert_eq!(allowed & IPS_OFFLOAD, 0);
    // These two are legitimately settable.
    assert_eq!(allowed & IPS_SEEN_REPLY, IPS_SEEN_REPLY);
    assert_eq!(allowed & IPS_ASSURED, IPS_ASSURED);
}

#[test]
fn ctinfo_reflects_direction_and_relatedness() {
    let c = entry(v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80));
    assert_eq!(c.ctinfo(IP_CT_DIR_ORIGINAL), IP_CT_NEW);
    c.set_status_bits(IPS_SEEN_REPLY);
    assert_eq!(c.ctinfo(IP_CT_DIR_ORIGINAL), IP_CT_ESTABLISHED);
    assert_eq!(c.ctinfo(IP_CT_DIR_REPLY), IP_CT_ESTABLISHED_REPLY);
    c.set_status_bits(IPS_EXPECTED);
    assert_eq!(c.ctinfo(IP_CT_DIR_ORIGINAL), IP_CT_RELATED);
    assert_eq!(c.ctinfo(IP_CT_DIR_REPLY), IP_CT_RELATED_REPLY);
    assert_eq!(ctinfo2dir(IP_CT_NEW), IP_CT_DIR_ORIGINAL);
    assert_eq!(ctinfo2dir(IP_CT_ESTABLISHED_REPLY), IP_CT_DIR_REPLY);
}

#[test]
fn ctnetlink_owner_updates_and_deletes_the_live_entry() {
    let ct = CtNet::new(0, 7);
    let c = entry(v4_tcp([10, 0, 0, 1], 1234, [10, 0, 0, 2], 80));
    ct.table.add_pending(c.clone());
    assert!(ct.confirm(&c, 0));
    assert!(ct.update_id(c.id, 0, Some(7), Some(IPS_ASSURED), Some((0x55, None)), [
        Some(SeqAdjust { correction_pos: 30, offset_before: 1, offset_after: 2, active: true }),
        None,
    ], Some(TcpProtoInfoUpdate {
        state: Some(4), flags: [Some((0x80, 0xff)), None],
    }), None, None, None));
    assert_eq!(c.expires_in(0), 7);
    assert_eq!(c.mark.load(core::sync::atomic::Ordering::Relaxed), 0x55);
    assert_ne!(c.status() & IPS_ASSURED, 0);
    assert_eq!(c.seqadj_record(IP_CT_DIR_ORIGINAL).offset_after, 2);
    let ProtoState::Tcp(track) = *c.proto.lock() else { panic!("TCP test flow lost its tracker"); };
    assert_eq!(track.state, 4);
    assert_eq!(track.seen[IP_CT_DIR_ORIGINAL as usize].flags, 0x80);
    assert!(ct.delete_id(c.id, 0));
    assert!(ct.table.snapshot(0).is_empty());
    assert!(!ct.delete_id(c.id, 0));
}

#[test]
fn ctnetlink_labels_use_one_canonical_masked_store_and_dump() {
    let ct = CtNet::new(0, 7);
    let c = entry(v4_udp([192, 0, 2, 1], 40000, [198, 51, 100, 2], 53));
    ct.table.add_pending(c.clone());
    assert!(ct.confirm(&c, 0));
    let mut data = [0u8; NF_CT_LABELS_MAX_SIZE];
    data[0] = 0x05;
    let mut mask = [0u8; NF_CT_LABELS_MAX_SIZE];
    mask[0] = 0x0f;
    assert!(ct.update_id(c.id, 0, None, None, None, [None, None], None,
        None, Some(LabelUpdate { data, mask: Some(mask), len: 4 }), None));
    data[0] = 0x80;
    mask[0] = 0x80;
    assert!(ct.update_id(c.id, 0, None, None, None, [None, None], None,
        None, Some(LabelUpdate { data, mask: Some(mask), len: 4 }), None));
    let mut got = [0u8; NF_CT_LABELS_MAX_SIZE];
    c.labels_copy(&mut got);
    assert_eq!(got[0], 0x85);
    let wire = ctnetlink::encode_entry(&c, 0, false);
    assert!(wire.windows(NF_CT_LABELS_MAX_SIZE).any(|window| window == &got));
}

#[test]
fn ctnetlink_synproxy_state_is_canonical_and_nested_on_dump() {
    let ct = CtNet::new(0, 7);
    let c = entry(v4_tcp([192, 0, 2, 1], 40000, [198, 51, 100, 2], 443));
    ct.table.add_pending(c.clone());
    assert!(ct.confirm(&c, 0));
    let state = SynproxyState { isn: 0x1122_3344, its: 0x5566_7788, tsoff: -12 };
    assert!(ct.update_id(c.id, 0, None, None, None, [None, None], None, None, None,
        Some(state)));
    assert_eq!(*c.synproxy.lock(), Some(state));
    let wire = ctnetlink::encode_entry(&c, 0, false);
    let raw = wire.windows(4).position(|window| {
        window[2..4] == (CTA_SYNPROXY | ctnetlink::NLA_F_NESTED).to_ne_bytes()
    });
    assert!(raw.is_some());
    assert!(wire.windows(4).any(|window| window == 0x1122_3344u32.to_be_bytes()));
}

#[test]
fn ctnetlink_sctp_protoinfo_is_canonical_and_nested_on_dump() {
    let ct = CtNet::new(0, 7);
    let mut tuple = v4_udp([192, 0, 2, 1], 40000, [198, 51, 100, 2], 3868);
    tuple.protonum = IPPROTO_SCTP;
    let c = entry(tuple);
    ct.table.add_pending(c.clone());
    assert!(ct.confirm(&c, 0));
    let update = SctpProtoInfoUpdate { state: 4, vtag: [0x1122_3344, 0x5566_7788] };
    assert!(ct.update_id(c.id, 0, None, None, None, [None, None], None,
        Some(update), None, None));
    let ProtoState::Sctp(track) = *c.proto.lock() else { panic!("SCTP flow lost its tracker"); };
    assert_eq!(track.state, 4);
    assert_eq!(track.vtag, update.vtag);
    let wire = ctnetlink::encode_entry(&c, 0, false);
    assert!(wire.windows(4).any(|window| window == 0x1122_3344u32.to_be_bytes()));
    assert!(wire.windows(4).any(|window| window == 0x5566_7788u32.to_be_bytes()));
}

#[test]
fn ctnetlink_creator_confirms_a_tuple_with_timeout_status_and_mark() {
    let ct = CtNet::new(0, 7);
    let tuple = v4_udp([192, 0, 2, 1], 40000, [198, 51, 100, 2], 53);
    let id = ct.create_tuple(tuple, None, 0, 30, IPS_ASSURED, Some(0x44), None, None)
        .expect("userspace tuple is publishable");
    let found = ct.table.find_id(id, 0).expect("created flow is live");
    assert_eq!(found.orig, tuple);
    assert_eq!(found.expires_in(0), 30);
    assert_eq!(found.mark.load(core::sync::atomic::Ordering::Relaxed), 0x44);
    assert_ne!(found.status() & IPS_CONFIRMED, 0);
}

#[test]
fn ctnetlink_creator_attaches_only_a_registered_tuple_helper() {
    let ct = CtNet::new(0, 7);
    ct.helpers.register(Helper {
        name: String::from("dns"), l3num: NFPROTO_IPV4, protonum: IPPROTO_UDP,
        port: 53, policies: Vec::new(),
    }).unwrap();
    let tuple = v4_udp([192, 0, 2, 1], 40000, [198, 51, 100, 2], 53);
    let id = ct.create_tuple(tuple, None, 0, 30, 0, None, None,
                             Some(String::from("dns"))).expect("registered helper");
    let found = ct.table.find_id(id, 0).expect("created flow is live");
    assert_eq!(found.helper.lock().as_deref(), Some("dns"));
    assert_ne!(found.status() & IPS_HELPER, 0);
    assert!(ct.create_tuple(v4_udp([192, 0, 2, 2], 40001, [198, 51, 100, 2], 53),
                            None, 0, 30, 0, None, None,
                            Some(String::from("ftp"))).is_none());
}

#[test]
fn ctnetlink_existing_helper_change_matches_linux_noop_and_busy_results() {
    let ct = CtNet::new(0, 7);
    let tuple = v4_udp([192, 0, 2, 3], 40002, [198, 51, 100, 2], 53);
    let c = entry(tuple);
    ct.table.add_pending(c.clone());
    assert!(ct.confirm(&c, 0));
    assert_eq!(ct.update_helper_id(c.id, 0, String::from("dns")),
               Err(crate::core::HelperChangeError::Unsupported));

    let with_helper = ct.create_tuple(tuple, None, 0, 30, 0, None, None,
                                      None);
    assert!(with_helper.is_none(), "the test tuple is already occupied");
    let other = v4_udp([192, 0, 2, 4], 40003, [198, 51, 100, 2], 53);
    let c = Arc::new({
        let c = Conn::new(99, other, other.invert().unwrap(), 0);
        c.refresh(0, 100);
        c.attach_helper(String::from("dns"), true);
        c
    });
    ct.table.add_pending(c.clone());
    assert!(ct.confirm(&c, 0));
    assert_eq!(ct.update_helper_id(c.id, 0, String::from("dns")), Ok(()));
    assert_eq!(ct.update_helper_id(c.id, 0, String::from("ftp")),
               Err(crate::core::HelperChangeError::Busy));
}
