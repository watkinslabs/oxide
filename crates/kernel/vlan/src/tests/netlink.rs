extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use net::addr::{MacAddr, NetIfaceId};
use net::netdev::NetDev;
use syscall::errno::Errno;

use super::support::{
    attr, attr_be16, attr_flags, attr_mapping, attr_u16, blob, nest, plain_caps, FakeDev, REAL_MAC,
};
use crate::caps::RealDevCaps;
use crate::dev::VlanDev;
use crate::flags::{VLAN_FLAG_GVRP, VLAN_FLAG_MVRP, VLAN_FLAG_REORDER_HDR};
use crate::netlink::*;
use crate::registry::VlanTable;
use crate::tci::qos_mask;
use crate::uapi::{
    ETH_P_8021AD, ETH_P_8021Q, IFLA_VLAN_EGRESS_QOS, IFLA_VLAN_FLAGS, IFLA_VLAN_ID,
    IFLA_VLAN_INGRESS_QOS, IFLA_VLAN_PROTOCOL, IFLA_VLAN_QOS_MAPPING,
};

/// Keep the attribute blob alive for as long as the view into it.
macro_rules! parsed {
    ($raw:expr, $name:ident) => {
        let raw = $raw;
        let $name = parse(&raw).unwrap();
    };
}

const REAL_IFINDEX: u32 = 3;
const REAL_ID: NetIfaceId = NetIfaceId(3);
const GOOD_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];

fn resolver(caps: RealDevCaps) -> impl FnOnce(u32) -> Option<(NetIfaceId, RealDevCaps)> {
    move |ifindex| (ifindex == REAL_IFINDEX).then_some((REAL_ID, caps))
}

fn id_blob(id: u16) -> Vec<u8> { attr_u16(IFLA_VLAN_ID, id) }

fn link_with(ifindex: Option<u32>) -> LinkAttrs<'static> {
    LinkAttrs { address: None, mtu: None, link: ifindex }
}

// -- parse ---------------------------------------------------------------

#[test]
fn a_full_blob_reads_back() {
    let raw = blob(&[
        id_blob(42),
        attr_be16(IFLA_VLAN_PROTOCOL, ETH_P_8021AD),
        attr_flags(IFLA_VLAN_FLAGS, VLAN_FLAG_GVRP, VLAN_FLAG_GVRP),
        nest(IFLA_VLAN_INGRESS_QOS, &[attr_mapping(3, 77)]),
        nest(IFLA_VLAN_EGRESS_QOS, &[attr_mapping(9, 5)]),
    ]);
    parsed!(raw, a);
    assert_eq!(a.id, Some(42));
    assert_eq!(a.protocol, Some(ETH_P_8021AD));
    assert_eq!(a.flags, Some(FlagsRequest { flags: VLAN_FLAG_GVRP, mask: VLAN_FLAG_GVRP }));
    assert_eq!(qos_mappings(a.ingress_qos.unwrap()).unwrap(),
               alloc::vec![QosMapping { from: 3, to: 77 }]);
    assert_eq!(qos_mappings(a.egress_qos.unwrap()).unwrap(),
               alloc::vec![QosMapping { from: 9, to: 5 }]);
}

#[test]
fn an_empty_blob_carries_nothing() {
    assert_eq!(parse(&[]).unwrap(), VlanAttrs::default());
}

#[test]
fn a_truncated_identifier_is_out_of_range() {
    assert_eq!(parse(&attr(IFLA_VLAN_ID, &[7])).unwrap_err(), Errno::Erange);
}

#[test]
fn a_truncated_flags_structure_is_out_of_range() {
    assert_eq!(parse(&attr(IFLA_VLAN_FLAGS, &[0; 7])).unwrap_err(), Errno::Erange);
}

#[test]
fn a_container_too_small_for_an_attribute_is_out_of_range() {
    assert_eq!(parse(&attr(IFLA_VLAN_INGRESS_QOS, &[0; 3])).unwrap_err(), Errno::Erange);
    assert!(parse(&attr(IFLA_VLAN_INGRESS_QOS, &[])).is_ok(), "an empty map is allowed");
}

#[test]
fn a_header_claiming_more_than_the_blob_holds_is_malformed() {
    let mut raw = attr_u16(IFLA_VLAN_ID, 5);
    raw[0] = 64; // length beyond the end
    assert_eq!(parse(&raw).unwrap_err(), Errno::Einval);
    assert_eq!(parse(&[2, 0, 1, 0]).unwrap_err(), Errno::Einval, "length below the header");
}

#[test]
fn unknown_attributes_are_ignored() {
    let raw = blob(&[attr_u16(999, 1), id_blob(8)]);
    assert_eq!(parse(&raw).unwrap().id, Some(8));
}

#[test]
fn a_short_translation_is_out_of_range() {
    let raw = nest(IFLA_VLAN_EGRESS_QOS, &[attr(IFLA_VLAN_QOS_MAPPING, &[0; 7])]);
    parsed!(raw, a);
    assert_eq!(qos_mappings(a.egress_qos.unwrap()).unwrap_err(), Errno::Erange);
}

// -- validate ------------------------------------------------------------

#[test]
fn a_request_with_no_kind_attributes_is_invalid() {
    assert_eq!(validate(&link_with(None), None).unwrap_err(), Errno::Einval);
}

#[test]
fn an_address_of_the_wrong_width_is_invalid() {
    let link = LinkAttrs { address: Some(&[0x02, 0, 0, 0, 0]), mtu: None, link: None };
    assert_eq!(validate(&link, None).unwrap_err(), Errno::Einval);
}

#[test]
fn an_address_no_station_can_have_is_unavailable() {
    let multicast = [0x01, 0, 0, 0, 0, 1];
    let link = LinkAttrs { address: Some(&multicast), mtu: None, link: None };
    assert_eq!(validate(&link, None).unwrap_err(), Errno::Eaddrnotavail);
    let zero = [0u8; 6];
    let link = LinkAttrs { address: Some(&zero), mtu: None, link: None };
    assert_eq!(validate(&link, None).unwrap_err(), Errno::Eaddrnotavail);
}

#[test]
fn a_usable_address_passes_to_the_next_check() {
    let link = LinkAttrs { address: Some(&GOOD_MAC), mtu: None, link: None };
    assert_eq!(validate(&link, None).unwrap_err(), Errno::Einval, "no kind attributes yet");
}

#[test]
fn a_protocol_that_is_not_a_tag_protocol_is_unsupported() {
    parsed!(attr_be16(IFLA_VLAN_PROTOCOL, 0x0800), a);
    assert_eq!(validate(&link_with(None), Some(&a)).unwrap_err(), Errno::Eprotonosupport);
    for proto in [ETH_P_8021Q, ETH_P_8021AD] {
        parsed!(attr_be16(IFLA_VLAN_PROTOCOL, proto), a);
        assert_eq!(validate(&link_with(None), Some(&a)), Ok(()));
    }
}

#[test]
fn the_reserved_identifier_and_above_are_out_of_range() {
    for id in [4095u16, 4096, 0xffff] {
        parsed!(id_blob(id), a);
        assert_eq!(validate(&link_with(None), Some(&a)).unwrap_err(), Errno::Erange,
                   "identifier {id}");
    }
    for id in [0u16, 1, 4094] {
        parsed!(id_blob(id), a);
        assert_eq!(validate(&link_with(None), Some(&a)), Ok(()), "identifier {id}");
    }
}

#[test]
fn a_flag_this_interface_does_not_have_is_invalid() {
    parsed!(attr_flags(IFLA_VLAN_FLAGS, 0x20, 0x20), a);
    assert_eq!(validate(&link_with(None), Some(&a)).unwrap_err(), Errno::Einval);
    // Selected but not set: the reference judges the intersection, so this
    // passes even though the bit is unknown.
    parsed!(attr_flags(IFLA_VLAN_FLAGS, 0, 0x20), a);
    assert_eq!(validate(&link_with(None), Some(&a)), Ok(()));
}

#[test]
fn a_malformed_map_is_caught_by_validation() {
    let raw = nest(IFLA_VLAN_INGRESS_QOS, &[attr(IFLA_VLAN_QOS_MAPPING, &[0; 4])]);
    parsed!(raw, a);
    assert_eq!(validate(&link_with(None), Some(&a)).unwrap_err(), Errno::Erange);
}

#[test]
fn the_protocol_is_judged_before_the_identifier() {
    let raw = blob(&[id_blob(4095), attr_be16(IFLA_VLAN_PROTOCOL, 0x0800)]);
    parsed!(raw, a);
    assert_eq!(validate(&link_with(None), Some(&a)).unwrap_err(), Errno::Eprotonosupport);
}

#[test]
fn the_address_is_judged_before_anything_in_the_kind_blob() {
    parsed!(id_blob(4095), a);
    let link = LinkAttrs { address: Some(&[0u8; 3]), mtu: None, link: None };
    assert_eq!(validate(&link, Some(&a)).unwrap_err(), Errno::Einval);
}

// -- newlink -------------------------------------------------------------

#[test]
fn a_creation_needs_an_identifier() {
    let table = VlanTable::new();
    let a = VlanAttrs::default();
    let e = newlink(&link_with(Some(REAL_IFINDEX)), &a, &table, resolver(plain_caps(1500)));
    assert_eq!(e.unwrap_err(), Errno::Einval);
}

#[test]
fn a_creation_needs_a_lower_interface() {
    let table = VlanTable::new();
    parsed!(id_blob(5), a);
    assert_eq!(newlink(&link_with(None), &a, &table, resolver(plain_caps(1500))).unwrap_err(),
               Errno::Einval);
}

#[test]
fn a_lower_interface_that_does_not_exist_is_reported_as_such() {
    let table = VlanTable::new();
    parsed!(id_blob(5), a);
    assert_eq!(newlink(&link_with(Some(99)), &a, &table, resolver(plain_caps(1500))).unwrap_err(),
               Errno::Enodev);
}

#[test]
fn a_lower_interface_that_cannot_carry_tags_is_unsupported() {
    let table = VlanTable::new();
    parsed!(id_blob(5), a);
    let mut caps = plain_caps(1500);
    caps.vlan_challenged = true;
    assert_eq!(newlink(&link_with(Some(REAL_IFINDEX)), &a, &table, resolver(caps)).unwrap_err(),
               Errno::Eopnotsupp);
}

#[test]
fn a_tag_another_interface_already_claims_exists() {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let table = VlanTable::new();
    let dev = Arc::new(VlanDev::new(String::from("eth0.5"), 5, ETH_P_8021Q, REAL_ID,
                                    real as Arc<dyn NetDev>, plain_caps(1500), MacAddr::ZERO));
    table.insert(NetIfaceId(10), dev).unwrap();
    parsed!(id_blob(5), a);
    assert_eq!(newlink(&link_with(Some(REAL_IFINDEX)), &a, &table,
                       resolver(plain_caps(1500))).unwrap_err(), Errno::Eexist);
    // Same identifier, other tag protocol: free.
    parsed!(blob(&[id_blob(5), attr_be16(IFLA_VLAN_PROTOCOL, ETH_P_8021AD)]), a);
    assert!(newlink(&link_with(Some(REAL_IFINDEX)), &a, &table,
                    resolver(plain_caps(1500))).is_ok());
}

#[test]
fn a_creation_defaults_to_the_customer_tag_protocol_and_the_full_ceiling() {
    let table = VlanTable::new();
    parsed!(id_blob(4094), a);
    let req = newlink(&link_with(Some(REAL_IFINDEX)), &a, &table,
                      resolver(plain_caps(1500))).unwrap();
    assert_eq!(req.proto, ETH_P_8021Q);
    assert_eq!(req.vlan_id, 4094);
    assert_eq!(req.real, REAL_ID);
    assert_eq!(req.mtu, 1500);
    assert_eq!(req.flags, VLAN_FLAG_REORDER_HDR);
    assert_eq!(req.mac, MacAddr::ZERO, "inherited later, from the lower interface");
}

#[test]
fn a_requested_frame_size_above_the_ceiling_is_invalid() {
    let table = VlanTable::new();
    parsed!(id_blob(5), a);
    let link = LinkAttrs { address: None, mtu: Some(1501), link: Some(REAL_IFINDEX) };
    assert_eq!(newlink(&link, &a, &table, resolver(plain_caps(1500))).unwrap_err(),
               Errno::Einval);
    let link = LinkAttrs { address: None, mtu: Some(1500), link: Some(REAL_IFINDEX) };
    assert_eq!(newlink(&link, &a, &table, resolver(plain_caps(1500))).unwrap().mtu, 1500);
}

#[test]
fn a_lower_interface_that_spends_the_tag_bytes_lowers_the_ceiling() {
    let table = VlanTable::new();
    parsed!(id_blob(5), a);
    let mut caps = plain_caps(1500);
    caps.reduces_vlan_mtu = true;
    let link = LinkAttrs { address: None, mtu: Some(1496), link: Some(REAL_IFINDEX) };
    assert_eq!(newlink(&link, &a, &table, resolver(caps)).unwrap().mtu, 1496);
    let link = LinkAttrs { address: None, mtu: Some(1497), link: Some(REAL_IFINDEX) };
    assert_eq!(newlink(&link, &a, &table, resolver(caps)).unwrap_err(), Errno::Einval);
    let link = LinkAttrs { address: None, mtu: None, link: Some(REAL_IFINDEX) };
    assert_eq!(newlink(&link, &a, &table, resolver(caps)).unwrap().mtu, 1496,
               "the default is the reduced ceiling");
}

#[test]
fn a_requested_address_reaches_the_creation() {
    let table = VlanTable::new();
    parsed!(id_blob(5), a);
    let link = LinkAttrs { address: Some(&GOOD_MAC), mtu: None, link: Some(REAL_IFINDEX) };
    let req = newlink(&link, &a, &table, resolver(plain_caps(1500))).unwrap();
    assert_eq!(req.mac, MacAddr(GOOD_MAC));
}

#[test]
fn the_maps_in_a_creation_survive_into_the_request() {
    let table = VlanTable::new();
    let raw = blob(&[
        id_blob(5),
        nest(IFLA_VLAN_INGRESS_QOS, &[attr_mapping(2, 22), attr_mapping(3, 33)]),
        nest(IFLA_VLAN_EGRESS_QOS, &[attr_mapping(4, 4)]),
    ]);
    parsed!(raw, a);
    let req = newlink(&link_with(Some(REAL_IFINDEX)), &a, &table,
                      resolver(plain_caps(1500))).unwrap();
    assert_eq!(req.ingress.len(), 2);
    assert_eq!(req.egress, alloc::vec![QosMapping { from: 4, to: 4 }]);
}

// -- changelink ----------------------------------------------------------

fn live_dev() -> (Arc<FakeDev>, Arc<VlanDev>) {
    let real = FakeDev::new("eth0", REAL_MAC, 1500);
    let dev = Arc::new(VlanDev::new(String::from("eth0.5"), 5, ETH_P_8021Q, REAL_ID,
                                    real.clone() as Arc<dyn NetDev>, plain_caps(1500),
                                    MacAddr::ZERO));
    (real, dev)
}

#[test]
fn a_flag_change_lands_on_the_interface() {
    let (_real, dev) = live_dev();
    parsed!(attr_flags(IFLA_VLAN_FLAGS, VLAN_FLAG_MVRP,
                              VLAN_FLAG_MVRP | VLAN_FLAG_REORDER_HDR), a);
    assert_eq!(changelink(&dev, &a), Ok(()));
    assert_eq!(dev.flags(), VLAN_FLAG_MVRP, "reordering selected and cleared");
}

#[test]
fn a_flag_change_selecting_an_unknown_bit_is_refused() {
    let (_real, dev) = live_dev();
    parsed!(attr_flags(IFLA_VLAN_FLAGS, 0, 0x40), a);
    assert_eq!(changelink(&dev, &a).unwrap_err(), Errno::Einval);
    assert_eq!(dev.flags(), VLAN_FLAG_REORDER_HDR, "nothing changed");
}

#[test]
fn the_two_maps_take_their_ends_in_opposite_orders() {
    let (_real, dev) = live_dev();
    // Ingress: from = code point 3, to = priority 77.
    // Egress:  from = priority 9,   to = code point 5.
    let raw = blob(&[
        nest(IFLA_VLAN_INGRESS_QOS, &[attr_mapping(3, 77)]),
        nest(IFLA_VLAN_EGRESS_QOS, &[attr_mapping(9, 5)]),
    ]);
    parsed!(raw, a);
    assert_eq!(changelink(&dev, &a), Ok(()));
    dev.with_maps(|m| {
        assert_eq!(m.ingress(3), 77);
        assert_eq!(m.ingress(77 & 7), 0, "the priority is not an index");
        assert_eq!(m.egress_mask(9), qos_mask(5));
        assert_eq!(m.egress_mask(5), 0, "the code point is not a priority");
    });
}

#[test]
fn a_change_with_nothing_in_it_changes_nothing() {
    let (_real, dev) = live_dev();
    assert_eq!(changelink(&dev, &VlanAttrs::default()), Ok(()));
    assert_eq!(dev.flags(), VLAN_FLAG_REORDER_HDR);
    dev.with_maps(|m| { assert_eq!(m.nr_ingress(), 0); assert_eq!(m.nr_egress(), 0); });
}
