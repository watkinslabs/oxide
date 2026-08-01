// Multicast delivery: who receives, who does not, and what "nobody" means.

extern crate alloc;

use super::harness::*;
use crate::genetlink::mcast::{self, GenlMcastError};
use crate::netlink_tests::test_namespace;

const PAYLOAD: &[u8] = &[0xA5; 32];

#[test]
fn only_sockets_subscribed_to_the_group_receive() {
    let fam = register_test_family("fan-sub", alloc::vec::Vec::new(), 2);
    let ns = test_namespace();
    let ns_id = ns.id().as_u64();
    let on_g0 = subscriber(&ns, fam.mcgrps[0].id);
    let on_g1 = subscriber(&ns, fam.mcgrps[1].id);
    let silent = genl_socket(&ns);

    assert_eq!(mcast::genlmsg_multicast_netns(&fam, ns_id, 0, PAYLOAD, 0), Ok(1));
    assert_eq!(recv(&on_g0).as_deref(), Some(PAYLOAD));
    assert!(recv(&on_g1).is_none());
    assert!(recv(&silent).is_none());

    assert_eq!(mcast::genlmsg_multicast_netns(&fam, ns_id, 1, PAYLOAD, 0), Ok(1));
    assert!(recv(&on_g0).is_none());
    assert!(recv(&on_g1).is_some());
}

#[test]
fn nobody_listening_is_esrch() {
    let fam = register_test_family("fan-esrch", alloc::vec::Vec::new(), 1);
    let ns = test_namespace();
    assert_eq!(mcast::genlmsg_multicast_netns(&fam, ns.id().as_u64(), 0, PAYLOAD, 0),
        Err(GenlMcastError::Esrch));
    assert_eq!(mcast::genlmsg_multicast_allns(&fam, 0, PAYLOAD, 0), Err(GenlMcastError::Esrch));
    // A socket that exists but never subscribed is still nobody.
    let _idle = genl_socket(&ns);
    assert_eq!(mcast::genlmsg_multicast_allns(&fam, 0, PAYLOAD, 0), Err(GenlMcastError::Esrch));
}

#[test]
fn a_group_index_outside_the_family_table_is_einval() {
    let fam = register_test_family("fan-range", alloc::vec::Vec::new(), 1);
    let ns = test_namespace();
    let _listener = subscriber(&ns, fam.mcgrps[0].id);
    assert_eq!(mcast::genlmsg_multicast_netns(&fam, ns.id().as_u64(), 1, PAYLOAD, 0),
        Err(GenlMcastError::Einval));
    assert_eq!(mcast::genlmsg_multicast_allns(&fam, 9, PAYLOAD, 0), Err(GenlMcastError::Einval));
}

#[test]
fn per_namespace_delivery_does_not_cross_into_another_namespace() {
    let fam = register_test_family("fan-ns", alloc::vec::Vec::new(), 1);
    let ns_a = test_namespace();
    let ns_b = test_namespace();
    let group = fam.mcgrps[0].id;
    let a = subscriber(&ns_a, group);
    let b = subscriber(&ns_b, group);

    assert_eq!(mcast::genlmsg_multicast_netns(&fam, ns_a.id().as_u64(), 0, PAYLOAD, 0), Ok(1));
    assert!(recv(&a).is_some());
    assert!(recv(&b).is_none());
}

#[test]
fn allns_delivery_reaches_every_namespace_at_once() {
    let fam = register_test_family("fan-allns", alloc::vec::Vec::new(), 1);
    let ns_a = test_namespace();
    let ns_b = test_namespace();
    let group = fam.mcgrps[0].id;
    let a = subscriber(&ns_a, group);
    let b = subscriber(&ns_b, group);

    assert_eq!(mcast::genlmsg_multicast_allns(&fam, 0, PAYLOAD, 0), Ok(2));
    assert!(recv(&a).is_some());
    assert!(recv(&b).is_some());
}

#[test]
fn the_excluded_port_does_not_receive_its_own_broadcast() {
    let fam = register_test_family("fan-excl", alloc::vec::Vec::new(), 1);
    let ns = test_namespace();
    let group = fam.mcgrps[0].id;
    let sender = subscriber(&ns, group);
    let other = subscriber(&ns, group);
    let sender_port = sender.port_id.load(core::sync::atomic::Ordering::Acquire);

    assert_eq!(mcast::genlmsg_multicast_netns(&fam, ns.id().as_u64(), 0, PAYLOAD, sender_port),
        Ok(1));
    assert!(recv(&sender).is_none());
    assert!(recv(&other).is_some());
}

#[test]
fn dropping_a_subscription_stops_delivery() {
    let fam = register_test_family("fan-drop", alloc::vec::Vec::new(), 1);
    let ns = test_namespace();
    let group = fam.mcgrps[0].id;
    let sock = subscriber(&ns, group);
    assert_eq!(mcast::genlmsg_multicast_netns(&fam, ns.id().as_u64(), 0, PAYLOAD, 0), Ok(1));
    assert!(recv(&sock).is_some());
    sock.drop_membership(group).unwrap();
    assert_eq!(mcast::genlmsg_multicast_netns(&fam, ns.id().as_u64(), 0, PAYLOAD, 0),
        Err(GenlMcastError::Esrch));
}

#[test]
fn a_closed_socket_drops_out_of_the_listener_set() {
    let fam = register_test_family("fan-closed", alloc::vec::Vec::new(), 1);
    let ns = test_namespace();
    let group = fam.mcgrps[0].id;
    let live = subscriber(&ns, group);
    { let _gone = subscriber(&ns, group); }
    assert_eq!(mcast::genlmsg_multicast_netns(&fam, ns.id().as_u64(), 0, PAYLOAD, 0), Ok(1));
    assert!(recv(&live).is_some());
}

#[test]
fn a_group_id_beyond_the_first_word_still_reaches_its_subscriber() {
    // Register enough families to push the group space past 32, then confirm a
    // subscription there both binds and delivers.
    let mut fam = register_test_family("fan-wide-0", alloc::vec::Vec::new(), 8);
    let mut round = 1;
    while fam.mcgrps.last().unwrap().id <= crate::groups::GROUP_BITS_PER_WORD {
        fam = register_test_family(
            alloc::string::String::leak(alloc::format!("fan-wide-{}", round)),
            alloc::vec::Vec::new(), 8);
        round += 1;
        assert!(round < 32, "group space must grow past one word");
    }
    let group = *fam.mcgrps.iter().map(|g| g.id)
        .find(|id| *id > crate::groups::GROUP_BITS_PER_WORD).as_ref().unwrap();
    let ns = test_namespace();
    let sock = subscriber(&ns, group);
    assert_eq!(sock.groups.low_mask(), 0);
    let index = fam.mcgrps.iter().position(|g| g.id == group).unwrap();
    assert_eq!(mcast::genlmsg_multicast_netns(&fam, ns.id().as_u64(), index, PAYLOAD, 0), Ok(1));
    assert!(recv(&sock).is_some());
}
