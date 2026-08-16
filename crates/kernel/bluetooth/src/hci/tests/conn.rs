use super::*;
use crate::uapi::bt::{BdAddr, BDADDR_LE_RANDOM, BT_CLOSED, BT_CONNECT, BT_CONNECTED};

fn addr(last: u8) -> BdAddr { BdAddr([1, 2, 3, 4, 5, last]) }

#[test]
fn a_new_link_starts_in_the_connecting_state() {
    let c = Conn::new(0x2a, PeerId::new(addr(6), BDADDR_BREDR), ACL_LINK, true);
    assert_eq!(c.state, BT_CONNECT);
    assert!(!c.is_connected());
    assert!(c.out);
}

// A BR/EDR address and an LE address with the same six bytes are DIFFERENT
// peers. Collapsing them is how a stack hands an LE key to a BR/EDR link.
#[test]
fn the_same_bytes_on_two_address_types_are_two_peers() {
    let bredr = PeerId::new(addr(6), BDADDR_BREDR);
    let le = PeerId::new(addr(6), BDADDR_LE_RANDOM);
    assert_ne!(bredr, le);
    let mut list = ConnList::new();
    list.insert(Conn::new(1, bredr, ACL_LINK, true));
    assert!(list.by_peer(le, ACL_LINK).is_none());
    assert!(list.by_peer(bredr, ACL_LINK).is_some());
}

// One peer can hold a data link and a voice link at once, so the link type is
// part of the lookup key.
#[test]
fn one_peer_can_hold_a_data_link_and_a_voice_link_at_once() {
    let peer = PeerId::new(addr(6), BDADDR_BREDR);
    let mut list = ConnList::new();
    list.insert(Conn::new(1, peer, ACL_LINK, true));
    list.insert(Conn::new(2, peer, SCO_LINK, true));
    assert_eq!(list.by_peer(peer, ACL_LINK).unwrap().handle, 1);
    assert_eq!(list.by_peer(peer, SCO_LINK).unwrap().handle, 2);
    assert_eq!(list.len(), 2);
}

// A controller reusing a handle has torn the old link down whether or not the
// host saw the disconnection, so the entry is replaced rather than duplicated.
#[test]
fn a_reused_handle_replaces_rather_than_duplicates() {
    let mut list = ConnList::new();
    list.insert(Conn::new(7, PeerId::new(addr(1), BDADDR_BREDR), ACL_LINK, true));
    list.insert(Conn::new(7, PeerId::new(addr(2), BDADDR_BREDR), ACL_LINK, false));
    assert_eq!(list.len(), 1);
    assert_eq!(list.by_handle(7).unwrap().peer.addr, addr(2));
}

#[test]
fn removing_a_link_returns_it_and_leaves_the_others() {
    let mut list = ConnList::new();
    list.insert(Conn::new(1, PeerId::new(addr(1), BDADDR_BREDR), ACL_LINK, true));
    list.insert(Conn::new(2, PeerId::new(addr(2), BDADDR_BREDR), ACL_LINK, true));
    assert_eq!(list.remove(1).unwrap().handle, 1);
    assert!(list.by_handle(1).is_none());
    assert_eq!(list.len(), 1);
    assert!(list.remove(99).is_none());
}

// Closing a link must drop the encryption state with it: a stale "encrypted"
// on a closed handle would let a later user believe a link is protected.
#[test]
fn closing_a_link_clears_its_encryption_state() {
    let mut list = ConnList::new();
    let mut c = Conn::new(3, PeerId::new(addr(1), BDADDR_BREDR), ACL_LINK, true);
    c.encrypted = true;
    c.enc_key_size = 16;
    list.insert(c);
    assert!(list.set_closed(3));
    let c = list.by_handle(3).unwrap();
    assert_eq!(c.state, BT_CLOSED);
    assert!(!c.encrypted);
    assert_eq!(c.enc_key_size, 0);
}

#[test]
fn marking_a_missing_handle_reports_failure_rather_than_creating_one() {
    let mut list = ConnList::new();
    assert!(!list.set_connected(9));
    assert!(!list.set_closed(9));
    assert!(list.is_empty());
}

#[test]
fn connecting_a_link_moves_it_to_the_established_state() {
    let mut list = ConnList::new();
    list.insert(Conn::new(4, PeerId::new(addr(1), BDADDR_BREDR), LE_LINK, true));
    assert!(list.set_connected(4));
    let c = list.by_handle(4).unwrap();
    assert_eq!(c.state, BT_CONNECTED);
    assert!(c.is_connected());
    assert!(c.is_le());
}

#[test]
fn link_type_classification_matches_the_baseband_taxonomy() {
    let peer = PeerId::new(addr(1), BDADDR_BREDR);
    assert!(Conn::new(1, peer, LE_LINK, true).is_le());
    assert!(!Conn::new(1, peer, ACL_LINK, true).is_le());
    assert!(Conn::new(1, peer, SCO_LINK, true).is_sco());
    assert!(Conn::new(1, peer, ESCO_LINK, true).is_sco());
    assert!(!Conn::new(1, peer, ACL_LINK, true).is_sco());
    assert!(carries_l2cap(ACL_LINK));
    assert!(carries_l2cap(LE_LINK));
    assert!(!carries_l2cap(SCO_LINK));
    assert!(!carries_l2cap(ESCO_LINK));
}

#[test]
fn a_link_type_selects_the_address_type_it_defaults_to() {
    assert_eq!(default_addr_type(LE_LINK), crate::uapi::bt::BDADDR_LE_PUBLIC);
    assert_eq!(default_addr_type(ACL_LINK), BDADDR_BREDR);
    assert_eq!(default_addr_type(SCO_LINK), BDADDR_BREDR);
}

#[test]
fn clearing_drops_every_link() {
    let mut list = ConnList::new();
    for h in 0..5 { list.insert(Conn::new(h, PeerId::new(addr(h as u8), BDADDR_BREDR), ACL_LINK, true)); }
    assert_eq!(list.iter().count(), 5);
    list.clear();
    assert!(list.is_empty());
}
