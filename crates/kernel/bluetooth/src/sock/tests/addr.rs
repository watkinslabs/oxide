use super::*;
use crate::uapi::bt::{BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM};

fn a() -> BdAddr { BdAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]) }

#[test]
fn each_address_form_round_trips() {
    let hci = SockAddrHci { dev: 3, channel: 2 };
    assert_eq!(hci_from_wire(&hci_to_wire(hci)), Some(hci));
    let l2 = SockAddrL2 { psm: 0x1001, bdaddr: a(), cid: 0x0040, bdaddr_type: BDADDR_LE_PUBLIC };
    assert_eq!(l2_from_wire(&l2_to_wire(l2)), Some(l2));
    let sco = SockAddrSco { bdaddr: a() };
    assert_eq!(sco_from_wire(&sco_to_wire(sco)), Some(sco));
    let rc = SockAddrRc { bdaddr: a(), channel: 22 };
    assert_eq!(rc_from_wire(&rc_to_wire(rc)), Some(rc));
}

#[test]
fn each_form_has_its_exact_abi_width() {
    assert_eq!(hci_to_wire(SockAddrHci::default()).len(), 6);
    assert_eq!(l2_to_wire(SockAddrL2::default()).len(), 13);
    assert_eq!(sco_to_wire(SockAddrSco::default()).len(), 8);
    assert_eq!(rc_to_wire(SockAddrRc::default()).len(), 9);
}

// A partially decoded address carries a peer identity the caller never
// supplied, and binding or connecting to it reaches the wrong device.
#[test]
fn a_buffer_one_byte_short_is_refused_rather_than_read_short() {
    let cases: [(&dyn Fn(&[u8]) -> bool, usize); 4] = [
        (&|b| hci_from_wire(b).is_some(), SOCKADDR_HCI_LEN),
        (&|b| l2_from_wire(b).is_some(), SOCKADDR_L2_LEN),
        (&|b| sco_from_wire(b).is_some(), SOCKADDR_SCO_LEN),
        (&|b| rc_from_wire(b).is_some(), SOCKADDR_RC_LEN),
    ];
    for (decode, len) in cases {
        let mut buf = alloc::vec![0u8; len];
        buf[0..2].copy_from_slice(&(AF_BLUETOOTH as u16).to_ne_bytes());
        assert!(decode(&buf), "full width should decode at {len}");
        assert!(!decode(&buf[..len - 1]), "short width should not decode at {len}");
    }
}

// An address whose family is not this one belongs to another family; decoding
// it here would bind a Bluetooth socket to bytes meant for a different stack.
#[test]
fn an_address_of_another_family_is_refused() {
    let mut buf = hci_to_wire(SockAddrHci { dev: 0, channel: 0 });
    buf[0..2].copy_from_slice(&2u16.to_ne_bytes());
    assert!(hci_from_wire(&buf).is_none());
    let mut buf = rc_to_wire(SockAddrRc { bdaddr: a(), channel: 1 });
    buf[0] = 0;
    assert!(rc_from_wire(&buf).is_none());
}

// A longer buffer is accepted: the socket layer pads addresses out to the
// family's widest form, so refusing the padding would refuse every real call.
#[test]
fn a_buffer_longer_than_the_form_decodes_the_form() {
    let mut buf = alloc::vec::Vec::from(rc_to_wire(SockAddrRc { bdaddr: a(), channel: 7 }));
    buf.extend_from_slice(&[0xff; 20]);
    assert_eq!(rc_from_wire(&buf), Some(SockAddrRc { bdaddr: a(), channel: 7 }));
}

// The two 16-bit channel fields sit either side of the address; swapping them
// would connect a socket to the wrong channel on the right device.
#[test]
fn the_channel_fields_sit_either_side_of_the_address() {
    let w = l2_to_wire(SockAddrL2 { psm: 0x0003, bdaddr: a(), cid: 0x0040,
        bdaddr_type: BDADDR_LE_RANDOM });
    assert_eq!(&w[2..4], &[0x03, 0x00]);
    assert_eq!(&w[4..10], a().as_bytes());
    assert_eq!(&w[10..12], &[0x40, 0x00]);
    assert_eq!(w[12], BDADDR_LE_RANDOM);
}

// An address type outside the three real ones is not a peer this host can
// reach, and admitting it would key a connection under an identity no key
// store can ever match.
#[test]
fn only_the_three_real_address_types_are_valid() {
    for t in [BDADDR_BREDR, BDADDR_LE_PUBLIC, BDADDR_LE_RANDOM] {
        assert!(addr_type_valid(t), "type {t}");
    }
    for t in [3u8, 4, 0x7f, 0xff] { assert!(!addr_type_valid(t), "type {t}"); }
}

#[test]
fn the_all_zero_address_is_recognised_as_the_wildcard() {
    assert!(SockAddrSco::default().bdaddr.is_any());
    assert!(!a().is_any());
}
