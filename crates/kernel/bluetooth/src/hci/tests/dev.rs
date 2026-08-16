use super::*;
use crate::uapi::hci_sock::{HCI_INIT, HCI_RUNNING, HCI_UP};

fn with_feature(byte: usize, bit: u8) -> LocalInfo {
    let mut i = LocalInfo::default();
    i.features[byte] |= 1 << bit;
    i
}

// BR/EDR is the one capability stated NEGATIVELY: a controller reporting
// nothing at all is a classic-only controller. Reading it as a positive bit
// inverts the whole BR/EDR half of the setup sequence.
#[test]
fn bredr_capability_is_the_absence_of_the_no_bredr_bit() {
    assert!(LocalInfo::default().bredr_capable());
    assert!(!with_feature(LMP_NO_BREDR_BYTE, LMP_NO_BREDR_BIT).bredr_capable());
}

#[test]
fn each_capability_reads_its_own_bit() {
    assert!(with_feature(LMP_LE_BYTE, LMP_LE_BIT).le_capable());
    assert!(!LocalInfo::default().le_capable());
    assert!(with_feature(LMP_ESCO_BYTE, LMP_ESCO_BIT).esco_capable());
    assert!(with_feature(LMP_SSP_BYTE, LMP_SSP_BIT).ssp_capable());
    assert!(with_feature(LMP_RSSI_INQ_BYTE, LMP_RSSI_INQ_BIT).rssi_inquiry_capable());
    assert!(with_feature(LMP_ESCO_2M_BYTE, LMP_ESCO_2M_BIT).esco_2m_capable());
}

// The capability bits must not collide: setting one must not read as another.
#[test]
fn no_two_capability_bits_share_a_position() {
    let probes: [(usize, u8, fn(&LocalInfo) -> bool); 4] = [
        (LMP_LE_BYTE, LMP_LE_BIT, |i| i.le_capable()),
        (LMP_ESCO_BYTE, LMP_ESCO_BIT, |i| i.esco_capable()),
        (LMP_SSP_BYTE, LMP_SSP_BIT, |i| i.ssp_capable()),
        (LMP_ESCO_2M_BYTE, LMP_ESCO_2M_BIT, |i| i.esco_2m_capable()),
    ];
    for (bi, (byte, bit, _)) in probes.iter().enumerate() {
        let info = with_feature(*byte, *bit);
        for (pi, (_, _, probe)) in probes.iter().enumerate() {
            assert_eq!(probe(&info), bi == pi, "bit {bi} read by probe {pi}");
        }
    }
}

// A controller may report a shorter feature page than the host asks about; a
// missing byte reads as clear rather than panicking.
#[test]
fn a_feature_byte_past_the_mask_reads_as_clear() {
    assert!(!feature_set(&[0xff, 0xff], 99, 0));
    assert!(feature_set(&[0xff], 0, 7));
}

#[test]
fn a_command_bit_past_the_bitmap_reads_as_clear() {
    let mut i = LocalInfo::default();
    i.commands[7] = 0x01;
    assert!(i.command_supported(7, 0));
    assert!(!i.command_supported(7, 1));
    assert!(!i.command_supported(999, 0));
}

// A controller identifies itself to every tool by this name, so the index is
// rendered without padding or a separator.
#[test]
fn a_controller_name_is_the_prefix_and_its_index() {
    assert_eq!(HciDevState::new(0, 0).name().as_str(), "hci0");
    assert_eq!(HciDevState::new(1, 0).name().as_str(), "hci1");
    assert_eq!(HciDevState::new(10, 0).name().as_str(), "hci10");
    assert_eq!(HciDevState::new(4095, 0).name().as_str(), "hci4095");
}

// Allocating the lowest free slot rather than the next unused number keeps a
// controller's name stable across a reset.
#[test]
fn index_allocation_reuses_the_lowest_free_slot() {
    assert_eq!(lowest_free_index(&[]), Some(0));
    assert_eq!(lowest_free_index(&[0, 1, 2]), Some(3));
    assert_eq!(lowest_free_index(&[0, 2, 3]), Some(1));
    assert_eq!(lowest_free_index(&[1, 2, 3]), Some(0));
}

#[test]
fn state_flags_set_and_clear_independently() {
    let mut d = HciDevState::new(0, 0);
    assert!(!d.is_up() && !d.is_running() && !d.is_initialising());
    d.set_flag(HCI_UP, true);
    assert!(d.is_up() && !d.is_running());
    d.set_flag(HCI_RUNNING, true);
    d.set_flag(HCI_UP, false);
    assert!(!d.is_up() && d.is_running());
    d.set_flag(HCI_INIT, true);
    assert!(d.is_initialising());
}

// A controller going down has forgotten its links and every queued command
// names a state it no longer holds.
#[test]
fn tearing_down_drops_the_links_the_commands_and_the_up_flags() {
    let mut d = HciDevState::new(0, 0);
    d.set_flag(HCI_UP, true);
    d.set_flag(HCI_RUNNING, true);
    d.set_flag(HCI_INIT, true);
    d.conns.insert(crate::hci::conn::Conn::new(1,
        crate::hci::conn::PeerId::new(crate::uapi::bt::BdAddr([1; 6]), 0),
        crate::uapi::hci::ACL_LINK, true));
    d.cmd.enqueue(crate::uapi::hci_cmd::HCI_OP_RESET, alloc::vec::Vec::new());
    d.tear_down();
    assert!(d.conns.is_empty());
    assert_eq!(d.cmd.pending(), 0);
    assert!(!d.is_up() && !d.is_running() && !d.is_initialising());
}

// A name is not terminated, so a reader bounds by the length — and an
// over-length name is cut to the field rather than overflowing it.
#[test]
fn a_local_name_is_bounded_by_the_field_width() {
    let mut d = HciDevState::new(0, 0);
    d.set_local_name(&[b'x'; 300]);
    assert_eq!(d.local_name.len(), crate::uapi::hci::HCI_MAX_NAME_LENGTH);
    d.set_local_name(b"oxide");
    assert_eq!(d.local_name.as_slice(), b"oxide");
}
