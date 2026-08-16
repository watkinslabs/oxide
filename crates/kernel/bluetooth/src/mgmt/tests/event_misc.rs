//! Controller-wide, advertising, monitor and mesh events.

use super::*;
use crate::uapi::bt::{BdAddr, BDADDR_LE_RANDOM};
use crate::uapi::mgmt::ev::{MGMT_WAKE_REASON_NON_BT_WAKE, MGMT_WAKE_REASON_REMOTE_WAKE};

fn a() -> AddrInfo { AddrInfo::new(BdAddr([1, 2, 3, 4, 5, 6]), BDADDR_LE_RANDOM) }

#[test]
fn the_one_byte_events_round_trip() {
    assert_eq!(ControllerError::decode(&[3]), Some(ControllerError { error_code: 3 }));
    assert_eq!(ControllerError::decode(&[3, 0]), None);
    assert_eq!(ControllerSuspend::decode(&[1]), Some(ControllerSuspend { suspend_state: 1 }));
    assert_eq!(MeshPacketCmplt::decode(&[2]), Some(MeshPacketCmplt { handle: 2 }));
    assert_eq!(MeshPacketCmplt::decode(&[]), None);
}

#[test]
fn the_class_of_device_event_is_three_bytes() {
    let v = ClassOfDevChanged { dev_class: [0x0c, 0x02, 0x18] };
    assert_eq!(v.encode(), alloc::vec![0x0c, 0x02, 0x18]);
    assert_eq!(ClassOfDevChanged::decode(&v.encode()), Some(v));
    assert_eq!(ClassOfDevChanged::decode(&[0, 0]), None);
    assert_eq!(ClassOfDevChanged::decode(&[0, 0, 0, 0]), None);
}

#[test]
fn the_name_change_event_uses_the_same_slots_as_the_setter() {
    let v = LocalNameChanged { name: b"oxide".to_vec(), short_name: b"ox".to_vec() };
    let buf = v.encode();
    assert_eq!(buf.len(), 260);
    assert_eq!(&buf[249..251], b"ox");
    assert_eq!(LocalNameChanged::decode(&buf), Some(v));
    assert_eq!(LocalNameChanged::decode(&alloc::vec![0u8; 259]), None);
}

#[test]
fn the_extended_info_event_round_trips() {
    let v = ExtInfoChanged { eir: alloc::vec![2, 0x01, 0x06] };
    let buf = v.encode();
    assert_eq!(buf, alloc::vec![3, 0, 2, 0x01, 0x06]);
    assert_eq!(ExtInfoChanged::decode(&buf), Some(v));
    assert_eq!(ExtInfoChanged::decode(&[4, 0, 2, 0x01, 0x06]), None);
}

#[test]
fn the_phy_change_event_is_one_word() {
    let v = PhyConfigurationChanged { selected_phys: 0x201 };
    assert_eq!(v.encode(), alloc::vec![0x01, 0x02, 0, 0]);
    assert_eq!(PhyConfigurationChanged::decode(&v.encode()), Some(v));
    assert_eq!(PhyConfigurationChanged::decode(&[0, 0, 0]), None);
}

/// A wake that was not Bluetooth's doing still carries an address field, and it
/// is all-zero rather than absent — the record is fixed width either way.
#[test]
fn the_resume_event_is_fixed_width_whatever_woke_the_host() {
    let peer = ControllerResume { wake_reason: MGMT_WAKE_REASON_REMOTE_WAKE, addr: a() };
    assert_eq!(peer.encode().len(), 8);
    assert_eq!(ControllerResume::decode(&peer.encode()), Some(peer));
    let other = ControllerResume {
        wake_reason: MGMT_WAKE_REASON_NON_BT_WAKE, addr: AddrInfo::default(),
    };
    assert_eq!(other.encode().len(), 8);
    assert_eq!(ControllerResume::decode(&other.encode()), Some(other));
    assert_eq!(ControllerResume::decode(&alloc::vec![0u8; 7]), None);
}

#[test]
fn a_monitor_report_names_the_monitor_that_matched() {
    let v = AdvMonitorDeviceFound {
        monitor_handle: 5, addr: a(), rssi: -60, flags: 0x20,
        eir: alloc::vec![2, 0x01, 0x06],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 2 + 7 + 1 + 4 + 2 + 3);
    assert_eq!(&buf[..2], &5u16.to_le_bytes());
    assert_eq!(AdvMonitorDeviceFound::decode(&buf), Some(v));
    let mut bad = buf.clone();
    bad[14] = 4;
    assert_eq!(AdvMonitorDeviceFound::decode(&bad), None);
}

#[test]
fn a_monitor_loss_is_a_handle_and_an_address() {
    let v = AdvMonitorDeviceLost { monitor_handle: 9, addr: a() };
    let buf = v.encode();
    assert_eq!(buf.len(), 9);
    assert_eq!(AdvMonitorDeviceLost::decode(&buf), Some(v));
    assert_eq!(AdvMonitorDeviceLost::decode(&buf[..8]), None);
}

#[test]
fn a_mesh_report_carries_the_instant_between_the_rssi_and_the_flags() {
    let v = MeshDeviceFound {
        addr: a(), rssi: -70, instant: 0x0102_0304_0506_0708, flags: 1,
        eir: alloc::vec![1, 0x2a],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 7 + 1 + 8 + 4 + 2 + 2);
    assert_eq!(&buf[8..16], &[8, 7, 6, 5, 4, 3, 2, 1]);
    assert_eq!(MeshDeviceFound::decode(&buf), Some(v));
    assert_eq!(MeshDeviceFound::decode(&buf[..buf.len() - 1]), None);
}
