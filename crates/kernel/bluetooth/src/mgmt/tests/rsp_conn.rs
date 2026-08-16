//! Per-peer answers and the small replies.

use super::*;
use crate::uapi::bt::{BdAddr, BDADDR_BREDR, BDADDR_LE_PUBLIC};

fn a(n: u8, t: u8) -> AddrInfo { AddrInfo::new(BdAddr([n; 6]), t) }

#[test]
fn the_connection_list_round_trips() {
    let v = GetConnections {
        conns: alloc::vec![a(1, BDADDR_BREDR), a(2, BDADDR_LE_PUBLIC)],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 2 + 14);
    assert_eq!(&buf[..2], &2u16.to_le_bytes());
    assert_eq!(GetConnections::decode(&buf), Some(v));
}

#[test]
fn an_empty_connection_list_is_two_bytes() {
    let v = GetConnections::default();
    assert_eq!(v.encode(), alloc::vec![0, 0]);
    assert_eq!(GetConnections::decode(&[0, 0]), Some(v));
}

#[test]
fn a_connection_count_that_disagrees_is_refused() {
    let v = GetConnections { conns: alloc::vec![a(1, BDADDR_BREDR)] };
    let mut buf = v.encode();
    buf[0] = 2;
    assert_eq!(GetConnections::decode(&buf), None);
    buf[0] = 0;
    assert_eq!(GetConnections::decode(&buf), None);
}

#[test]
fn the_link_info_response_carries_three_signed_bytes() {
    let v = GetConnInfo {
        addr: a(3, BDADDR_LE_PUBLIC), rssi: -55, tx_power: 0, max_tx_power: 10,
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 10);
    assert_eq!(buf[7], 0xc9);
    assert_eq!(GetConnInfo::decode(&buf), Some(v));
    assert_eq!(GetConnInfo::decode(&buf[..9]), None);
    assert_eq!(GetConnInfo::decode(&alloc::vec![0u8; 11]), None);
}

#[test]
fn the_clock_response_round_trips() {
    let v = GetClockInfo {
        addr: a(4, BDADDR_BREDR), local_clock: 0x1234_5678,
        piconet_clock: 0x9abc_def0, accuracy: 500,
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 17);
    assert_eq!(GetClockInfo::decode(&buf), Some(v));
    assert_eq!(GetClockInfo::decode(&buf[..16]), None);
}

#[test]
fn the_device_flags_response_reports_both_words() {
    let v = DeviceFlags {
        addr: a(5, BDADDR_LE_PUBLIC), supported_flags: 0xf, current_flags: 1,
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 15);
    assert_eq!(&buf[7..11], &0xfu32.to_le_bytes());
    assert_eq!(&buf[11..15], &1u32.to_le_bytes());
    assert_eq!(DeviceFlags::decode(&buf), Some(v));
    assert_eq!(DeviceFlags::decode(&alloc::vec![0u8; 16]), None);
}

#[test]
fn the_small_replies_round_trip() {
    assert_eq!(InstanceRsp::decode(&[2]), Some(InstanceRsp { instance: 2 }));
    assert_eq!(InstanceRsp::decode(&[2, 0]), None);
    let h = MonitorHandle { monitor_handle: 0x0201 };
    assert_eq!(h.encode(), alloc::vec![0x01, 0x02]);
    assert_eq!(MonitorHandle::decode(&h.encode()), Some(h));
    assert_eq!(MonitorHandle::decode(&[1]), None);
}

#[test]
fn the_advertising_size_response_round_trips() {
    let v = AdvSizeInfo {
        instance: 1, flags: 0x41, max_adv_data_len: 25, max_scan_rsp_len: 31,
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 7);
    assert_eq!(AdvSizeInfo::decode(&buf), Some(v));
    assert_eq!(AdvSizeInfo::decode(&buf[..6]), None);
}

#[test]
fn the_extended_parameters_response_round_trips() {
    let v = ExtAdvParamsRsp {
        instance: 1, tx_power: -20, max_adv_data_len: 31, max_scan_rsp_len: 31,
    };
    let buf = v.encode();
    assert_eq!(buf, alloc::vec![1, 0xec, 31, 31]);
    assert_eq!(ExtAdvParamsRsp::decode(&buf), Some(v));
    assert_eq!(ExtAdvParamsRsp::decode(&buf[..3]), None);
}

#[test]
fn the_experimental_feature_state_round_trips() {
    let v = ExpFeatureState { uuid: [7u8; 16], flags: 3 };
    let buf = v.encode();
    assert_eq!(buf.len(), 20);
    assert_eq!(ExpFeatureState::decode(&buf), Some(v));
    assert_eq!(ExpFeatureState::decode(&buf[..19]), None);
    assert_eq!(ExpFeatureState::decode(&alloc::vec![0u8; 21]), None);
}
