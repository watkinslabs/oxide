//! The variable-length commands: advertising, monitors, mesh, pass-through.

use super::*;
use crate::uapi::bt::{BdAddr, BDADDR_LE_RANDOM};

#[test]
fn add_advertising_lays_the_two_blocks_end_to_end() {
    let v = AddAdvertising {
        instance: 1, flags: 0x0000_0003, duration: 0, timeout: 0,
        adv_data: alloc::vec![2, 0x01, 0x06],
        scan_rsp: alloc::vec![3, 0x09, b'o', b'x'],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 11 + 3 + 4);
    assert_eq!(buf[9], 3, "adv length");
    assert_eq!(buf[10], 4, "scan response length");
    assert_eq!(AddAdvertising::decode(&buf), Some(v));
}

/// The two declared lengths must together account for exactly the tail.
#[test]
fn advertising_lengths_that_disagree_with_the_tail_are_refused() {
    let v = AddAdvertising {
        instance: 1, flags: 0, duration: 0, timeout: 0,
        adv_data: alloc::vec![1, 2, 3], scan_rsp: alloc::vec![],
    };
    let mut buf = v.encode();
    buf[9] = 4;
    assert_eq!(AddAdvertising::decode(&buf), None, "adv length overstates");
    buf[9] = 2;
    assert_eq!(AddAdvertising::decode(&buf), None, "adv length understates");
    buf[9] = 3;
    assert!(AddAdvertising::decode(&buf).is_some());
    // Splitting the same tail differently is legal and changes the meaning.
    buf[9] = 1;
    buf[10] = 2;
    let split = AddAdvertising::decode(&buf).expect("well formed");
    assert_eq!(split.adv_data.len(), 1);
    assert_eq!(split.scan_rsp.len(), 2);
}

#[test]
fn the_instance_commands_round_trip() {
    assert_eq!(Instance::decode(&[3]), Some(Instance { instance: 3 }));
    assert_eq!(Instance::decode(&[3, 0]), None);
    let g = GetAdvSizeInfo { instance: 2, flags: 0x10 };
    assert_eq!(g.encode().len(), 5);
    assert_eq!(GetAdvSizeInfo::decode(&g.encode()), Some(g));
    assert_eq!(GetAdvSizeInfo::decode(&[0, 0, 0, 0]), None);
}

#[test]
fn extended_advertising_parameters_round_trip() {
    let v = AddExtAdvParams {
        instance: 1, flags: 0x1_0000, duration: 5, timeout: 10,
        min_interval: 0x20, max_interval: 0x40, tx_power: -12,
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 18);
    assert_eq!(buf[17], 0xf4, "the power is a signed byte");
    assert_eq!(AddExtAdvParams::decode(&buf), Some(v));
    assert_eq!(AddExtAdvParams::decode(&buf[..17]), None);
    assert_eq!(AddExtAdvParams::decode(&alloc::vec![0u8; 19]), None);
}

#[test]
fn extended_advertising_data_round_trips() {
    let v = AddExtAdvData {
        instance: 1, adv_data: alloc::vec![1, 2], scan_rsp: alloc::vec![3],
    };
    let buf = v.encode();
    assert_eq!(buf, alloc::vec![1, 2, 1, 1, 2, 3]);
    assert_eq!(AddExtAdvData::decode(&buf), Some(v));
    let mut bad = buf.clone();
    bad[1] = 3;
    assert_eq!(AddExtAdvData::decode(&bad), None);
}

#[test]
fn a_monitor_round_trips_in_both_forms() {
    let p = AdvPattern { ad_type: 9, offset: 0, length: 3, value: [0xab; 31] };
    let plain = AddAdvPatternsMonitor { rssi: None, patterns: alloc::vec![p] };
    let buf = plain.encode();
    assert_eq!(buf.len(), 1 + 34);
    assert_eq!(AddAdvPatternsMonitor::decode(&buf), Some(plain));

    let t = AdvRssiThresholds {
        high_threshold: -30, high_threshold_timeout: 1,
        low_threshold: -70, low_threshold_timeout: 2, sampling_period: 3,
    };
    let rssi = AddAdvPatternsMonitor { rssi: Some(t), patterns: alloc::vec![p, p] };
    let buf = rssi.encode();
    assert_eq!(buf.len(), 7 + 1 + 2 * 34);
    assert_eq!(AddAdvPatternsMonitor::decode_rssi(&buf), Some(rssi));
}

#[test]
fn a_pattern_count_that_disagrees_is_refused() {
    let p = AdvPattern { ad_type: 9, offset: 0, length: 3, value: [0; 31] };
    let mut buf = AddAdvPatternsMonitor { rssi: None, patterns: alloc::vec![p] }.encode();
    buf[0] = 2;
    assert_eq!(AddAdvPatternsMonitor::decode(&buf), None);
    buf[0] = 0;
    assert_eq!(AddAdvPatternsMonitor::decode(&buf), None);
}

#[test]
fn a_monitor_with_no_patterns_matches_nothing_and_is_refused() {
    let empty = AddAdvPatternsMonitor { rssi: None, patterns: alloc::vec![] };
    assert!(!empty.windows_are_valid());
    let bad = AddAdvPatternsMonitor {
        rssi: None,
        patterns: alloc::vec![AdvPattern { ad_type: 0, offset: 30, length: 5, value: [0; 31] }],
    };
    assert!(!bad.windows_are_valid());
}

#[test]
fn remove_adv_monitor_round_trips() {
    let v = RemoveAdvMonitor { monitor_handle: 0x1234 };
    assert_eq!(v.encode(), alloc::vec![0x34, 0x12]);
    assert_eq!(RemoveAdvMonitor::decode(&v.encode()), Some(v));
    assert_eq!(RemoveAdvMonitor::decode(&[0x34]), None);
}

#[test]
fn an_experimental_feature_carries_an_open_ended_parameter() {
    let v = SetExpFeature { uuid: [1u8; 16], param: alloc::vec![1] };
    assert_eq!(v.encode().len(), 17);
    assert_eq!(SetExpFeature::decode(&v.encode()), Some(v));
    // No parameter at all is legal.
    let bare = SetExpFeature { uuid: [2u8; 16], param: alloc::vec![] };
    assert_eq!(SetExpFeature::decode(&bare.encode()), Some(bare));
    // Short of the UUID is not.
    assert_eq!(SetExpFeature::decode(&alloc::vec![0u8; 15]), None);
}

#[test]
fn the_mesh_receiver_round_trips() {
    let v = SetMeshReceiver {
        enable: 1, window: 0x10, period: 0x20, ad_types: alloc::vec![0x2a, 0x2b],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 6 + 2);
    assert_eq!(buf[5], 2);
    assert_eq!(SetMeshReceiver::decode(&buf), Some(v));
    let mut bad = buf.clone();
    bad[5] = 3;
    assert_eq!(SetMeshReceiver::decode(&bad), None);
}

#[test]
fn the_mesh_duty_cycle_is_bounded_and_the_window_fits_the_period() {
    let mk = |enable, window, period| SetMeshReceiver {
        enable, window, period, ad_types: alloc::vec![],
    };
    assert!(mk(1, MESH_SCAN_MIN, MESH_SCAN_MAX).duty_cycle_is_valid());
    assert!(mk(0, MESH_SCAN_MAX, MESH_SCAN_MAX).duty_cycle_is_valid());
    assert!(!mk(1, MESH_SCAN_MIN - 1, MESH_SCAN_MAX).duty_cycle_is_valid());
    assert!(!mk(1, MESH_SCAN_MIN, MESH_SCAN_MAX + 1).duty_cycle_is_valid());
    assert!(!mk(1, MESH_SCAN_MAX, MESH_SCAN_MIN).duty_cycle_is_valid(), "window past period");
    assert!(!mk(2, MESH_SCAN_MIN, MESH_SCAN_MAX).duty_cycle_is_valid(), "enable is boolean");
}

#[test]
fn a_mesh_send_round_trips() {
    let v = MeshSend {
        addr: AddrInfo::new(BdAddr([9; 6]), BDADDR_LE_RANDOM),
        instant: 0x0102_0304_0506_0708, delay: 5, cnt: 3,
        adv_data: alloc::vec![1, 2, 3],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 19 + 3);
    assert_eq!(MeshSend::decode(&buf), Some(v));
    let mut bad = buf.clone();
    bad[18] = 4;
    assert_eq!(MeshSend::decode(&bad), None);
}

#[test]
fn a_mesh_payload_must_fit_one_advertisement() {
    let mk = |n: usize| MeshSend {
        addr: AddrInfo::default(), instant: 0, delay: 0, cnt: 1,
        adv_data: alloc::vec![0u8; n],
    };
    assert!(!mk(0).data_len_is_valid());
    assert!(mk(1).data_len_is_valid());
    assert!(mk(MESH_MAX_ADV_DATA).data_len_is_valid());
    assert!(!mk(MESH_MAX_ADV_DATA + 1).data_len_is_valid());
}

#[test]
fn the_pass_through_command_round_trips() {
    let v = HciCmdSync {
        opcode: 0x0c03, event: 0x0e, timeout: 2, params: alloc::vec![1, 2, 3],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 6 + 3);
    assert_eq!(&buf[4..6], &3u16.to_le_bytes());
    assert_eq!(HciCmdSync::decode(&buf), Some(v));
    let mut bad = buf.clone();
    bad[4] = 4;
    assert_eq!(HciCmdSync::decode(&bad), None);
}
