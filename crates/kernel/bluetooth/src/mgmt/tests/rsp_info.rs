//! Controller descriptions and capability reads.

use super::*;

#[test]
fn the_version_response_is_three_bytes() {
    let v = ReadVersion { version: 1, revision: 23 };
    assert_eq!(v.encode(), alloc::vec![1, 23, 0]);
    assert_eq!(ReadVersion::decode(&v.encode()), Some(v));
    assert_eq!(ReadVersion::decode(&[1, 23]), None);
    assert_eq!(ReadVersion::decode(&[1, 23, 0, 0]), None);
}

fn info() -> ReadInfo {
    ReadInfo {
        bdaddr: BdAddr([1, 2, 3, 4, 5, 6]),
        version: 9,
        manufacturer: 0x000f,
        supported_settings: 0x0001_ffff,
        current_settings: 0x0000_0081,
        dev_class: [0x0c, 0x02, 0x18],
        name: b"oxide".to_vec(),
        short_name: b"ox".to_vec(),
    }
}

#[test]
fn the_info_response_is_fixed_width_at_every_field() {
    let v = info();
    let buf = v.encode();
    assert_eq!(buf.len(), READ_INFO_RSP_SIZE);
    assert_eq!(buf.len(), 280);
    assert_eq!(&buf[..6], &[1, 2, 3, 4, 5, 6]);
    assert_eq!(buf[6], 9);
    assert_eq!(&buf[7..9], &0x000fu16.to_le_bytes());
    assert_eq!(&buf[9..13], &0x0001_ffffu32.to_le_bytes());
    assert_eq!(&buf[13..17], &0x0000_0081u32.to_le_bytes());
    assert_eq!(&buf[17..20], &[0x0c, 0x02, 0x18]);
    assert_eq!(&buf[20..25], b"oxide");
    assert_eq!(&buf[269..271], b"ox");
    assert_eq!(ReadInfo::decode(&buf), Some(v));
}

#[test]
fn an_info_response_of_the_wrong_width_is_refused() {
    let buf = info().encode();
    assert_eq!(ReadInfo::decode(&buf[..buf.len() - 1]), None);
    let mut long = buf.clone();
    long.push(0);
    assert_eq!(ReadInfo::decode(&long), None);
}

#[test]
fn the_extended_info_response_carries_its_identity_as_eir() {
    let v = ReadExtInfo {
        bdaddr: BdAddr([6, 5, 4, 3, 2, 1]),
        version: 9, manufacturer: 2,
        supported_settings: 3, current_settings: 1,
        eir: alloc::vec![6, 0x09, b'o', b'x', b'i', b'd', b'e'],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 19 + 7);
    assert_eq!(&buf[17..19], &7u16.to_le_bytes());
    assert_eq!(ReadExtInfo::decode(&buf), Some(v));
    let mut bad = buf.clone();
    bad[17] = 8;
    assert_eq!(ReadExtInfo::decode(&bad), None);
}

#[test]
fn the_configuration_response_round_trips() {
    let v = ReadConfigInfo {
        manufacturer: 0x1234, supported_options: 3, missing_options: 2,
    };
    assert_eq!(v.encode().len(), 10);
    assert_eq!(ReadConfigInfo::decode(&v.encode()), Some(v));
    assert_eq!(ReadConfigInfo::decode(&alloc::vec![0u8; 9]), None);
}

#[test]
fn capability_records_round_trip_with_their_declared_body_length() {
    let v = ReadControllerCap {
        caps: alloc::vec![
            Tlv { tlv_type: 1, value: alloc::vec![0xff] },
            Tlv { tlv_type: 2, value: alloc::vec![16] },
        ],
    };
    let buf = v.encode();
    assert_eq!(&buf[..2], &8u16.to_le_bytes(), "the body length leads");
    assert_eq!(buf.len(), 2 + 8);
    assert_eq!(ReadControllerCap::decode(&buf), Some(v));
}

#[test]
fn a_capability_body_length_that_disagrees_is_refused() {
    let v = ReadControllerCap { caps: alloc::vec![Tlv { tlv_type: 1, value: alloc::vec![1] }] };
    let mut buf = v.encode();
    buf[0] = 5;
    assert_eq!(ReadControllerCap::decode(&buf), None);
    // A record inside the body claiming more than the body holds is refused too.
    let bad = [4u8, 0, 1, 0, 9, 0xff];
    assert_eq!(ReadControllerCap::decode(&bad), None);
}

#[test]
fn the_advertising_features_response_round_trips() {
    let v = ReadAdvFeatures {
        supported_flags: 0x7ff, max_adv_data_len: 31, max_scan_rsp_len: 31,
        max_instances: 5, instances: alloc::vec![1, 2],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 8 + 2);
    assert_eq!(buf[7], 2, "the count is the instances present, not the maximum");
    assert_eq!(ReadAdvFeatures::decode(&buf), Some(v));
    let mut bad = buf.clone();
    bad[7] = 3;
    assert_eq!(ReadAdvFeatures::decode(&bad), None);
}

#[test]
fn the_phy_response_is_three_words() {
    let v = PhyConfiguration {
        supported_phys: 0x7fff, configurable_phys: 0x1ff, selected_phys: 0x201,
    };
    assert_eq!(v.encode().len(), 12);
    assert_eq!(PhyConfiguration::decode(&v.encode()), Some(v));
    assert_eq!(PhyConfiguration::decode(&alloc::vec![0u8; 11]), None);
}

#[test]
fn the_monitor_features_response_round_trips() {
    let v = ReadAdvMonitorFeatures {
        supported_features: 1, enabled_features: 1,
        max_num_handles: 32, max_num_patterns: 16,
        handles: alloc::vec![1, 2, 3],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 13 + 6);
    assert_eq!(ReadAdvMonitorFeatures::decode(&buf), Some(v));
    assert_eq!(ReadAdvMonitorFeatures::decode(&buf[..buf.len() - 1]), None);
}

#[test]
fn the_mesh_features_response_reports_every_handle_slot() {
    let v = MeshReadFeatures {
        index: 0, max_handles: 3, used_handles: 1, handles: [7, 0, 0],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 7);
    assert_eq!(MeshReadFeatures::decode(&buf), Some(v));
    assert_eq!(MeshReadFeatures::decode(&buf[..6]), None);
}

#[test]
fn the_experimental_features_response_round_trips() {
    let v = ReadExpFeaturesInfo {
        features: alloc::vec![
            ExpFeature { uuid: [1u8; 16], flags: 3 },
            ExpFeature { uuid: [2u8; 16], flags: 0 },
        ],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 2 + 40);
    assert_eq!(ReadExpFeaturesInfo::decode(&buf), Some(v));
    let mut bad = buf.clone();
    bad[0] = 3;
    assert_eq!(ReadExpFeaturesInfo::decode(&bad), None);
}

/// The out-of-band response has the same two widths as the command.
#[test]
fn the_oob_response_accepts_exactly_its_two_widths() {
    let short = ReadLocalOobData { hash192: [1; 16], rand192: [2; 16], sc: None };
    assert_eq!(short.encode().len(), 32);
    assert_eq!(ReadLocalOobData::decode(&short.encode()), Some(short));
    let long = ReadLocalOobData {
        hash192: [1; 16], rand192: [2; 16], sc: Some(([3; 16], [4; 16])),
    };
    assert_eq!(long.encode().len(), 64);
    assert_eq!(ReadLocalOobData::decode(&long.encode()), Some(long));
    for n in [31usize, 33, 48, 63, 65] {
        assert_eq!(ReadLocalOobData::decode(&alloc::vec![0u8; n]), None, "width {n}");
    }
}

#[test]
fn the_extended_oob_response_round_trips() {
    let v = LocalOobExtData { addr_type: 1, eir: alloc::vec![2, 0x01, 0x06] };
    let buf = v.encode();
    assert_eq!(buf.len(), 3 + 3);
    assert_eq!(LocalOobExtData::decode(&buf), Some(v));
    let mut bad = buf.clone();
    bad[1] = 4;
    assert_eq!(LocalOobExtData::decode(&bad), None);
}
