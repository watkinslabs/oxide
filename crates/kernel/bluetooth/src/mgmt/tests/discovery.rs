//! Scan admission and the two scan records.

use super::*;
use crate::mgmt::types::AddrInfo;
use crate::uapi::bt::{BdAddr, BDADDR_LE_RANDOM};
use crate::uapi::mgmt::flags::{
    MGMT_DEV_FOUND_CONFIRM_NAME, MGMT_DEV_FOUND_INITIATED_CONN, MGMT_DEV_FOUND_LEGACY_PAIRING,
    MGMT_DEV_FOUND_NAME_REQUEST_FAILED, MGMT_DEV_FOUND_NOT_CONNECTABLE, MGMT_DEV_FOUND_SCAN_RSP,
};

const HAVE: TransportSupport = TransportSupport { capable: true, enabled: true };
const OFF: TransportSupport = TransportSupport { capable: true, enabled: false };
const NONE: TransportSupport = TransportSupport { capable: false, enabled: false };

#[test]
fn the_type_byte_is_a_mask_over_address_types() {
    assert_eq!(DISCOV_TYPE_BREDR, 0x01);
    assert_eq!(DISCOV_TYPE_LE, 0x06);
    assert_eq!(DISCOV_TYPE_INTERLEAVED, 0x07);
}

#[test]
fn a_type_outside_the_three_is_invalid() {
    for t in [0u8, 0x02, 0x04, 0x05, 0x08, 0xff] {
        assert_eq!(discovery_type_status(t, HAVE, HAVE), MGMT_STATUS_INVALID_PARAMS,
                   "type {t:#04x}");
    }
}

#[test]
fn absent_hardware_and_a_disabled_transport_are_different_answers() {
    assert_eq!(discovery_type_status(DISCOV_TYPE_LE, HAVE, NONE), MGMT_STATUS_NOT_SUPPORTED);
    assert_eq!(discovery_type_status(DISCOV_TYPE_LE, HAVE, OFF), MGMT_STATUS_REJECTED);
    assert_eq!(discovery_type_status(DISCOV_TYPE_BREDR, NONE, HAVE), MGMT_STATUS_NOT_SUPPORTED);
    assert_eq!(discovery_type_status(DISCOV_TYPE_BREDR, OFF, HAVE), MGMT_STATUS_REJECTED);
}

#[test]
fn each_type_consults_only_the_transports_it_uses() {
    // A BR/EDR scan does not care about LE, and vice versa.
    assert_eq!(discovery_type_status(DISCOV_TYPE_BREDR, HAVE, NONE), MGMT_STATUS_SUCCESS);
    assert_eq!(discovery_type_status(DISCOV_TYPE_LE, NONE, HAVE), MGMT_STATUS_SUCCESS);
}

/// An interleaved scan needs both, and reports the LE failure first.
#[test]
fn an_interleaved_scan_needs_both_and_reports_le_first() {
    assert_eq!(discovery_type_status(DISCOV_TYPE_INTERLEAVED, HAVE, HAVE),
               MGMT_STATUS_SUCCESS);
    assert_eq!(discovery_type_status(DISCOV_TYPE_INTERLEAVED, NONE, HAVE),
               MGMT_STATUS_NOT_SUPPORTED);
    assert_eq!(discovery_type_status(DISCOV_TYPE_INTERLEAVED, HAVE, OFF),
               MGMT_STATUS_REJECTED);
    // Both broken: the LE answer wins.
    assert_eq!(discovery_type_status(DISCOV_TYPE_INTERLEAVED, OFF, NONE),
               MGMT_STATUS_NOT_SUPPORTED);
}

#[test]
fn service_discovery_round_trips() {
    let v = ServiceDiscovery {
        disc_type: DISCOV_TYPE_LE, rssi: -70,
        uuids: alloc::vec![[1u8; 16], [2u8; 16]],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 4 + 32);
    assert_eq!(buf[1], 0xba, "the threshold is a signed byte");
    assert_eq!(ServiceDiscovery::decode(&buf), Some(v));
}

#[test]
fn a_uuid_count_that_disagrees_with_the_bytes_is_refused() {
    // Claims one UUID, carries none.
    assert_eq!(ServiceDiscovery::decode(&[DISCOV_TYPE_LE, 0, 1, 0]), None);
    // Claims none, carries sixteen bytes.
    let mut buf = alloc::vec![DISCOV_TYPE_LE, 0, 0, 0];
    buf.extend_from_slice(&[0u8; 16]);
    assert_eq!(ServiceDiscovery::decode(&buf), None);
    // A count too large for the length field is refused before any allocation.
    let huge = ((MAX_SERVICE_UUID_COUNT + 1) as u16).to_le_bytes();
    assert_eq!(ServiceDiscovery::decode(&[DISCOV_TYPE_LE, 0, huge[0], huge[1]]), None);
}

#[test]
fn the_discovering_event_round_trips() {
    let v = Discovering { disc_type: DISCOV_TYPE_INTERLEAVED, discovering: true };
    assert_eq!(v.encode(), alloc::vec![0x07, 0x01]);
    assert_eq!(Discovering::decode(&v.encode()), Some(v));
    let off = Discovering { disc_type: DISCOV_TYPE_BREDR, discovering: false };
    assert_eq!(off.encode(), alloc::vec![0x01, 0x00]);
    assert_eq!(Discovering::decode(&[0x01, 0x00, 0x00]), None, "trailing byte");
}

#[test]
fn a_device_report_carries_its_eir_verbatim() {
    let v = DeviceFound {
        addr: AddrInfo::new(BdAddr([1, 2, 3, 4, 5, 6]), BDADDR_LE_RANDOM),
        rssi: -100,
        flags: MGMT_DEV_FOUND_CONFIRM_NAME | MGMT_DEV_FOUND_SCAN_RSP,
        eir: alloc::vec![2, 0x01, 0x06],
    };
    let buf = v.encode();
    assert_eq!(buf.len(), 7 + 1 + 4 + 2 + 3);
    assert_eq!(buf[7], 0x9c, "rssi is a signed byte");
    assert_eq!(DeviceFound::decode(&buf), Some(v));
}

#[test]
fn a_device_report_with_a_lying_eir_length_is_refused() {
    let mut v = DeviceFound {
        addr: AddrInfo::default(), rssi: 0, flags: 0, eir: alloc::vec![2, 0x01, 0x06],
    };
    let mut buf = v.encode();
    // Claim one byte more of EIR than is present.
    buf[12] = 4;
    assert_eq!(DeviceFound::decode(&buf), None);
    // A trailing byte past the declared EIR is equally a disagreement.
    v.eir.clear();
    let mut buf = v.encode();
    buf.push(0xff);
    assert_eq!(DeviceFound::decode(&buf), None);
}

#[test]
fn the_device_found_flags_sit_where_the_interface_says() {
    assert_eq!(MGMT_DEV_FOUND_CONFIRM_NAME, 1);
    assert_eq!(MGMT_DEV_FOUND_LEGACY_PAIRING, 2);
    assert_eq!(MGMT_DEV_FOUND_NOT_CONNECTABLE, 4);
    assert_eq!(MGMT_DEV_FOUND_INITIATED_CONN, 8);
    assert_eq!(MGMT_DEV_FOUND_NAME_REQUEST_FAILED, 16);
    assert_eq!(MGMT_DEV_FOUND_SCAN_RSP, 32);
}
