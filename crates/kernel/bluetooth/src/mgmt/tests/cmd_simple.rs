//! The fixed-shape setters.

use super::*;
use crate::uapi::bt::BdAddr;

#[test]
fn a_mode_byte_round_trips() {
    assert_eq!(Mode::decode(&[1]), Some(Mode { val: 1 }));
    assert_eq!(Mode { val: 0 }.encode(), alloc::vec![0]);
    assert_eq!(Mode::decode(&[]), None);
    assert_eq!(Mode::decode(&[0, 0]), None);
}

#[test]
fn a_boolean_mode_rejects_anything_past_one() {
    assert!(Mode { val: 0 }.is_boolean());
    assert!(Mode { val: 1 }.is_boolean());
    assert!(!Mode { val: 2 }.is_boolean());
    assert!(!Mode { val: 0xff }.is_boolean());
    assert!(Mode { val: 2 }.on(), "any non-zero value is on");
}

#[test]
fn set_discoverable_round_trips() {
    let v = SetDiscoverable { val: 1, timeout: 180 };
    assert_eq!(v.encode(), alloc::vec![1, 180, 0]);
    assert_eq!(SetDiscoverable::decode(&v.encode()), Some(v));
    assert_eq!(SetDiscoverable::decode(&[1, 0]), None);
    assert_eq!(SetDiscoverable::decode(&[1, 0, 0, 0]), None);
}

#[test]
fn set_dev_class_round_trips() {
    let v = SetDevClass { major: 0x02, minor: 0x0c };
    assert_eq!(v.encode(), alloc::vec![0x02, 0x0c]);
    assert_eq!(SetDevClass::decode(&v.encode()), Some(v));
    assert_eq!(SetDevClass::decode(&[1]), None);
}

#[test]
fn the_name_slots_are_fixed_width_and_nul_terminated() {
    let v = SetLocalName { name: b"oxide".to_vec(), short_name: b"ox".to_vec() };
    let buf = v.encode();
    assert_eq!(buf.len(), 260);
    assert_eq!(&buf[..5], b"oxide");
    assert_eq!(buf[5], 0, "the slot is padded, not packed");
    assert_eq!(&buf[249..251], b"ox");
    assert_eq!(SetLocalName::decode(&buf), Some(v));
}

#[test]
fn a_name_payload_of_the_wrong_width_is_refused() {
    assert_eq!(SetLocalName::decode(&alloc::vec![0u8; 259]), None);
    assert_eq!(SetLocalName::decode(&alloc::vec![0u8; 261]), None);
}

#[test]
fn a_name_that_fills_its_slot_leaves_no_terminator() {
    let v = SetLocalName {
        name: alloc::vec![b'x'; 249], short_name: alloc::vec![b'y'; 11],
    };
    assert!(!v.fits(), "a value filling the slot has nowhere for the terminator");
    let ok = SetLocalName {
        name: alloc::vec![b'x'; 248], short_name: alloc::vec![b'y'; 10],
    };
    assert!(ok.fits());
    // Encoding still writes exactly the slot width.
    assert_eq!(v.encode().len(), 260);
}

#[test]
fn add_and_remove_uuid_round_trip() {
    let v = AddUuid { uuid: [3u8; 16], svc_hint: 0x02 };
    assert_eq!(v.encode().len(), 17);
    assert_eq!(AddUuid::decode(&v.encode()), Some(v));
    assert_eq!(AddUuid::decode(&alloc::vec![0u8; 16]), None);

    let r = RemoveUuid { uuid: [0u8; 16] };
    assert!(r.is_all(), "the all-zero UUID clears the list");
    assert_eq!(RemoveUuid::decode(&r.encode()), Some(r));
    assert!(!RemoveUuid { uuid: [1u8; 16] }.is_all());
    assert_eq!(RemoveUuid::decode(&alloc::vec![0u8; 17]), None);
}

#[test]
fn set_device_id_round_trips_four_words() {
    let v = SetDeviceId { source: 1, vendor: 0x1d6b, product: 0x0246, version: 0x0537 };
    let buf = v.encode();
    assert_eq!(buf, alloc::vec![0x01, 0x00, 0x6b, 0x1d, 0x46, 0x02, 0x37, 0x05]);
    assert_eq!(SetDeviceId::decode(&buf), Some(v));
    assert_eq!(SetDeviceId::decode(&buf[..7]), None);
}

#[test]
fn a_bare_address_command_round_trips() {
    let v = SetAddress { bdaddr: BdAddr([1, 2, 3, 4, 5, 6]) };
    assert_eq!(v.encode(), alloc::vec![1, 2, 3, 4, 5, 6]);
    assert_eq!(SetAddress::decode(&v.encode()), Some(v));
    assert_eq!(SetAddress::decode(&[1, 2, 3, 4, 5]), None);
    assert_eq!(SetAddress::decode(&[1, 2, 3, 4, 5, 6, 7]), None);
}

#[test]
fn scan_parameters_round_trip_and_the_window_fits_the_interval() {
    let v = SetScanParams { interval: 0x0060, window: 0x0030 };
    assert_eq!(v.encode(), alloc::vec![0x60, 0x00, 0x30, 0x00]);
    assert_eq!(SetScanParams::decode(&v.encode()), Some(v));
    assert!(v.is_consistent());
    assert!(SetScanParams { interval: 0x30, window: 0x30 }.is_consistent());
    assert!(!SetScanParams { interval: 0x30, window: 0x31 }.is_consistent());
}

#[test]
fn set_privacy_round_trips() {
    let v = SetPrivacy { privacy: 1, irk: [9u8; 16] };
    assert_eq!(v.encode().len(), 17);
    assert_eq!(SetPrivacy::decode(&v.encode()), Some(v));
    assert_eq!(SetPrivacy::decode(&alloc::vec![0u8; 18]), None);
}

#[test]
fn the_one_word_setters_round_trip() {
    let a = SetAppearance { appearance: 0x0341 };
    assert_eq!(a.encode(), alloc::vec![0x41, 0x03]);
    assert_eq!(SetAppearance::decode(&a.encode()), Some(a));
    assert_eq!(SetAppearance::decode(&[0x41]), None);

    let p = SetPhyConfiguration { selected_phys: 0x0000_0201 };
    assert_eq!(p.encode(), alloc::vec![0x01, 0x02, 0x00, 0x00]);
    assert_eq!(SetPhyConfiguration::decode(&p.encode()), Some(p));
    assert_eq!(SetPhyConfiguration::decode(&[0, 0, 0]), None);
}

#[test]
fn an_io_capability_past_the_last_one_is_refused() {
    for c in 0..=4u8 {
        assert!(SetIoCapability { io_capability: c }.is_valid(), "capability {c}");
    }
    for c in [5u8, 6, 0xff] {
        assert!(!SetIoCapability { io_capability: c }.is_valid(), "capability {c}");
    }
    assert_eq!(SetIoCapability::decode(&[3]), Some(SetIoCapability { io_capability: 3 }));
    assert_eq!(SetIoCapability::decode(&[3, 0]), None);
}
