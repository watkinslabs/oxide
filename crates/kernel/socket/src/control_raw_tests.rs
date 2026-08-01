use alloc::vec;
use alloc::vec::Vec;

use crate::Error;

use crate::control_raw::parse_raw_control;

fn cmsg(level: i32, kind: i32, data: &[u8]) -> Vec<u8> {
    let len = 16 + data.len();
    let mut out = vec![0u8; (len + 7) & !7];
    out[..8].copy_from_slice(&(len as u64).to_ne_bytes());
    out[8..12].copy_from_slice(&level.to_ne_bytes());
    out[12..16].copy_from_slice(&kind.to_ne_bytes());
    out[16..16 + data.len()].copy_from_slice(data);
    out
}
fn einval() -> Error { Error::Einval }
fn eperm() -> Error { Error::Eperm }
fn int(value: i32) -> [u8; 4] { value.to_ne_bytes() }

#[test]
fn ipv4_fixed_controls_require_exact_native_payloads() {
    assert_eq!(parse_raw_control(&cmsg(0, 8, &[0; 11]), false, true, 0).err(), Some(einval()));
    assert_eq!(parse_raw_control(&cmsg(0, 2, &[1; 5]), false, true, 0).err(), Some(einval()));
    assert_eq!(parse_raw_control(&cmsg(0, 1, &[7; 2]), false, true, 0).err(), Some(einval()));
    let mut long = [1u8; 41]; long[40] = 0xff;
    assert_eq!(parse_raw_control(&cmsg(0, 7, &long), false, true, 0).unwrap()
        .raw4.options.unwrap().len(), 40);
    for (kind, value) in [(2, 0), (2, 256), (52, 0), (52, 256), (1, -1), (1, 256)] {
        assert_eq!(parse_raw_control(&cmsg(0, kind, &int(value)), false, true, 0).err(), Some(einval()));
    }
    assert!(parse_raw_control(&cmsg(0, 1, &[0xff]), false, true, 0).is_ok());
    assert_eq!(parse_raw_control(&cmsg(0, 99, &[]), false, true, 0).err(), Some(einval()));
}

#[test]
fn ipv4_options_compile_linux_pointer_duplicate_and_cap_rules() {
    // The compile pass reserves the slot the fill pass will write, so the
    // stored pointer already names the byte past it.
    let rr = [7, 7, 4, 0, 0, 0, 0];
    let parsed = parse_raw_control(&cmsg(0, 7, &rr), false, false, 0).unwrap();
    let rr_compiled = parsed.raw4.options.unwrap();
    assert_eq!(rr_compiled.data[2], 8);
    assert!(rr_compiled.rr_needaddr);
    assert_eq!(parse_raw_control(&cmsg(0, 7, &[7, 3, 3]), false, true, 0).err(), Some(einval()));
    let mut duplicate = rr.to_vec(); duplicate.extend_from_slice(&rr);
    assert_eq!(parse_raw_control(&cmsg(0, 7, &duplicate), false, true, 0).err(), Some(einval()));

    let ts_only = [68, 8, 5, 0, 0, 0, 0, 0];
    assert_eq!(parse_raw_control(&cmsg(0, 7, &ts_only), false, false, 0).unwrap()
        .raw4.options.unwrap().data[2], 9);
    let ts_addr = [68, 12, 5, 1, 0, 0, 0, 0, 0, 0, 0, 0];
    assert_eq!(parse_raw_control(&cmsg(0, 7, &ts_addr), false, false, 0).unwrap()
        .raw4.options.unwrap().data[2], 13);
    assert_eq!(parse_raw_control(&cmsg(0, 7, &[68, 8, 5, 1, 0, 0, 0, 0]), false, true, 0).err(), Some(einval()));
    assert_eq!(parse_raw_control(&cmsg(0, 7, &[68, 4, 9, 0xf0]), false, true, 0).err(), Some(einval()));
    assert_eq!(parse_raw_control(&cmsg(0, 7, &[68, 8, 5, 2, 0, 0, 0, 0]), false, false, 0).err(), Some(einval()));
    assert!(parse_raw_control(&cmsg(0, 7, &[68, 8, 5, 2, 0, 0, 0, 0]), false, true, 0).is_ok());

    assert!(parse_raw_control(&cmsg(0, 7, &[148, 4, 0, 0]), false, false, 0).is_ok());
    assert_eq!(parse_raw_control(&cmsg(0, 7, &[148, 3, 0]), false, true, 0).err(), Some(einval()));
    assert_eq!(parse_raw_control(&cmsg(0, 7, &[30, 2]), false, false, 0).err(), Some(einval()));
    assert!(parse_raw_control(&cmsg(0, 7, &[30, 2]), false, true, 0).is_ok());
}

#[test]
fn ipv4_source_route_requires_cap_and_extracts_first_hop() {
    let route = [131, 11, 4, 192, 0, 2, 1, 192, 0, 2, 2];
    assert_eq!(parse_raw_control(&cmsg(0, 7, &route), false, false, 0).err(), Some(eperm()));
    let parsed = parse_raw_control(&cmsg(0, 7, &route), false, true, 0).unwrap();
    let options = parsed.raw4.options.unwrap();
    assert_eq!(options.faddr, [192, 0, 2, 1]);
    assert_eq!(&options.data[3..7], &[192, 0, 2, 2]);
    let mut duplicate = route.to_vec(); duplicate.extend_from_slice(&route[..7]);
    assert_eq!(parse_raw_control(&cmsg(0, 7, &duplicate), false, true, 0).err(), Some(einval()));
}

#[test]
fn ipv6_fixed_and_variable_controls_accept_linux_trailing_data() {
    assert!(parse_raw_control(&cmsg(41, 50, &[0; 21]), true, true, 0).is_ok());
    assert!(parse_raw_control(&cmsg(41, 11, &[0; 5]), true, true, 0).is_ok());
    let mut ext = [0u8; 9]; ext[1] = 0;
    assert_eq!(parse_raw_control(&cmsg(41, 54, &ext), true, true, 0).unwrap()
        .raw6.hop_options.unwrap().len(), 8);
    let mut route = [0u8; 25]; route[1] = 2; route[2] = 2; route[3] = 1;
    assert_eq!(parse_raw_control(&cmsg(41, 57, &route), true, true, 0).unwrap()
        .raw6.routing.unwrap().len(), 24);
    for (kind, value) in [(52, -2), (52, 256), (8, -2), (67, -2), (67, 256),
        (62, -1), (62, 2)]
    {
        assert_eq!(parse_raw_control(&cmsg(41, kind, &int(value)), true, true, 0).err(), Some(einval()));
    }
    assert_eq!(parse_raw_control(&cmsg(41, 99, &[]), true, true, 0).err(), Some(einval()));
}

#[test]
fn every_ipv6_extension_header_requires_net_raw() {
    let mut ext = [0u8; 8]; ext[1] = 0;
    for kind in [3, 4, 54, 55, 59] {
        assert_eq!(parse_raw_control(&cmsg(41, kind, &ext), true, false, 0).err(), Some(eperm()));
    }
    let mut route = [0u8; 24]; route[1] = 2; route[2] = 2; route[3] = 1;
    assert!(parse_raw_control(&cmsg(41, 57, &route), true, false, 0).is_ok());
}
