//! Address formatting contracts: the dotted quad with its port suffix, the
//! IPv6 zero-run elision, the embedded quad forms, and the produced length.

use super::{format6, ipv4};

fn quad(bytes: [u8; 4], port: u16) -> (alloc::string::String, usize) {
    let mut out = [0u8; ipv4::TEXT_UNITS];
    let needed = ipv4::format(bytes, port.swap_bytes(), &mut out, 0);
    (alloc::string::String::from_utf8_lossy(&out[..needed]).into_owned(), needed + 1)
}

fn wide(raw: [u8; 16], scope: u32, port: u16) -> (alloc::string::String, usize) {
    let mut out = [0u8; format6::TEXT_BYTES];
    let needed = format6::render(&raw, scope, port.swap_bytes(), &mut out);
    (alloc::string::String::from_utf8_lossy(&out[..needed - 1]).into_owned(), needed)
}

fn raw(groups: [u16; 8]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for (index, group) in groups.iter().enumerate() { out[index * 2..index * 2 + 2].copy_from_slice(&group.to_be_bytes()); }
    out
}

#[test]
fn a_dotted_quad_reports_its_own_length() {
    assert_eq!(quad([0, 0, 0, 0], 0), ("0.0.0.0".into(), 8));
    assert_eq!(quad([1, 2, 3, 4], 0), ("1.2.3.4".into(), 8));
    assert_eq!(quad([255, 255, 255, 255], 0), ("255.255.255.255".into(), 16));
    assert_eq!(quad([1, 2, 3, 4], 80), ("1.2.3.4:80".into(), 11));
    assert_eq!(quad([10, 0, 0, 1], 65535), ("10.0.0.1:65535".into(), 15));
}

#[test]
fn the_longest_zero_run_elides_and_ties_go_to_the_first() {
    assert_eq!(wide(raw([0; 8]), 0, 0), ("::".into(), 3));
    assert_eq!(wide(raw([0x1234, 0, 0, 0, 0, 0, 0, 0x5678]), 0, 0), ("1234::5678".into(), 11));
    assert_eq!(wide(raw([1, 0, 0, 1, 0, 0, 1, 1]), 0, 0), ("1::1:0:0:1:1".into(), 13));
    assert_eq!(wide(raw([1, 0, 0, 1, 0, 0, 0, 1]), 0, 0), ("1:0:0:1::1".into(), 11));
    assert_eq!(wide(raw([1, 0, 0, 0, 0, 0, 0, 0]), 0, 0), ("1::".into(), 4));
    assert_eq!(wide(raw([0xffff; 8]), 0, 0), ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".into(), 40));
}

#[test]
fn the_mapped_and_tunnel_forms_print_an_embedded_quad() {
    assert_eq!(wide(raw([0, 0, 0, 0, 0, 0xffff, 0x0102, 0x0304]), 0, 0), ("::ffff:1.2.3.4".into(), 15));
    assert_eq!(wide(raw([0, 0, 0, 0, 0, 0, 0x0102, 0x0304]), 0, 0), ("::1.2.3.4".into(), 10));
    assert_eq!(wide(raw([0, 0, 0, 0, 0, 0x5efe, 0xc0a8, 1]), 0, 0), ("::5efe:192.168.0.1".into(), 19));
    assert_eq!(wide(raw([0, 0, 0, 0, 0x200, 0x5efe, 0xc0a8, 1]), 0, 0), ("::200:5efe:192.168.0.1".into(), 23));
    // The tunnel marker one group later is an ordinary address.
    assert_eq!(wide(raw([0, 0, 0, 0, 0x5efe, 0, 0xc0a8, 1]), 0, 0), ("::5efe:0:c0a8:1".into(), 16));
    assert_eq!(wide(raw([0, 0, 0, 0, 0, 0, 0, 0xffff]), 0, 0), ("::ffff".into(), 7));
}

#[test]
fn the_scope_and_port_suffixes_bracket_the_address() {
    assert_eq!(wide(raw([0, 0, 0, 0, 0, 0, 0, 1]), 7, 0), ("::1%7".into(), 6));
    assert_eq!(wide(raw([0, 0, 0, 0, 0, 0, 0, 1]), 0, 80), ("[::1]:80".into(), 9));
    assert_eq!(wide(raw([0, 0, 0, 0, 0, 0, 0, 1]), 3, 8080), ("[::1%3]:8080".into(), 13));
    assert_eq!(wide(raw([0xfe80, 0, 0, 0, 0, 0, 0, 1]), 0, 0), ("fe80::1".into(), 8));
    assert_eq!(wide(raw([0x2001, 0x0db8, 0, 0, 8, 0x0800, 0x200c, 0x417a]), 0, 0), ("2001:db8::8:800:200c:417a".into(), 26));
}
