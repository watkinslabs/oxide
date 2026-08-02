// The cookie construction, pinned against the reference behaviour it must
// interoperate with. A cookie is a keyed hash of the address pair alone, so
// these tests are the durable record of exactly which bytes go in, in what
// order, and how the 64-bit result reaches the wire.

use super::*;
use crate::addr::{Ipv4Addr, Ipv6Addr};
use crate::tcp_fastopen::KEY_LEN;

const K1: [u8; KEY_LEN] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f];
const K2: [u8; KEY_LEN] = [
    0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
    0x78, 0x69, 0x5a, 0x4b, 0x3c, 0x2d, 0x1e, 0x0f];

fn v4(a: u8, b: u8, c: u8, d: u8) -> IpAddr { IpAddr::V4(Ipv4Addr::new(a, b, c, d)) }

fn v6(last: u8) -> IpAddr {
    let mut raw = [0u8; 16];
    raw[0] = 0x20; raw[1] = 0x01; raw[15] = last;
    IpAddr::V6(Ipv6Addr(raw))
}

#[test]
fn an_issued_cookie_is_eight_bytes_under_both_option_kinds() {
    for exp in [false, true] {
        let c = gen(&Key::new(K1), v4(10, 0, 0, 1), v4(10, 0, 0, 2), exp);
        assert_eq!(c.len(), crate::tcp_conn::fastopen::COOKIE_SIZE);
        assert_eq!(c.exp, exp, "the reply keeps the kind the exchange opened under");
        assert!(!c.is_request(), "an issued cookie is never read as a request");
    }
}

#[test]
fn the_cookie_is_the_little_endian_reading_of_the_hash_of_source_then_destination() {
    let src = v4(192, 0, 2, 1);
    let dst = v4(198, 51, 100, 7);
    let mut expect = [0u8; 8];
    expect[..4].copy_from_slice(&[192, 0, 2, 1]);
    expect[4..].copy_from_slice(&[198, 51, 100, 7]);
    let hash = siphash(&expect, &SipKey::from_bytes(&K1));
    assert_eq!(gen(&Key::new(K1), src, dst, false).as_bytes(), &hash.to_le_bytes());
}

#[test]
fn the_two_directions_of_one_connection_get_different_cookies() {
    let a = v4(10, 0, 0, 1);
    let b = v4(10, 0, 0, 2);
    assert_ne!(gen(&Key::new(K1), a, b, false).as_bytes(),
               gen(&Key::new(K1), b, a, false).as_bytes(),
               "source and destination are hashed in packet order, not as a set");
}

#[test]
fn ports_do_not_enter_the_cookie() {
    // Nothing but the addresses is hashed, which is why one cookie serves
    // every service on a host. Expressed as: the same address pair yields the
    // same cookie no matter how many times it is asked.
    let key = Key::new(K1);
    let first = gen(&key, v4(10, 0, 0, 1), v4(10, 0, 0, 2), false);
    let again = gen(&key, v4(10, 0, 0, 1), v4(10, 0, 0, 2), false);
    assert_eq!(first.as_bytes(), again.as_bytes());
}

#[test]
fn a_different_key_yields_a_different_cookie() {
    let src = v4(10, 0, 0, 1);
    let dst = v4(10, 0, 0, 2);
    assert_ne!(gen(&Key::new(K1), src, dst, false).as_bytes(),
               gen(&Key::new(K2), src, dst, false).as_bytes());
}

#[test]
fn an_ipv6_pair_hashes_thirty_two_bytes_in_the_same_order() {
    let src = v6(1);
    let dst = v6(2);
    let mut buf = [0u8; 32];
    if let (IpAddr::V6(s), IpAddr::V6(d)) = (src, dst) {
        buf[..16].copy_from_slice(&s.0);
        buf[16..].copy_from_slice(&d.0);
    }
    let hash = siphash(&buf, &SipKey::from_bytes(&K1));
    assert_eq!(gen(&Key::new(K1), src, dst, false).as_bytes(), &hash.to_le_bytes());
}

#[test]
fn a_mapped_pair_cannot_collide_with_the_native_ipv4_pair() {
    let native = gen(&Key::new(K1), v4(10, 0, 0, 1), v4(10, 0, 0, 2), false);
    let mapped = gen(&Key::new(K1),
        IpAddr::V6(Ipv6Addr::from_v4_mapped(Ipv4Addr::new(10, 0, 0, 1))),
        IpAddr::V6(Ipv6Addr::from_v4_mapped(Ipv4Addr::new(10, 0, 0, 2))), false);
    assert_ne!(native.as_bytes(), mapped.as_bytes(),
        "the two families hash different byte counts, so one key serves both");
}

#[test]
fn the_primary_key_verifies_what_it_minted() {
    let ctx = KeyCtx::new(Key::new(K1), None);
    let src = v4(10, 0, 0, 1);
    let dst = v4(10, 0, 0, 2);
    let c = gen(&ctx.primary, src, dst, false);
    assert_eq!(verify(&ctx, src, dst, &c), Some(KeyMatch::Primary));
}

#[test]
fn the_backup_key_still_verifies_after_a_rotation() {
    let rotated = KeyCtx::new(Key::new(K2), Some(Key::new(K1)));
    let src = v4(10, 0, 0, 1);
    let dst = v4(10, 0, 0, 2);
    let old = gen(&Key::new(K1), src, dst, false);
    assert_eq!(verify(&rotated, src, dst, &old), Some(KeyMatch::Backup),
        "a cookie handed out before the rotation keeps working");
    let new = gen(&Key::new(K2), src, dst, false);
    assert_eq!(verify(&rotated, src, dst, &new), Some(KeyMatch::Primary));
}

#[test]
fn a_rotation_that_dropped_the_backup_stops_believing_the_old_cookie() {
    let src = v4(10, 0, 0, 1);
    let dst = v4(10, 0, 0, 2);
    let old = gen(&Key::new(K1), src, dst, false);
    assert_eq!(verify(&KeyCtx::new(Key::new(K2), None), src, dst, &old), None);
}

#[test]
fn a_cookie_minted_for_another_address_pair_verifies_against_neither_key() {
    let ctx = KeyCtx::new(Key::new(K2), Some(Key::new(K1)));
    let elsewhere = gen(&ctx.primary, v4(203, 0, 113, 9), v4(10, 0, 0, 2), false);
    assert_eq!(verify(&ctx, v4(10, 0, 0, 1), v4(10, 0, 0, 2), &elsewhere), None,
        "the cookie names the host pair, so it does not travel to another one");
}

#[test]
fn a_cookie_of_any_other_permitted_length_names_no_key() {
    let ctx = KeyCtx::new(Key::new(K1), Some(Key::new(K2)));
    let src = v4(10, 0, 0, 1);
    let dst = v4(10, 0, 0, 2);
    let mine = gen(&ctx.primary, src, dst, false);
    // The option admits 4..=16; only the length this side issues can match,
    // even when the shorter value is a prefix of a cookie that would verify.
    for len in [4usize, 6, 10, 16] {
        let mut raw = [0u8; 16];
        raw[..mine.len()].copy_from_slice(mine.as_bytes());
        let other = crate::tcp_conn::fastopen::Cookie::new(&raw[..len], false)
            .expect("a permitted length");
        assert_eq!(verify(&ctx, src, dst, &other), None, "length {len} must not verify");
    }
}

#[test]
fn a_request_carries_no_cookie_and_verifies_as_nothing() {
    let ctx = KeyCtx::new(Key::new(K1), None);
    let request = crate::tcp_conn::fastopen::Cookie::request(false);
    assert_eq!(verify(&ctx, v4(10, 0, 0, 1), v4(10, 0, 0, 2), &request), None);
}
