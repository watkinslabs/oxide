// Object, sealing and non-volatile commands: framing only, asserted byte for
// byte, plus the response parsers' bounds.

use alloc::vec::Vec;

use super::support::{hex, response};
use crate::codec::objects;
use crate::codec::{CodecError, Response};
use crate::uapi::{TPM2_RH_OWNER, TPM2_RH_PLATFORM, TPM2_ST_NO_SESSIONS, TPM2_ST_SESSIONS};

/// A password authorisation area on the wire: a four-byte size field and
/// the nine bytes it counts.
const AUTH_HEX: &str = "00000009400000090000000000";

#[test]
fn read_public_and_test_result_carry_no_authorisation() {
    assert_eq!(objects::read_public(0x8000_0001).unwrap(), hex("80010000000e0000017380000001"));
    assert_eq!(objects::get_test_result().unwrap(), hex("80010000000a0000017c"));
    assert_eq!(objects::nv_read_public(0x0180_0001).unwrap(), hex("80010000000e0000016901800001"));
}

#[test]
fn unseal_names_one_handle_and_authorises_it() {
    let got = objects::unseal(0x8000_0002).unwrap();
    let want = hex(&alloc::format!("8002{:08x}0000015e80000002{}", 10 + 4 + 13, AUTH_HEX));
    assert_eq!(got, want);
}

#[test]
fn nv_read_names_the_authorising_handle_before_the_index() {
    let got = objects::nv_read(TPM2_RH_OWNER, 0x0180_0001, 32, 4).unwrap();
    let want = hex(&alloc::format!("8002{:08x}0000014e4000000101800001{}00200004", 10 + 8 + 13 + 4, AUTH_HEX));
    assert_eq!(got, want);
}

#[test]
fn nv_write_length_prefixes_its_data() {
    let got = objects::nv_write(TPM2_RH_OWNER, 0x0180_0001, &[0xAA; 4], 8).unwrap();
    let want = hex(&alloc::format!("8002{:08x}000001374000000101800001{}0004aaaaaaaa0008", 10 + 8 + 13 + 2 + 4 + 2, AUTH_HEX));
    assert_eq!(got, want);
}

#[test]
fn load_length_prefixes_both_halves_of_the_object() {
    let priv_blob = [0x11u8; 3];
    let pub_blob = [0x22u8; 2];
    let got = objects::load(0x8000_0001, &priv_blob, &pub_blob).unwrap();
    let mut want = hex(&alloc::format!("8002{:08x}0000015780000001{}", 10 + 4 + 13 + 2 + 3 + 2 + 2, AUTH_HEX));
    want.extend_from_slice(&3u16.to_be_bytes());
    want.extend_from_slice(&priv_blob);
    want.extend_from_slice(&2u16.to_be_bytes());
    want.extend_from_slice(&pub_blob);
    assert_eq!(got, want);
    assert_eq!(objects::load(0x8000_0001, &[], &pub_blob), Err(CodecError::BadArgument("empty object blob")));
    assert_eq!(objects::load(0x8000_0001, &priv_blob, &[]), Err(CodecError::BadArgument("empty object blob")));
}

#[test]
fn create_primary_frames_its_four_operands_in_order() {
    let got = objects::create_primary(TPM2_RH_PLATFORM, &[1], &[2, 2], &[], &[0, 0, 0, 0]).unwrap();
    // handle, auth, then three sized buffers and the raw selection list
    let body = &got[10..];
    assert_eq!(&body[..4], &TPM2_RH_PLATFORM.to_be_bytes());
    let after_auth = 4 + 13;
    assert_eq!(&body[after_auth..after_auth + 3], &[0x00, 0x01, 0x01]);
    assert_eq!(&body[after_auth + 3..after_auth + 7], &[0x00, 0x02, 0x02, 0x02]);
    assert_eq!(&body[after_auth + 7..after_auth + 9], &[0x00, 0x00]);
    assert_eq!(&body[after_auth + 9..], &[0, 0, 0, 0]);
    assert_eq!(&got[2..6], &(got.len() as u32).to_be_bytes());
}

#[test]
fn hierarchy_change_auth_length_prefixes_the_new_value() {
    let got = objects::hierarchy_change_auth(TPM2_RH_OWNER, b"pw").unwrap();
    let want = hex(&alloc::format!("8002{:08x}0000012940000001{}0002{}", 10 + 4 + 13 + 2 + 2, AUTH_HEX, "7077"));
    assert_eq!(got, want);
}

#[test]
fn unseal_and_nv_read_responses_are_bounded_by_their_own_length_field() {
    let mut body = Vec::new();
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&[1, 2, 3, 4]);
    let r = response(TPM2_ST_NO_SESSIONS, 0, &body);
    assert_eq!(objects::parse_unseal(&Response::parse(&r).unwrap()).unwrap(), &[1, 2, 3, 4]);
    assert_eq!(objects::parse_nv_read(&Response::parse(&r).unwrap()).unwrap(), &[1, 2, 3, 4]);

    let mut lying = Vec::new();
    lying.extend_from_slice(&999u16.to_be_bytes());
    lying.extend_from_slice(&[1, 2]);
    let r = response(TPM2_ST_NO_SESSIONS, 0, &lying);
    assert_eq!(objects::parse_unseal(&Response::parse(&r).unwrap()).err(),
               Some(CodecError::Truncated { need: 999, have: 2 }));
}

#[test]
fn a_session_tagged_unseal_response_skips_its_parameter_size() {
    let mut body = Vec::new();
    body.extend_from_slice(&6u32.to_be_bytes());
    body.extend_from_slice(&4u16.to_be_bytes());
    body.extend_from_slice(&[5, 6, 7, 8]);
    let r = response(TPM2_ST_SESSIONS, 0, &body);
    assert_eq!(objects::parse_unseal(&Response::parse(&r).unwrap()).unwrap(), &[5, 6, 7, 8]);
}

#[test]
fn a_self_test_result_carries_its_own_code() {
    let mut body = Vec::new();
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&[0xDE, 0xAD]);
    body.extend_from_slice(&0u32.to_be_bytes());
    let r = response(TPM2_ST_NO_SESSIONS, 0, &body);
    let out = objects::parse_get_test_result(&Response::parse(&r).unwrap()).unwrap();
    assert_eq!(out.data, &[0xDE, 0xAD]);
    assert_eq!(out.test_result, 0);
}
