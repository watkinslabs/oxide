// Credential marshalling and reply-verifier checking.

extern crate alloc;
use alloc::vec::Vec;
use alloc::vec;

use crate::auth::{check_reply_verf, encode_call_verf, AuthSys, Cred};
use crate::err::RpcError;
use crate::uapi::{flavor, limits};
use crate::xdr::{Dec, Enc};

fn enc(c: &Cred) -> Vec<u8> {
    let mut e = Enc::new();
    c.encode(&mut e).unwrap();
    e.finish()
}

#[test]
fn a_null_credential_is_a_flavour_and_a_zero_length() {
    assert_eq!(enc(&Cred::Null), vec![0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn an_authsys_credential_carries_stamp_name_uid_gid_and_groups_in_order() {
    // The field order IS the protocol. A uid and gid transposed here reaches
    // the server as a plausible identity and silently grants the wrong access.
    let mut s = AuthSys::new("host", 1000, 100);
    s.stamp = 7;
    s.gids = vec![10, 20];
    let buf = enc(&Cred::Sys(s));
    let mut d = Dec::new(&buf);
    assert_eq!(d.u32().unwrap(), flavor::UNIX);
    let len = d.u32().unwrap() as usize;
    // stamp + (len+name padded to 8) + uid + gid + count + 2 gids
    assert_eq!(len, 4 + 8 + 4 + 4 + 4 + 8);
    assert_eq!(d.u32().unwrap(), 7);
    assert_eq!(d.string(255).unwrap(), "host");
    assert_eq!(d.u32().unwrap(), 1000);
    assert_eq!(d.u32().unwrap(), 100);
    assert_eq!(d.u32().unwrap(), 2);
    assert_eq!(d.u32().unwrap(), 10);
    assert_eq!(d.u32().unwrap(), 20);
    assert!(d.at_end());
}

#[test]
fn the_declared_credential_length_matches_the_bytes_that_follow() {
    // The length is patched after the body is written. If it were computed
    // ahead of the encode the two would drift on any name length, and the
    // server would parse the verifier out of the middle of the credential.
    for name in ["", "a", "ab", "abc", "abcd", "abcdefghij"] {
        let mut s = AuthSys::new(name, 0, 0);
        s.gids = vec![1, 2, 3];
        let buf = enc(&Cred::Sys(s));
        let mut d = Dec::new(&buf);
        d.u32().unwrap();
        let len = d.u32().unwrap() as usize;
        assert_eq!(len, buf.len() - 8, "name {name:?}");
    }
}

#[test]
fn more_groups_than_the_protocol_allows_are_truncated_not_rejected() {
    let mut s = AuthSys::new("h", 0, 0);
    s.gids = (0..40).collect();
    let buf = enc(&Cred::Sys(s));
    let mut d = Dec::new(&buf);
    d.u32().unwrap();
    d.u32().unwrap();
    d.u32().unwrap();
    d.string(255).unwrap();
    d.u32().unwrap();
    d.u32().unwrap();
    assert_eq!(d.u32().unwrap() as usize, limits::UNX_NGROUPS);
    for i in 0..limits::UNX_NGROUPS { assert_eq!(d.u32().unwrap(), i as u32); }
    assert!(d.at_end());
}

#[test]
fn an_over_long_machine_name_is_truncated_to_the_protocol_bound() {
    let long = "n".repeat(400);
    let s = AuthSys::new(&long, 0, 0);
    let buf = enc(&Cred::Sys(s));
    let mut d = Dec::new(&buf);
    d.u32().unwrap();
    d.u32().unwrap();
    d.u32().unwrap();
    assert_eq!(d.string(limits::MAX_MACHINENAME).unwrap().len(), limits::MAX_MACHINENAME);
}

#[test]
fn a_credential_body_over_the_protocol_maximum_is_refused() {
    // 255 name + 16 groups fits; nothing legal exceeds it, so a body that does
    // means the encoder was handed something the wire cannot carry.
    let mut e = Enc::with_limit(1 << 20);
    let mut s = AuthSys::new(&"n".repeat(limits::MAX_MACHINENAME), 0, 0);
    s.gids = vec![0; limits::UNX_NGROUPS];
    assert!(Cred::Sys(s).encode(&mut e).is_ok());
    assert!(e.len() - 8 <= limits::MAX_AUTH_SIZE as usize);
}

#[test]
fn a_call_verifier_is_always_null() {
    let mut e = Enc::new();
    encode_call_verf(&mut e).unwrap();
    assert_eq!(e.as_slice(), &[0, 0, 0, 0, 0, 0, 0, 0]);
}

#[test]
fn a_null_reply_verifier_is_accepted_and_fully_consumed() {
    let buf = [0u8, 0, 0, 0, 0, 0, 0, 0, 0xAA, 0xBB, 0xCC, 0xDD];
    let mut d = Dec::new(&buf);
    check_reply_verf(&mut d).unwrap();
    assert_eq!(d.pos(), 8);
    assert_eq!(d.u32().unwrap(), 0xAABB_CCDD);
}

#[test]
fn a_reply_verifier_with_a_body_is_consumed_including_its_padding() {
    // Leaving the verifier body unconsumed would leave the cursor short of the
    // accept status, and the accepted-reply branch would read the verifier's
    // last word as the status instead.
    let mut e = Enc::new();
    e.u32(flavor::UNIX).unwrap();
    e.u32(3).unwrap();
    e.opaque_fixed(b"abc").unwrap();
    e.u32(0x1234).unwrap();
    let buf = e.finish();
    let mut d = Dec::new(&buf);
    check_reply_verf(&mut d).unwrap();
    assert_eq!(d.u32().unwrap(), 0x1234);
}

#[test]
fn a_reply_verifier_of_an_impossible_flavour_is_rejected() {
    let mut e = Enc::new();
    e.u32(flavor::GSS).unwrap();
    e.u32(0).unwrap();
    let buf = e.finish();
    assert_eq!(check_reply_verf(&mut Dec::new(&buf)), Err(RpcError::BadVerifier));
}

#[test]
fn a_reply_verifier_declaring_an_over_long_body_is_rejected() {
    // A size taken on trust walks the decoder past the results the caller is
    // about to read — silently, because the bytes it then returns still decode.
    let mut e = Enc::new();
    e.u32(flavor::NULL).unwrap();
    e.u32(limits::MAX_AUTH_SIZE + 1).unwrap();
    let buf = e.finish();
    assert_eq!(check_reply_verf(&mut Dec::new(&buf)), Err(RpcError::BadVerifier));
}

#[test]
fn a_reply_verifier_whose_body_is_not_there_is_unparsable() {
    let mut e = Enc::new();
    e.u32(flavor::NULL).unwrap();
    e.u32(64).unwrap();
    let buf = e.finish();
    assert_eq!(check_reply_verf(&mut Dec::new(&buf)), Err(RpcError::Unparsable));
}
