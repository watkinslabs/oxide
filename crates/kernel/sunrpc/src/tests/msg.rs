// Call and reply headers, every status branch.

extern crate alloc;
use alloc::vec;

use crate::auth::{AuthSys, Cred};
use crate::err::RpcError;
use crate::msg::{decode_reply_header, encode_call, peek_xid, Proc};
use crate::uapi::{accept_stat, auth_stat, msg_type, program, reply_stat, RPC_VERSION};
use crate::xdr::Dec;
use super::server::{reply_accept_err, reply_auth_err, reply_bad_verf, reply_ok,
                    reply_rpc_mismatch, decode_call};

const P: Proc = Proc { prog: program::NFS, vers: 3, proc_num: 6 };

#[test]
fn a_call_header_carries_the_six_fixed_words_in_order() {
    let msg = encode_call(0x1111_2222, P, &Cred::Null, b"", 4096).unwrap();
    let mut d = Dec::new(&msg);
    assert_eq!(d.u32().unwrap(), 0x1111_2222);
    assert_eq!(d.u32().unwrap(), msg_type::CALL);
    assert_eq!(d.u32().unwrap(), RPC_VERSION);
    assert_eq!(d.u32().unwrap(), program::NFS);
    assert_eq!(d.u32().unwrap(), 3);
    assert_eq!(d.u32().unwrap(), 6);
}

#[test]
fn a_call_round_trips_through_an_independent_server_side_parse() {
    let cred = Cred::Sys(AuthSys::new("client", 500, 500));
    let msg = encode_call(42, P, &cred, b"\x00\x00\x00\x09", 4096).unwrap();
    let c = decode_call(&msg).unwrap();
    assert_eq!(c.xid, 42);
    assert_eq!(c.proc_, P);
    assert_eq!(c.cred, cred);
    assert_eq!(c.args, b"\x00\x00\x00\x09".to_vec());
}

#[test]
fn a_call_too_large_for_the_transport_is_refused_not_truncated() {
    let big = vec![0u8; 4096];
    assert_eq!(encode_call(1, P, &Cred::Null, &big, 64), Err(RpcError::MsgTooLarge));
}

#[test]
fn peek_xid_reads_the_first_word_without_decoding() {
    assert_eq!(peek_xid(&[0, 0, 0, 9, 1, 2]), Some(9));
    assert_eq!(peek_xid(&[0, 0]), None);
}

fn hdr(record: &[u8], xid: u32) -> Result<usize, RpcError> {
    let mut d = Dec::new(record);
    decode_reply_header(&mut d, xid)?;
    Ok(d.pos())
}

#[test]
fn an_accepted_success_positions_the_cursor_at_the_results() {
    let r = reply_ok(7, b"\xDE\xAD\xBE\xEF");
    let at = hdr(&r, 7).unwrap();
    assert_eq!(&r[at..], b"\xDE\xAD\xBE\xEF");
}

#[test]
fn a_reply_for_a_different_call_is_refused() {
    // This is the failure with no downstream symptom: the bytes decode, the
    // sizes are plausible, and one operation's results reach another
    // operation's caller. Nothing but this check can catch it.
    let r = reply_ok(7, b"\x00\x00\x00\x00");
    assert_eq!(hdr(&r, 8), Err(RpcError::XidMismatch));
}

#[test]
fn a_reply_whose_length_is_not_a_multiple_of_four_is_unparsable() {
    let mut r = reply_ok(1, b"");
    r.push(0);
    assert_eq!(hdr(&r, 1), Err(RpcError::Unparsable));
}

#[test]
fn a_message_marked_as_a_call_is_not_a_reply() {
    let mut r = reply_ok(1, b"");
    r[7] = msg_type::CALL as u8;
    assert_eq!(hdr(&r, 1), Err(RpcError::Unparsable));
}

#[test]
fn each_accept_status_maps_to_its_own_error() {
    let cases: &[(u32, RpcError)] = &[
        (accept_stat::PROG_UNAVAIL, RpcError::ProgUnavail),
        (accept_stat::PROC_UNAVAIL, RpcError::ProcUnavail),
        (accept_stat::GARBAGE_ARGS, RpcError::GarbageArgs),
        (accept_stat::SYSTEM_ERR, RpcError::SystemErr),
    ];
    for (stat, want) in cases {
        let r = reply_accept_err(3, *stat, &[]);
        assert_eq!(hdr(&r, 3), Err(*want), "accept_stat {stat}");
    }
}

#[test]
fn a_program_mismatch_carries_the_servers_version_range() {
    let r = reply_accept_err(3, accept_stat::PROG_MISMATCH, &[2, 4]);
    assert_eq!(hdr(&r, 3), Err(RpcError::ProgMismatch { low: 2, high: 4 }));
}

#[test]
fn an_unknown_accept_status_is_unparsable_rather_than_a_guess() {
    let r = reply_accept_err(3, 99, &[]);
    assert_eq!(hdr(&r, 3), Err(RpcError::Unparsable));
}

#[test]
fn a_denied_reply_reports_the_auth_status_verbatim() {
    for a in [auth_stat::BADCRED, auth_stat::REJECTEDCRED, auth_stat::TOOWEAK] {
        let r = reply_auth_err(5, a);
        assert_eq!(hdr(&r, 5), Err(RpcError::AuthError(a)));
    }
}

#[test]
fn an_rpc_version_mismatch_carries_the_servers_range() {
    let r = reply_rpc_mismatch(5, 2, 2);
    assert_eq!(hdr(&r, 5), Err(RpcError::RpcMismatch { low: 2, high: 2 }));
}

#[test]
fn a_denied_reply_is_read_without_a_verifier() {
    // A denied reply has NO verifier — the reject status follows the reply
    // status directly. A decoder that consumed a verifier here would read the
    // reject status and its detail as the verifier's flavour and length, and
    // report the wrong failure entirely.
    let r = reply_auth_err(5, auth_stat::REJECTEDCRED);
    assert_eq!(r.len(), 20);
    assert_eq!(hdr(&r, 5), Err(RpcError::AuthError(auth_stat::REJECTEDCRED)));
}

#[test]
fn an_unacceptable_reply_verifier_is_rejected_before_the_status_is_read() {
    let r = reply_bad_verf(5);
    assert_eq!(hdr(&r, 5), Err(RpcError::BadVerifier));
}

#[test]
fn an_unknown_reply_status_word_is_unparsable() {
    let mut r = reply_ok(1, b"");
    r[11] = 9;
    assert_eq!(hdr(&r, 1), Err(RpcError::Unparsable));
    assert_eq!(reply_stat::MSG_ACCEPTED, 0);
}
