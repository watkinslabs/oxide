// Error replies: numeric in `.L`, string (plus optional number) elsewhere.

use vfs::VfsError;

use crate::client::rpc::decode_reply;
use crate::codec::{Dialect, Enc};
use crate::err::{errstr_to_errno, rerror_errno, NpError};
use crate::uapi::op;

fn frame(ty: u8, body: impl FnOnce(&mut Enc)) -> alloc::vec::Vec<u8> {
    let mut e = Enc::request(ty, 1, 4096);
    body(&mut e);
    e.finish().unwrap()
}

#[test]
fn a_dotl_server_reports_a_numeric_errno() {
    let f = frame(op::RLERROR, |e| { e.u32(2).unwrap(); });
    assert_eq!(decode_reply(op::TWALK, Dialect::DotL, f).unwrap_err(), NpError::Server(2));
}

#[test]
fn a_server_errno_survives_translation_rather_than_collapsing_to_eio() {
    // Folding a server's answer into a generic I/O error both hides what it
    // said and makes `ESTALE` — the one errno the revalidating re-walk exists
    // to act on — unreachable.
    for (code, want) in [(1, VfsError::Eperm), (2, VfsError::Enoent), (13, VfsError::Eacces),
                         (17, VfsError::Eexist), (20, VfsError::Enotdir), (21, VfsError::Eisdir),
                         (28, VfsError::Enospc), (39, VfsError::Enotempty),
                         (95, VfsError::Eopnotsupp), (116, VfsError::Estale)] {
        assert_eq!(VfsError::from(NpError::Server(code)), want, "errno {code}");
    }
    assert_ne!(VfsError::from(NpError::Server(116)), VfsError::from(NpError::Server(5)));
}

#[test]
fn an_out_of_range_server_errno_is_a_protocol_fault_not_an_error_code() {
    // A code above the errno range could be reinterpreted by a caller as a
    // successful large result.
    assert_eq!(NpError::from_server(4096), NpError::BadMessage);
    assert_eq!(NpError::from_server(u32::MAX), NpError::BadMessage);
    // An error reply with no error is equally meaningless.
    assert_eq!(NpError::from_server(0), NpError::BadMessage);
    assert_eq!(NpError::from_server(4095), NpError::Server(4095));
}

#[test]
fn a_legacy_server_reports_a_string_and_it_is_resolved() {
    let f = frame(op::RERROR, |e| { e.string("No such file or directory").unwrap(); });
    assert_eq!(decode_reply(op::TWALK, Dialect::Legacy, f).unwrap_err(), NpError::Server(2));
    let f = frame(op::RERROR, |e| { e.string("Permission denied").unwrap(); });
    assert_eq!(decode_reply(op::TWALK, Dialect::Legacy, f).unwrap_err(), NpError::Server(13));
}

#[test]
fn a_legacy_reply_is_not_read_for_a_numeric_code_that_is_not_there() {
    // Base 9P2000 appends nothing after the string. Reading four bytes anyway
    // turns a legitimate error into a framing fault.
    let f = frame(op::RERROR, |e| { e.string("File exists").unwrap(); });
    assert_eq!(decode_reply(op::TWALK, Dialect::Legacy, f).unwrap_err(), NpError::Server(17));
}

#[test]
fn a_dotu_numeric_code_overrides_the_string() {
    let f = frame(op::RERROR, |e| { e.string("something odd").unwrap(); e.u32(28).unwrap(); });
    assert_eq!(decode_reply(op::TWALK, Dialect::DotU, f).unwrap_err(), NpError::Server(28));
}

#[test]
fn a_dotu_code_outside_the_posix_range_falls_back_to_the_string() {
    // Codes at or above 512 are Plan 9 error numbers in a different namespace
    // and must not be handed to POSIX code as an errno.
    assert_eq!(rerror_errno("Is a directory", Some(600)), NpError::Server(21));
    assert_eq!(rerror_errno("Is a directory", Some(512)), NpError::Server(21));
    assert_eq!(rerror_errno("Is a directory", Some(511)), NpError::Server(511));
}

#[test]
fn an_unrecognised_error_string_is_still_an_error() {
    assert_eq!(errstr_to_errno("the server had a bad day"), 5);
    assert_ne!(errstr_to_errno("the server had a bad day"), 0);
    assert_eq!(rerror_errno("who knows", None), NpError::Server(5));
}

#[test]
fn a_reply_of_the_wrong_type_is_rejected_rather_than_decoded() {
    // Decoding a mismatched body yields plausible-looking fields that reach the
    // VFS as real metadata.
    let f = frame(op::reply_of(op::TSTATFS), |e| { e.u32(0).unwrap(); });
    assert_eq!(decode_reply(op::TWALK, Dialect::DotL, f).unwrap_err(), NpError::UnexpectedReply);
}

#[test]
fn the_expected_reply_type_is_accepted() {
    let f = frame(op::reply_of(op::TWALK), |e| { e.u16(0).unwrap(); });
    let r = decode_reply(op::TWALK, Dialect::DotL, f).unwrap();
    assert_eq!(r.ty, op::reply_of(op::TWALK));
    assert_eq!(r.body().len(), 2);
}

#[test]
fn protocol_faults_map_to_distinct_vfs_errors() {
    assert_eq!(VfsError::from(NpError::BadMessage), VfsError::Eproto);
    assert_eq!(VfsError::from(NpError::MsgTooLarge), VfsError::Emsgsize);
    assert_eq!(VfsError::from(NpError::NameTooLong), VfsError::Enametoolong);
    assert_eq!(VfsError::from(NpError::Interrupted), VfsError::Erestartsys);
    assert_eq!(VfsError::from(NpError::NoMemory), VfsError::Enomem);
    assert_eq!(VfsError::from(NpError::Disconnected), VfsError::Eio);
}
