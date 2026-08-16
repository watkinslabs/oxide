// Device-file transaction model. One command in flight, one response, read
// once.

use alloc::vec;
use alloc::vec::Vec;

use super::support::response;
use crate::chip::{DevError, DevFile, Readiness};
use crate::limits::TPM_BUFSIZE;
use crate::uapi::TPM2_ST_NO_SESSIONS;

fn cmd(len: usize) -> Vec<u8> {
    let mut v = vec![0x80, 0x01];
    v.extend_from_slice(&(len as u32).to_be_bytes());
    v.extend_from_slice(&0x0000_017Bu32.to_be_bytes());
    v.resize(len, 0);
    v
}

#[test]
fn a_command_is_accepted_whole() {
    let mut f = DevFile::new();
    let c = cmd(12);
    assert_eq!(f.write(&c).unwrap(), 12);
    assert_eq!(f.staged(12), c.as_slice());
}

#[test]
fn a_second_command_before_the_response_is_read_is_refused() {
    let mut f = DevFile::new();
    f.write(&cmd(12)).unwrap();
    f.complete(&response(TPM2_ST_NO_SESSIONS, 0, &[1, 2, 3, 4])).unwrap();
    assert_eq!(f.write(&cmd(12)), Err(DevError::Busy));
    let mut out = [0u8; 64];
    f.read(&mut out);
    assert!(f.write(&cmd(12)).is_ok());
}

#[test]
fn a_queued_command_blocks_the_next_write() {
    let mut f = DevFile::new();
    f.write(&cmd(12)).unwrap();
    f.enqueue();
    assert_eq!(f.write(&cmd(12)), Err(DevError::Busy));
    f.complete(&response(TPM2_ST_NO_SESSIONS, 0, &[])).unwrap();
    let mut out = [0u8; 64];
    f.read(&mut out);
    assert!(f.write(&cmd(12)).is_ok());
}

#[test]
fn a_command_shorter_than_its_own_length_field_is_refused() {
    let mut f = DevFile::new();
    let mut c = cmd(12);
    c[2..6].copy_from_slice(&64u32.to_be_bytes());
    assert_eq!(f.write(&c), Err(DevError::Inval));
    for n in 0..6 { assert_eq!(f.write(&vec![0u8; n]), Err(DevError::Inval), "{n}-byte write"); }
    assert_eq!(f.write(&vec![0u8; TPM_BUFSIZE + 1]), Err(DevError::TooBig));
}

#[test]
fn a_command_longer_than_its_length_field_is_accepted() {
    // A trailing partial write is not the device's problem: the declared
    // length is what will be transmitted.
    let mut f = DevFile::new();
    let mut c = cmd(12);
    c.extend_from_slice(&[0; 4]);
    assert_eq!(f.write(&c).unwrap(), 16);
}

#[test]
fn a_response_is_handed_over_once() {
    let mut f = DevFile::new();
    let r = response(TPM2_ST_NO_SESSIONS, 0, &[9, 9, 9, 9]);
    f.write(&cmd(12)).unwrap();
    f.complete(&r).unwrap();
    let mut out = [0u8; 64];
    let n = f.read(&mut out);
    assert_eq!(&out[..n], r.as_slice());
    assert_eq!(f.response_length(), 0);
    assert_eq!(f.read(&mut out), 0);
}

#[test]
fn partial_reads_resume_where_they_stopped_and_never_repeat_bytes() {
    let mut f = DevFile::new();
    let r = response(TPM2_ST_NO_SESSIONS, 0, &[1, 2, 3, 4, 5, 6]);
    f.write(&cmd(12)).unwrap();
    f.complete(&r).unwrap();
    let mut got = Vec::new();
    let mut out = [0u8; 5];
    loop {
        let n = f.read(&mut out);
        if n == 0 { break; }
        got.extend_from_slice(&out[..n]);
    }
    assert_eq!(got, r);
}

#[test]
fn readiness_follows_the_parked_response() {
    let mut f = DevFile::new();
    assert_eq!(f.readiness(), Readiness::Writable);
    f.write(&cmd(12)).unwrap();
    assert_eq!(f.readiness(), Readiness::Writable);
    f.complete(&response(TPM2_ST_NO_SESSIONS, 0, &[1])).unwrap();
    assert_eq!(f.readiness(), Readiness::Readable);
    let mut out = [0u8; 64];
    f.read(&mut out);
    assert_eq!(f.readiness(), Readiness::Writable);
}

#[test]
fn an_uncollected_response_is_dropped_and_zeroed() {
    let mut f = DevFile::new();
    f.write(&cmd(12)).unwrap();
    f.complete(&response(TPM2_ST_NO_SESSIONS, 0, &[7; 8])).unwrap();
    f.expire();
    assert_eq!(f.response_length(), 0);
    assert_eq!(f.readiness(), Readiness::Writable);
    assert!(f.staged(TPM_BUFSIZE).iter().all(|b| *b == 0));
    assert!(f.write(&cmd(12)).is_ok());
}

#[test]
fn a_failed_transport_leaves_nothing_to_read() {
    let mut f = DevFile::new();
    f.write(&cmd(12)).unwrap();
    f.enqueue();
    f.fail();
    assert_eq!(f.response_length(), 0);
    assert_eq!(f.readiness(), Readiness::Writable);
    assert!(f.write(&cmd(12)).is_ok());
}

#[test]
fn release_clears_the_file() {
    let mut f = DevFile::new();
    f.write(&cmd(12)).unwrap();
    f.complete(&response(TPM2_ST_NO_SESSIONS, 0, &[7; 8])).unwrap();
    f.release();
    assert_eq!(f.response_length(), 0);
    assert!(f.staged(TPM_BUFSIZE).iter().all(|b| *b == 0));
}
