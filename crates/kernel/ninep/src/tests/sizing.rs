// Transfer sizing and frame-size enforcement.

use crate::client::io::{readdir_size, transfer_size};
use crate::codec::Enc;
use crate::err::NpError;
use crate::uapi::limits;

#[test]
fn an_iounit_of_zero_means_no_server_limit_not_a_limit_of_zero() {
    // Taken literally, a zero iounit makes every read return nothing and the
    // caller loop forever on a file it can never finish.
    let msize = 8192u32;
    let envelope = msize as usize - limits::IOHDRSZ;
    assert_eq!(transfer_size(0, msize, usize::MAX), envelope);
    assert_eq!(transfer_size(0, msize, 100), 100);
    assert_ne!(transfer_size(0, msize, 100), 0);
}

#[test]
fn the_smallest_of_the_three_bounds_wins() {
    let msize = 8192u32;
    let envelope = msize as usize - limits::IOHDRSZ;
    // Server limit smallest.
    assert_eq!(transfer_size(512, msize, 100_000), 512);
    // Frame smallest.
    assert_eq!(transfer_size(1 << 20, msize, 100_000), envelope);
    // Caller's request smallest.
    assert_eq!(transfer_size(1 << 20, msize, 7), 7);
    assert_eq!(transfer_size(512, msize, 7), 7);
}

#[test]
fn the_envelope_is_subtracted_so_the_frame_always_fits() {
    let msize = limits::DEFAULT_MSIZE;
    let n = transfer_size(0, msize, usize::MAX);
    // Header plus the request's own fixed fields plus the payload must fit.
    assert!(n + limits::IOHDRSZ <= msize as usize);
    let mut e = Enc::request(crate::uapi::op::TWRITE, 0, msize);
    e.u32(1).unwrap();
    e.u64(0).unwrap();
    e.data(&alloc::vec![0u8; n]).unwrap();
    assert!(e.finish().is_ok());
}

#[test]
fn readdir_uses_its_own_larger_envelope() {
    let msize = 8192u32;
    assert_eq!(readdir_size(0, msize, usize::MAX), msize as usize - limits::READDIRHDRSZ);
    // Reusing the I/O envelope here would let the client ask for more than the
    // readdir reply frame can hold.
    assert!(readdir_size(0, msize, usize::MAX) <= transfer_size(0, msize, usize::MAX));
    assert_eq!(readdir_size(64, msize, usize::MAX), 64);
    assert_eq!(readdir_size(0, msize, 10), 10);
}

#[test]
fn a_tiny_frame_size_does_not_underflow_the_envelope() {
    // A frame smaller than the envelope would wrap to a colossal size and hand
    // the caller a length that overruns every buffer downstream.
    assert_eq!(transfer_size(0, 8, usize::MAX), 0);
    assert_eq!(readdir_size(0, 8, usize::MAX), 0);
}

#[test]
fn the_encoder_refuses_a_body_past_the_negotiated_frame_size() {
    let mut e = Enc::request(crate::uapi::op::TWRITE, 0, 32);
    assert!(e.raw(&[0u8; 20]).is_ok());
    assert_eq!(e.headroom(), 32 - 27);
    assert_eq!(e.raw(&[0u8; 20]).unwrap_err(), NpError::MsgTooLarge);
    // The failed append left the message intact rather than half-written.
    assert_eq!(e.len(), 27);
    assert_eq!(e.finish().unwrap().len(), 27);
}

#[test]
fn a_name_longer_than_the_length_prefix_is_refused() {
    let mut e = Enc::request(0, 0, u32::MAX);
    let big = alloc::vec![b'a'; u16::MAX as usize + 1];
    assert_eq!(e.bytes_str(&big).unwrap_err(), NpError::NameTooLong);
    let ok = alloc::vec![b'a'; u16::MAX as usize];
    assert!(e.bytes_str(&ok).is_ok());
}

#[test]
fn the_size_field_is_patched_to_the_final_length() {
    let mut e = Enc::request(crate::uapi::op::TREAD, 5, 4096);
    e.u32(1).unwrap();
    e.u64(2).unwrap();
    e.u32(3).unwrap();
    let f = e.finish().unwrap();
    assert_eq!(u32::from_le_bytes([f[0], f[1], f[2], f[3]]) as usize, f.len());
    assert_eq!(f.len(), limits::HDRSZ + 16);
}
