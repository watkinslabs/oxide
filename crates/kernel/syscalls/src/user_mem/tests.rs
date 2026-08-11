use super::copy::*;
use super::pod::*;

use syscall::errno::Errno;

fn addr_of(b: &[u8]) -> u64 { b.as_ptr() as u64 }

#[test]
fn every_scalar_width_round_trips() {
    let buf = [0u8; 32];
    let a = addr_of(&buf);
    assert_eq!(put_u8(a, 0xa5), Ok(()));
    assert_eq!(put_bytes(a + 1, &0x1234u16.to_ne_bytes()), Ok(()));
    assert_eq!(put_i16(a + 3, -3), Ok(()));
    assert_eq!(put_u32(a + 5, 0xdead_beef), Ok(()));
    assert_eq!(put_i32(a + 9, -7), Ok(()));
    assert_eq!(put_u64(a + 13, 0x0102_0304_0506_0708), Ok(()));
    assert_eq!(put_i64(a + 21, -9), Ok(()));
    assert_eq!(get_u8(a), Ok(0xa5));
    assert_eq!(get_i8(a), Ok(-91));
    assert_eq!(get_u16(a + 1), Ok(0x1234));
    assert_eq!(get_i16(a + 3), Ok(-3));
    assert_eq!(get_u32(a + 5), Ok(0xdead_beef));
    assert_eq!(get_i32(a + 9), Ok(-7));
    assert_eq!(get_u64(a + 13), Ok(0x0102_0304_0506_0708));
    assert_eq!(get_i64(a + 21), Ok(-9));
}

/// The offsets a slot reads are struct field offsets, not alignment promises:
/// `struct pollfd`'s `revents` sits at +6 and a `timespec` inside a packed
/// argument block can start anywhere. A typed dereference assumes alignment;
/// these must not.
#[test]
fn an_unaligned_field_round_trips() {
    let buf = [0u8; 24];
    let a = addr_of(&buf) + 1;
    assert_eq!(put_i64(a, i64::MIN), Ok(()));
    assert_eq!(get_i64(a), Ok(i64::MIN));
    assert_eq!(put_u32(a + 9, u32::MAX), Ok(()));
    assert_eq!(get_u32(a + 9), Ok(u32::MAX));
}

#[test]
fn a_run_length_transfer_round_trips() {
    let buf = [0u8; 16];
    let a = addr_of(&buf);
    assert_eq!(put_bytes(a, b"oxide-kernel"), Ok(()));
    let mut out = [0u8; 12];
    assert_eq!(get_into(a, &mut out), Ok(()));
    assert_eq!(&out, b"oxide-kernel");
    assert_eq!(get_bytes::<5>(a), Ok(*b"oxide"));
}

#[test]
fn a_null_address_faults_in_both_directions() {
    assert_eq!(get_u32(0), Err(Errno::Efault));
    assert_eq!(put_u32(0, 1), Err(Errno::Efault));
    assert_eq!(get_u64(0), Err(Errno::Efault));
    assert_eq!(put_i64(0, 1), Err(Errno::Efault));
    let mut dst = [0u8; 4];
    assert_eq!(get_into(0, &mut dst), Err(Errno::Efault));
    assert_eq!(put_bytes(0, &dst), Err(Errno::Efault));
}

/// The whole point of routing through the fault-recoverable usercopy: an
/// address outside the user window answers EFAULT instead of dereferencing.
#[test]
fn an_address_outside_the_user_window_faults() {
    assert_eq!(get_u32(hal::USER_VA_END), Err(Errno::Efault));
    assert_eq!(put_u32(hal::USER_VA_END, 1), Err(Errno::Efault));
    // A span that STARTS inside and runs past the end is rejected whole.
    assert_eq!(get_u64(hal::USER_VA_END - 4), Err(Errno::Efault));
    assert_eq!(put_u64(hal::USER_VA_END - 4, 1), Err(Errno::Efault));
    // And one whose length arithmetic would wrap.
    assert_eq!(get_bytes::<8>(u64::MAX - 1), Err(Errno::Efault));
}

/// A short read must not leave the caller's stack copy holding whatever was
/// there before — the usercopy zeroes the tail it could not fill.
#[test]
fn a_faulting_fetch_zeroes_the_destination_tail() {
    let mut dst = [0xffu8; 8];
    assert_eq!(get_into(0, &mut dst), Err(Errno::Efault));
    assert_eq!(dst, [0u8; 8]);
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Rec { a: u32, b: u64, c: i8 }
// SAFETY: repr(C) integer fields only; every byte pattern is a valid value.
unsafe impl UserPod for Rec {}

#[test]
fn a_whole_record_round_trips_and_faults() {
    let buf = [0u8; 32];
    let a = addr_of(&buf);
    let r = Rec { a: 0x1122_3344, b: 0x5566_7788_99aa_bbcc, c: -5 };
    assert_eq!(put_pod(a, r), Ok(()));
    assert_eq!(get_pod::<Rec>(a), Ok(r));
    assert_eq!(get_pod::<Rec>(0), Err(Errno::Efault));
    assert_eq!(put_pod(0, r), Err(Errno::Efault));
}

/// The i64 form a slot returns directly is the same errno the helpers answer.
#[test]
fn the_i64_efault_matches_the_errno() {
    assert_eq!(EFAULT, -(Errno::Efault.as_i32() as i64));
}
