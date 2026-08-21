// A range check that passes is not an address that can be touched. Each of
// these drives the real `uaccess` copy: against a live buffer for the layout,
// and against addresses the copy must refuse for the errno.

use super::*;

/// The lowest address in the kernel half. The copy refuses it, which is the
/// outcome every converted call site must produce instead of dereferencing it.
const KERNEL_SIDE: u64 = hal::USER_VA_END;

#[test]
fn the_scalar_helpers_round_trip_through_a_real_buffer() {
    let mut buf = [0u8; 8];
    let p = buf.as_mut_ptr() as u64;
    write_i64(p, -42).expect("i64 out");
    assert_eq!(read_i64(p), Ok(-42));
    assert_eq!(read_u64(p), Ok((-42i64) as u64));
    write_u32(p, 0xdead_beef).expect("u32 out");
    assert_eq!(read_u32(p), Ok(0xdead_beef));
    assert_eq!(read_i32(p), Ok(0xdead_beefu32 as i32));
    assert_eq!(cmpxchg_u32(p, 0, 1), Ok(0xdead_beef));
    assert_eq!(cmpxchg_u32(p, 0xdead_beef, 1), Ok(0xdead_beef));
    assert_eq!(read_u32(p), Ok(1));
}

#[test]
fn the_byte_helpers_move_exactly_the_slice_they_were_given() {
    let mut dst = [0u8; 6];
    let src = [1u8, 2, 3, 4, 5, 6];
    write_bytes(dst.as_mut_ptr() as u64, &src).expect("out");
    assert_eq!(dst, src);
    let mut back = [0u8; 6];
    read_bytes(dst.as_ptr() as u64, &mut back).expect("in");
    assert_eq!(back, src);
}

/// `tv_sec` at +0 and `tv_nsec` at +8, both signed 64-bit. The offsets are
/// literals here: a fixture built from the module's own constant would move
/// with it and could not fail.
#[test]
fn a_timespec_is_two_signed_words_at_zero_and_eight() {
    let mut raw = [0u8; 16];
    raw[..8].copy_from_slice(&7i64.to_ne_bytes());
    raw[8..].copy_from_slice(&(-1i64).to_ne_bytes());
    assert_eq!(read_timespec(raw.as_ptr() as u64), Ok((7, -1)));
}

/// A zero length never looks at the pointer.
#[test]
fn a_zero_length_transfer_never_looks_at_the_pointer() {
    assert_eq!(read_bytes(KERNEL_SIDE, &mut []), Ok(()));
    assert_eq!(write_bytes(0, &[]), Ok(()));
}

#[test]
fn an_address_the_copy_cannot_reach_is_efault_every_way_round() {
    let mut one = [0u8; 1];
    assert_eq!(read_i64(KERNEL_SIDE), Err(Errno::Efault));
    assert_eq!(read_u64(KERNEL_SIDE), Err(Errno::Efault));
    assert_eq!(read_u32(KERNEL_SIDE), Err(Errno::Efault));
    assert_eq!(read_i32(KERNEL_SIDE), Err(Errno::Efault));
    assert_eq!(read_timespec(KERNEL_SIDE), Err(Errno::Efault));
    assert_eq!(write_i64(KERNEL_SIDE, 0), Err(Errno::Efault));
    assert_eq!(write_u32(KERNEL_SIDE, 0), Err(Errno::Efault));
    assert_eq!(cmpxchg_u32(KERNEL_SIDE, 0, 1), Err(Errno::Efault));
    assert_eq!(read_bytes(KERNEL_SIDE, &mut one), Err(Errno::Efault));
    assert_eq!(write_bytes(KERNEL_SIDE, &[0u8]), Err(Errno::Efault));
}

/// NULL is EFAULT, not a read of address zero. The hand-rolled range checks
/// these helpers replaced let a NULL pointer straight through on several of
/// the scalar paths.
#[test]
fn a_null_pointer_is_efault_rather_than_a_dereference_of_zero() {
    let mut one = [0u8; 1];
    assert_eq!(read_i64(0), Err(Errno::Efault));
    assert_eq!(read_u32(0), Err(Errno::Efault));
    assert_eq!(read_timespec(0), Err(Errno::Efault));
    assert_eq!(write_i64(0, 0), Err(Errno::Efault));
    assert_eq!(write_u32(0, 0), Err(Errno::Efault));
    assert_eq!(cmpxchg_u32(0, 0, 1), Err(Errno::Efault));
    assert_eq!(read_bytes(0, &mut one), Err(Errno::Efault));
    assert_eq!(write_bytes(0, &[0u8]), Err(Errno::Efault));
}

/// An object straddling the top of the user range is refused WHOLE — never
/// delivered as the readable prefix plus zeros.
#[test]
fn a_transfer_that_straddles_the_user_boundary_is_refused_whole() {
    assert_eq!(read_u64(hal::USER_VA_END - 7), Err(Errno::Efault));
    assert_eq!(read_u32(hal::USER_VA_END - 3), Err(Errno::Efault));
    assert_eq!(read_timespec(hal::USER_VA_END - 15), Err(Errno::Efault));
    assert_eq!(write_i64(hal::USER_VA_END - 7, 0), Err(Errno::Efault));
}

/// A failed copy-IN leaves the destination ZEROED, so a caller that ignores
/// the error cannot act on whatever was in the kernel buffer before.
#[test]
fn a_failed_copy_in_zeroes_the_destination() {
    let mut dst = [0xaau8; 8];
    assert_eq!(read_bytes(KERNEL_SIDE, &mut dst), Err(Errno::Efault));
    assert_eq!(dst, [0u8; 8]);
}
