// Every UFFDIO_* handler reads its request through `read_req` and reports
// through `write_reply`/`write_req`. Both go through the exception-table copy
// routines, so an address that passed a range check but cannot be touched is
// EFAULT rather than a kernel fault.

use super::*;

/// The lowest address in the kernel half — range-rejected, which is what the
/// converted copy must answer instead of dereferencing it.
const KERNEL_SIDE: u64 = hal::USER_VA_END;

#[test]
fn a_request_object_round_trips_through_the_copy() {
    let mut buf = [0u8; core::mem::size_of::<UffdioCopy>()];
    let want = UffdioCopy { dst: 0x1111, src: 0x2222, len: 0x3333, mode: 0x4444, copy: 0x5555 };
    write_req(buf.as_mut_ptr() as u64, &want).expect("write");
    let got: UffdioCopy = read_req(buf.as_ptr() as u64).expect("read");
    assert_eq!((got.dst, got.src, got.len, got.mode, got.copy), (0x1111, 0x2222, 0x3333, 0x4444, 0x5555));
}

/// `uffdio_copy.copy` is the whole partial-progress contract: a short fill
/// reports the BYTE COUNT there and returns EAGAIN, and a fill that installed
/// nothing reports the negative errno there. The slot is signed, so both
/// encodings have to survive the write.
#[test]
fn the_reply_slot_carries_a_byte_count_and_a_negative_errno_alike() {
    let mut obj = [0u8; core::mem::size_of::<UffdioCopy>()];
    let slot = obj.as_mut_ptr() as u64 + 32;
    write_reply(slot, 8192).expect("count");
    assert_eq!(i64::from_ne_bytes(obj[32..40].try_into().expect("8")), 8192);
    write_reply(slot, err(Errno::Efault)).expect("errno");
    assert_eq!(i64::from_ne_bytes(obj[32..40].try_into().expect("8")), -(Errno::Efault.as_i32() as i64));
}

#[test]
fn an_unreachable_request_object_is_efault_not_a_dereference() {
    assert_eq!(read_req::<UffdioCopy>(KERNEL_SIDE).err(), Some(Errno::Efault));
    assert_eq!(read_req::<UffdioCopy>(0).err(), Some(Errno::Efault));
    assert_eq!(write_req(KERNEL_SIDE, &UffdioApi::default()).err(), Some(Errno::Efault));
    assert_eq!(write_reply(KERNEL_SIDE, 0).err(), Some(Errno::Efault));
    assert_eq!(write_reply(0, 0).err(), Some(Errno::Efault));
}

/// A request object straddling the top of the user range is refused whole —
/// the copy must not deliver the readable prefix and leave the rest as zeros.
#[test]
fn an_object_that_straddles_the_user_boundary_is_refused_whole() {
    let size = core::mem::size_of::<UffdioCopy>() as u64;
    assert_eq!(read_req::<UffdioCopy>(hal::USER_VA_END - size + 1).err(), Some(Errno::Efault));
}
