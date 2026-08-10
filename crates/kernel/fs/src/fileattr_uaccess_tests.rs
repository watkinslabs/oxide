// `read_user`/`write_user` go through the exception-table copy routines, so a
// range check that passes is not the same as an address that can be touched.
// These drive the real copy against a real buffer.

use super::*;

/// An address inside the kernel half. The range check rejects it, which is the
/// only outcome a hosted test can observe — but it is also the outcome the
/// converted call must produce instead of dereferencing it.
const KERNEL_SIDE: u64 = hal::USER_VA_END;

fn efault() -> i64 { -(Errno::Efault.as_i32() as i64) }

#[test]
fn a_struct_written_out_reads_back_as_the_same_fields() {
    let mut fa = vfs::fileattr_fill_xflags(0);
    fa.fsx_extsize = 0x1234;
    fa.fsx_projid = 0x5678;
    fa.fsx_cowextsize = 0x9abc;
    let mut buf = alloc::vec![0xffu8; FILE_ATTR_SIZE_VER0];
    assert_eq!(write_user(buf.as_mut_ptr() as u64, FILE_ATTR_SIZE_VER0, &fa), 0);
    let back = read_user(buf.as_ptr() as u64, FILE_ATTR_SIZE_VER0).expect("round trip");
    assert_eq!(back.fsx_extsize, 0x1234);
    assert_eq!(back.fsx_projid, 0x5678);
    assert_eq!(back.fsx_cowextsize, 0x9abc);
}

/// The tail a caller declared beyond VER0 is ZEROED, never left holding
/// whatever was in the buffer before.
#[test]
fn the_declared_tail_is_zero_filled_not_left_alone() {
    let fa = vfs::fileattr_fill_xflags(0);
    let declared = FILE_ATTR_SIZE_VER0 + 16;
    let mut buf = alloc::vec![0xaau8; declared];
    assert_eq!(write_user(buf.as_mut_ptr() as u64, declared, &fa), 0);
    assert!(buf[FILE_ATTR_SIZE_VER0..].iter().all(|b| *b == 0), "tail: {:?}", &buf[FILE_ATTR_SIZE_VER0..]);
}

#[test]
fn an_address_the_copy_cannot_reach_is_efault_on_the_way_in() {
    assert_eq!(read_user(KERNEL_SIDE, FILE_ATTR_SIZE_VER0), Err(efault()));
    assert_eq!(read_user(0, FILE_ATTR_SIZE_VER0), Err(efault()));
}

#[test]
fn an_address_the_copy_cannot_reach_is_efault_on_the_way_out() {
    let fa = vfs::fileattr_fill_xflags(0);
    assert_eq!(write_user(KERNEL_SIDE, FILE_ATTR_SIZE_VER0, &fa), efault());
    assert_eq!(write_user(0, FILE_ATTR_SIZE_VER0, &fa), efault());
}

/// Size handshake outranks the pointer: an under-VER0 struct is EINVAL and an
/// over-page one is E2BIG even when the address itself is fine.
#[test]
fn the_size_handshake_is_answered_before_the_address_is_touched() {
    let mut buf = alloc::vec![0u8; FILE_ATTR_SIZE_VER0];
    let p = buf.as_mut_ptr() as u64;
    assert_eq!(read_user(p, FILE_ATTR_SIZE_VER0 - 1), Err(err(Errno::Einval)));
    assert_eq!(read_user(KERNEL_SIDE, FILE_ATTR_SIZE_VER0 - 1), Err(err(Errno::Einval)));
    assert_eq!(read_user(KERNEL_SIDE, hal::PAGE_SIZE_BYTES as usize + 1), Err(err(Errno::E2big)));
}
