// iocb decode + the submit validation ladder, including the orderings that
// separate one rejection from another.

use crate::aio_abi::iocb::*;
use crate::aio_abi::uapi::*;
use syscall::errno::Errno;

fn blank() -> [u8; 64] { [0u8; 64] }

fn put_u16(b: &mut [u8; 64], off: u64, v: u16) {
    b[off as usize..off as usize + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8; 64], off: u64, v: u32) {
    b[off as usize..off as usize + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8; 64], off: u64, v: u64) {
    b[off as usize..off as usize + 8].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn decode_reads_every_field_from_its_offset() {
    let mut b = blank();
    put_u64(&mut b, IOCB_OFF_DATA, 0x1122_3344_5566_7788);
    put_u32(&mut b, IOCB_OFF_KEY, 0xdead_beef); // overwritten by the kernel; ignored
    put_u32(&mut b, IOCB_OFF_RW_FLAGS, 0x18);
    put_u16(&mut b, IOCB_OFF_LIO_OPCODE, IOCB_CMD_PWRITEV);
    put_u16(&mut b, IOCB_OFF_REQPRIO, (-3i16) as u16);
    put_u32(&mut b, IOCB_OFF_FILDES, 7);
    put_u64(&mut b, IOCB_OFF_BUF, 0x7fff_0000_1000);
    put_u64(&mut b, IOCB_OFF_NBYTES, 4);
    put_u64(&mut b, IOCB_OFF_OFFSET, (-1i64) as u64);
    put_u64(&mut b, IOCB_OFF_RESERVED2, 0);
    put_u32(&mut b, IOCB_OFF_FLAGS, IOCB_FLAG_RESFD | IOCB_FLAG_IOPRIO);
    put_u32(&mut b, IOCB_OFF_RESFD, 11);
    let io = decode(&b);
    assert_eq!(io.data, 0x1122_3344_5566_7788);
    assert_eq!(io.rw_flags, 0x18);
    assert_eq!(io.opcode, IOCB_CMD_PWRITEV);
    assert_eq!(io.reqprio, -3);
    assert_eq!(io.fildes, 7);
    assert_eq!(io.buf, 0x7fff_0000_1000);
    assert_eq!(io.nbytes, 4);
    assert_eq!(io.offset, -1);
    assert_eq!(io.flags, 3);
    assert_eq!(io.resfd, 11);
    assert!(wants_resfd(&io));
    assert!(wants_ioprio(&io));
}

#[test]
fn aio_key_is_not_part_of_the_decoded_request() {
    // The kernel writes KIOCB_KEY over it at submit, so whatever the caller
    // left there must not reach any decision.
    let mut a = blank();
    let mut b = blank();
    put_u32(&mut b, IOCB_OFF_KEY, u32::MAX);
    assert_eq!(decode(&a), decode(&b));
    put_u32(&mut a, IOCB_OFF_KEY, 1);
    assert_eq!(decode(&a), decode(&b));
}

#[test]
fn reserved_field_must_be_zero() {
    let mut b = blank();
    put_u64(&mut b, IOCB_OFF_RESERVED2, 1);
    assert_eq!(validate_common(&decode(&b)), Err(Errno::Einval));
}

#[test]
fn negative_signed_byte_count_is_rejected() {
    let mut b = blank();
    put_u64(&mut b, IOCB_OFF_NBYTES, u64::MAX);
    assert_eq!(validate_common(&decode(&b)), Err(Errno::Einval));
    put_u64(&mut b, IOCB_OFF_NBYTES, 1u64 << 63);
    assert_eq!(validate_common(&decode(&b)), Err(Errno::Einval));
    put_u64(&mut b, IOCB_OFF_NBYTES, (1u64 << 63) - 1);
    assert_eq!(validate_common(&decode(&b)), Ok(()));
}

#[test]
fn reserved_field_outranks_the_byte_count_check() {
    let mut b = blank();
    put_u64(&mut b, IOCB_OFF_RESERVED2, 1);
    put_u64(&mut b, IOCB_OFF_NBYTES, u64::MAX);
    // Both are EINVAL, so the ordering is only observable through which check
    // runs first; pin it so a reordering is caught by review of this test.
    assert_eq!(validate_common(&decode(&b)), Err(Errno::Einval));
}

#[test]
fn opcode_classification() {
    assert_eq!(classify(IOCB_CMD_PREAD), Ok(AioOp::Pread));
    assert_eq!(classify(IOCB_CMD_PWRITE), Ok(AioOp::Pwrite));
    assert_eq!(classify(IOCB_CMD_FSYNC), Ok(AioOp::Fsync));
    assert_eq!(classify(IOCB_CMD_FDSYNC), Ok(AioOp::Fdsync));
    assert_eq!(classify(IOCB_CMD_POLL), Ok(AioOp::Poll));
    assert_eq!(classify(IOCB_CMD_PREADV), Ok(AioOp::Preadv));
    assert_eq!(classify(IOCB_CMD_PWRITEV), Ok(AioOp::Pwritev));
}

#[test]
fn noop_and_the_retired_opcode_are_einval() {
    // IOCB_CMD_NOOP is still enumerated in the UAPI header but the submit
    // switch has no arm for it, so it fails like any unknown opcode.
    assert_eq!(classify(IOCB_CMD_NOOP), Err(Errno::Einval));
    assert_eq!(classify(4), Err(Errno::Einval));
    assert_eq!(classify(9), Err(Errno::Einval));
    assert_eq!(classify(u16::MAX), Err(Errno::Einval));
}

#[test]
fn op_predicates() {
    assert!(AioOp::Pread.is_rw() && !AioOp::Pread.is_vectored() && !AioOp::Pread.is_write());
    assert!(AioOp::Pwritev.is_rw() && AioOp::Pwritev.is_vectored() && AioOp::Pwritev.is_write());
    assert!(AioOp::Preadv.is_vectored() && !AioOp::Preadv.is_write());
    assert!(!AioOp::Fsync.is_rw() && !AioOp::Fdsync.is_rw() && !AioOp::Poll.is_rw());
    assert!(AioOp::Pwrite.is_write());
}

#[test]
fn fsync_rejects_every_transfer_field() {
    let mut b = blank();
    put_u16(&mut b, IOCB_OFF_LIO_OPCODE, IOCB_CMD_FSYNC);
    assert_eq!(validate_fsync(&decode(&b)), Ok(()));
    for off in [IOCB_OFF_BUF, IOCB_OFF_NBYTES, IOCB_OFF_OFFSET] {
        let mut c = b;
        put_u64(&mut c, off, 1);
        assert_eq!(validate_fsync(&decode(&c)), Err(Errno::Einval));
    }
    let mut c = b;
    put_u32(&mut c, IOCB_OFF_RW_FLAGS, 1);
    assert_eq!(validate_fsync(&decode(&c)), Err(Errno::Einval));
}

#[test]
fn poll_mask_must_fit_the_user_poll_word() {
    let mut b = blank();
    put_u16(&mut b, IOCB_OFF_LIO_OPCODE, IOCB_CMD_POLL);
    put_u64(&mut b, IOCB_OFF_BUF, 0x1);
    assert_eq!(validate_poll(&decode(&b)), Ok(1));
    put_u64(&mut b, IOCB_OFF_BUF, u16::MAX as u64);
    assert_eq!(validate_poll(&decode(&b)), Ok(u16::MAX));
    put_u64(&mut b, IOCB_OFF_BUF, u16::MAX as u64 + 1);
    assert_eq!(validate_poll(&decode(&b)), Err(Errno::Einval));
}

#[test]
fn poll_rejects_the_transfer_fields_but_not_a_zero_mask() {
    let mut b = blank();
    put_u16(&mut b, IOCB_OFF_LIO_OPCODE, IOCB_CMD_POLL);
    assert_eq!(validate_poll(&decode(&b)), Ok(0));
    for off in [IOCB_OFF_NBYTES, IOCB_OFF_OFFSET] {
        let mut c = b;
        put_u64(&mut c, off, 1);
        assert_eq!(validate_poll(&decode(&c)), Err(Errno::Einval));
    }
    let mut c = b;
    put_u32(&mut c, IOCB_OFF_RW_FLAGS, 8);
    assert_eq!(validate_poll(&decode(&c)), Err(Errno::Einval));
}

#[test]
fn reqprio_is_ignored_without_the_ioprio_flag() {
    let mut b = blank();
    put_u16(&mut b, IOCB_OFF_REQPRIO, 0x7fff);
    let io = decode(&b);
    assert!(!wants_ioprio(&io));
    // Unknown aio_flags bits are not validated at all.
    put_u32(&mut b, IOCB_OFF_FLAGS, 0xffff_fffc);
    let io = decode(&b);
    assert!(!wants_ioprio(&io) && !wants_resfd(&io));
}
