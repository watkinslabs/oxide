// Wire-layout contract: the byte offsets userspace and the kernel must agree
// on, identical on x86_64 and aarch64 (no compat form is in play — both are
// 64-bit LP64 and the structures carry explicit fixed-width fields).

use crate::aio_abi::layout::{AioRingAbi, AioSigsetAbi, IoEventAbi, IocbAbi};
use crate::aio_abi::uapi::*;
use core::mem::{offset_of, size_of};

#[test]
fn iocb_field_offsets_and_size() {
    assert_eq!(IOCB_OFF_DATA, 0);
    assert_eq!(IOCB_OFF_KEY, 8);
    assert_eq!(IOCB_OFF_RW_FLAGS, 12);
    assert_eq!(IOCB_OFF_LIO_OPCODE, 16);
    assert_eq!(IOCB_OFF_REQPRIO, 18);
    assert_eq!(IOCB_OFF_FILDES, 20);
    assert_eq!(IOCB_OFF_BUF, 24);
    assert_eq!(IOCB_OFF_NBYTES, 32);
    assert_eq!(IOCB_OFF_OFFSET, 40);
    assert_eq!(IOCB_OFF_RESERVED2, 48);
    assert_eq!(IOCB_OFF_FLAGS, 56);
    assert_eq!(IOCB_OFF_RESFD, 60);
    assert_eq!(IOCB_SIZE, 64);
    // Every field lands inside the 64-byte structure.
    assert_eq!(IOCB_OFF_RESFD + 4, IOCB_SIZE);
}

#[test]
fn io_event_field_offsets_and_size() {
    assert_eq!((IOEV_OFF_DATA, IOEV_OFF_OBJ, IOEV_OFF_RES, IOEV_OFF_RES2), (0, 8, 16, 24));
    assert_eq!(IOEV_SIZE, 32);
}

#[test]
fn aio_ring_header_offsets_and_constants() {
    assert_eq!(RING_OFF_ID, 0);
    assert_eq!(RING_OFF_NR, 4);
    assert_eq!(RING_OFF_HEAD, 8);
    assert_eq!(RING_OFF_TAIL, 12);
    assert_eq!(RING_OFF_MAGIC, 16);
    assert_eq!(RING_OFF_COMPAT_FEATURES, 20);
    assert_eq!(RING_OFF_INCOMPAT_FEATURES, 24);
    assert_eq!(RING_OFF_HEADER_LENGTH, 28);
    assert_eq!(AIO_RING_HDR_SIZE, 32);
    // The magic is what libaio tests before it reaps from the mapping without
    // a syscall; getting it wrong silently costs every reap a syscall.
    assert_eq!(AIO_RING_MAGIC, 0xa10a_10a1);
    assert_eq!(AIO_RING_COMPAT_FEATURES, 1);
    assert_eq!(AIO_RING_INCOMPAT_FEATURES, 0);
}

#[test]
fn event_slots_start_right_after_the_header() {
    assert_eq!(event_byte_off(0), AIO_RING_HDR_SIZE);
    assert_eq!(event_byte_off(1), AIO_RING_HDR_SIZE + IOEV_SIZE);
    assert_eq!(event_byte_off(126), 32 + 126 * 32);
    // Slot 126 is the last one that fits in the first 4 KiB page.
    assert!(event_byte_off(126) + IOEV_SIZE <= 4096);
    assert!(event_byte_off(127) + IOEV_SIZE > 4096);
}

#[test]
fn opcode_numbers_are_the_uapi_ones() {
    assert_eq!(IOCB_CMD_PREAD, 0);
    assert_eq!(IOCB_CMD_PWRITE, 1);
    assert_eq!(IOCB_CMD_FSYNC, 2);
    assert_eq!(IOCB_CMD_FDSYNC, 3);
    assert_eq!(IOCB_CMD_POLL, 5);
    assert_eq!(IOCB_CMD_NOOP, 6);
    assert_eq!(IOCB_CMD_PREADV, 7);
    assert_eq!(IOCB_CMD_PWRITEV, 8);
}

#[test]
fn flag_bits_and_sigset_layout() {
    assert_eq!(IOCB_FLAG_RESFD, 1);
    assert_eq!(IOCB_FLAG_IOPRIO, 2);
    assert_eq!(AIO_SIGSET_OFF_SIGMASK, 0);
    assert_eq!(AIO_SIGSET_OFF_SIGSETSIZE, 8);
    assert_eq!(AIO_SIGSET_SIZE, 16);
    assert_eq!(KIOCB_KEY, 0);
}

#[test]
fn repr_c_mirrors_agree_with_the_constants() {
    // The const assertions in `aio_abi::layout` make this claim on BOTH kernel
    // targets at compile time; this repeats it at runtime so a reader sees the
    // binding, and so a constant edited without touching the mirror fails here
    // as well as in the aarch64 build.
    assert_eq!(size_of::<IocbAbi>(), IOCB_SIZE as usize);
    assert_eq!(offset_of!(IocbAbi, aio_reserved2), IOCB_OFF_RESERVED2 as usize);
    assert_eq!(offset_of!(IocbAbi, aio_resfd), IOCB_OFF_RESFD as usize);
    assert_eq!(size_of::<IoEventAbi>(), IOEV_SIZE as usize);
    assert_eq!(offset_of!(IoEventAbi, res2), IOEV_OFF_RES2 as usize);
    assert_eq!(size_of::<AioRingAbi>(), AIO_RING_HDR_SIZE as usize);
    assert_eq!(offset_of!(AioRingAbi, header_length), RING_OFF_HEADER_LENGTH as usize);
    assert_eq!(size_of::<AioSigsetAbi>(), AIO_SIGSET_SIZE as usize);
    // Slot 0 abuts the header: no padding, on any target.
    assert_eq!(event_byte_off(0), size_of::<AioRingAbi>() as u64);
}
