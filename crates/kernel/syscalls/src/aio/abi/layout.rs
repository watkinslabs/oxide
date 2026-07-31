// Compile-time proof that the libaio wire structures have the SAME size and
// field offsets on x86_64 and aarch64.
//
// The `uapi` constants are plain integers, so a unit test that compares them to
// each other proves nothing about a second architecture — and `cargo test` only
// ever runs the host one. These are `const` assertions over real `#[repr(C)]`
// declarations instead: they are evaluated for EVERY target the crate is built
// for, so `xtask kernel --arch aarch64` fails to link if aarch64's layout ever
// diverges from the offsets the syscall paths hard-code. The runtime tests in
// `tests/layout.rs` cover the same ground for readability; these are the ones
// that make the claim on both arches.

use core::mem::{align_of, offset_of, size_of};

use super::uapi::*;

/// `struct iocb`.
#[repr(C)]
pub struct IocbAbi {
    pub aio_data: u64,
    pub aio_key: u32,
    pub aio_rw_flags: u32,
    pub aio_lio_opcode: u16,
    pub aio_reqprio: i16,
    pub aio_fildes: u32,
    pub aio_buf: u64,
    pub aio_nbytes: u64,
    pub aio_offset: i64,
    pub aio_reserved2: u64,
    pub aio_flags: u32,
    pub aio_resfd: u32,
}

/// `struct io_event`.
#[repr(C)]
pub struct IoEventAbi {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
}

/// `struct aio_ring`, header only — the `io_event` array follows it.
#[repr(C)]
pub struct AioRingAbi {
    pub id: u32,
    pub nr: u32,
    pub head: u32,
    pub tail: u32,
    pub magic: u32,
    pub compat_features: u32,
    pub incompat_features: u32,
    pub header_length: u32,
}

/// `struct __aio_sigset`.
#[repr(C)]
pub struct AioSigsetAbi {
    pub sigmask: u64,
    pub sigsetsize: u64,
}

// ── struct iocb ───────────────────────────────────────────────────────────
const _: () = assert!(size_of::<IocbAbi>() == IOCB_SIZE as usize);
const _: () = assert!(align_of::<IocbAbi>() == 8);
const _: () = assert!(offset_of!(IocbAbi, aio_data) == IOCB_OFF_DATA as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_key) == IOCB_OFF_KEY as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_rw_flags) == IOCB_OFF_RW_FLAGS as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_lio_opcode) == IOCB_OFF_LIO_OPCODE as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_reqprio) == IOCB_OFF_REQPRIO as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_fildes) == IOCB_OFF_FILDES as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_buf) == IOCB_OFF_BUF as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_nbytes) == IOCB_OFF_NBYTES as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_offset) == IOCB_OFF_OFFSET as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_reserved2) == IOCB_OFF_RESERVED2 as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_flags) == IOCB_OFF_FLAGS as usize);
const _: () = assert!(offset_of!(IocbAbi, aio_resfd) == IOCB_OFF_RESFD as usize);

// ── struct io_event ───────────────────────────────────────────────────────
const _: () = assert!(size_of::<IoEventAbi>() == IOEV_SIZE as usize);
const _: () = assert!(align_of::<IoEventAbi>() == 8);
const _: () = assert!(offset_of!(IoEventAbi, data) == IOEV_OFF_DATA as usize);
const _: () = assert!(offset_of!(IoEventAbi, obj) == IOEV_OFF_OBJ as usize);
const _: () = assert!(offset_of!(IoEventAbi, res) == IOEV_OFF_RES as usize);
const _: () = assert!(offset_of!(IoEventAbi, res2) == IOEV_OFF_RES2 as usize);

// ── struct aio_ring ───────────────────────────────────────────────────────
const _: () = assert!(size_of::<AioRingAbi>() == AIO_RING_HDR_SIZE as usize);
const _: () = assert!(align_of::<AioRingAbi>() == 4);
const _: () = assert!(offset_of!(AioRingAbi, id) == RING_OFF_ID as usize);
const _: () = assert!(offset_of!(AioRingAbi, nr) == RING_OFF_NR as usize);
const _: () = assert!(offset_of!(AioRingAbi, head) == RING_OFF_HEAD as usize);
const _: () = assert!(offset_of!(AioRingAbi, tail) == RING_OFF_TAIL as usize);
const _: () = assert!(offset_of!(AioRingAbi, magic) == RING_OFF_MAGIC as usize);
const _: () = assert!(offset_of!(AioRingAbi, compat_features) == RING_OFF_COMPAT_FEATURES as usize);
const _: () = assert!(offset_of!(AioRingAbi, incompat_features) == RING_OFF_INCOMPAT_FEATURES as usize);
const _: () = assert!(offset_of!(AioRingAbi, header_length) == RING_OFF_HEADER_LENGTH as usize);
// Event slot 0 begins exactly where the header ends, with no padding between.
const _: () = assert!(event_byte_off(0) == size_of::<AioRingAbi>() as u64);
const _: () = assert!(event_byte_off(1) - event_byte_off(0) == size_of::<IoEventAbi>() as u64);

// ── struct __aio_sigset ───────────────────────────────────────────────────
const _: () = assert!(size_of::<AioSigsetAbi>() == AIO_SIGSET_SIZE as usize);
const _: () = assert!(offset_of!(AioSigsetAbi, sigmask) == AIO_SIGSET_OFF_SIGMASK as usize);
const _: () = assert!(offset_of!(AioSigsetAbi, sigsetsize) == AIO_SIGSET_OFF_SIGSETSIZE as usize);

// ── the model the offsets assume ──────────────────────────────────────────
// `aio_context_t` is `__kernel_ulong_t` and the context IS the ring's user
// address, so a target where a pointer is not 8 bytes would need a compat form
// this code does not have. Both kernel targets are LP64 little-endian.
const _: () = assert!(size_of::<usize>() == 8);
const _: () = assert!(size_of::<*const u8>() == 8);
const _: () = assert!(u32::from_ne_bytes([1, 0, 0, 0]) == 1);
