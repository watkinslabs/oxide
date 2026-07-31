// libaio wire constants: `struct iocb`, `struct io_event`, `struct aio_ring`,
// the `aio_lio_opcode` numbers and the `aio_flags` bits. Numbers only — every
// decision that consumes them lives in `iocb`/`geometry`/`events`/`ring`.

// ── struct iocb (64 bytes) ─────────────────────────────────────────────────
/// `aio_data` — echoed into `io_event.data`.
pub const IOCB_OFF_DATA: u64 = 0;
/// `aio_key` — kernel-written request tag; `io_cancel` reads it back.
pub const IOCB_OFF_KEY: u64 = 8;
/// `aio_rw_flags` — the `RWF_*` word (shares the 8..16 pair with `aio_key`).
pub const IOCB_OFF_RW_FLAGS: u64 = 12;
/// `aio_lio_opcode`.
pub const IOCB_OFF_LIO_OPCODE: u64 = 16;
/// `aio_reqprio` — an ioprio value when `IOCB_FLAG_IOPRIO` is set.
pub const IOCB_OFF_REQPRIO: u64 = 18;
/// `aio_fildes`.
pub const IOCB_OFF_FILDES: u64 = 20;
/// `aio_buf` — user buffer, iovec array, or the poll event mask.
pub const IOCB_OFF_BUF: u64 = 24;
/// `aio_nbytes` — byte count or iovec count.
pub const IOCB_OFF_NBYTES: u64 = 32;
/// `aio_offset`.
pub const IOCB_OFF_OFFSET: u64 = 40;
/// `aio_reserved2` — must be zero; the forwards-compatibility gate.
pub const IOCB_OFF_RESERVED2: u64 = 48;
/// `aio_flags`.
pub const IOCB_OFF_FLAGS: u64 = 56;
/// `aio_resfd` — eventfd signalled on completion when `IOCB_FLAG_RESFD` is set.
pub const IOCB_OFF_RESFD: u64 = 60;
/// `sizeof(struct iocb)`.
pub const IOCB_SIZE: u64 = 64;

/// Value the kernel stores into `aio_key` at submit; `io_cancel` rejects any
/// other value with `EINVAL` before it even looks up the context.
pub const KIOCB_KEY: u32 = 0;

// ── struct io_event (32 bytes) ────────────────────────────────────────────
/// `io_event.data`.
pub const IOEV_OFF_DATA: u64 = 0;
/// `io_event.obj` — the user `struct iocb *` the event came from.
pub const IOEV_OFF_OBJ: u64 = 8;
/// `io_event.res` — byte count or `-errno`.
pub const IOEV_OFF_RES: u64 = 16;
/// `io_event.res2` — secondary result.
pub const IOEV_OFF_RES2: u64 = 24;
/// `sizeof(struct io_event)`.
pub const IOEV_SIZE: u64 = 32;

// ── struct aio_ring (32-byte header, then the io_event array) ─────────────
/// `aio_ring.id` — the context's table index; the first word userspace sees.
pub const RING_OFF_ID: u64 = 0;
/// `aio_ring.nr` — event-slot count (the trusted copy lives in the kernel).
pub const RING_OFF_NR: u64 = 4;
/// `aio_ring.head` — consumer index, advanced by the reaper.
pub const RING_OFF_HEAD: u64 = 8;
/// `aio_ring.tail` — producer index, advanced by completion.
pub const RING_OFF_TAIL: u64 = 12;
/// `aio_ring.magic`.
pub const RING_OFF_MAGIC: u64 = 16;
/// `aio_ring.compat_features`.
pub const RING_OFF_COMPAT_FEATURES: u64 = 20;
/// `aio_ring.incompat_features`.
pub const RING_OFF_INCOMPAT_FEATURES: u64 = 24;
/// `aio_ring.header_length`.
pub const RING_OFF_HEADER_LENGTH: u64 = 28;
/// `sizeof(struct aio_ring)` — also the byte offset of event slot 0.
pub const AIO_RING_HDR_SIZE: u64 = 32;
/// `AIO_RING_MAGIC`. Userspace libaio reads this out of the mapped ring to
/// decide whether it may reap events without entering the kernel; a ring that
/// does not carry it makes every `io_getevents` a syscall.
pub const AIO_RING_MAGIC: u32 = 0xa10a_10a1;
/// `AIO_RING_COMPAT_FEATURES`.
pub const AIO_RING_COMPAT_FEATURES: u32 = 1;
/// `AIO_RING_INCOMPAT_FEATURES`.
pub const AIO_RING_INCOMPAT_FEATURES: u32 = 0;

// ── aio_lio_opcode ────────────────────────────────────────────────────────
/// `IOCB_CMD_PREAD`.
pub const IOCB_CMD_PREAD: u16 = 0;
/// `IOCB_CMD_PWRITE`.
pub const IOCB_CMD_PWRITE: u16 = 1;
/// `IOCB_CMD_FSYNC`.
pub const IOCB_CMD_FSYNC: u16 = 2;
/// `IOCB_CMD_FDSYNC`.
pub const IOCB_CMD_FDSYNC: u16 = 3;
/// `IOCB_CMD_POLL`.
pub const IOCB_CMD_POLL: u16 = 5;
/// `IOCB_CMD_NOOP` — enumerated in the UAPI header but not accepted by the
/// submit switch, so it is `EINVAL` like any unknown opcode.
pub const IOCB_CMD_NOOP: u16 = 6;
/// `IOCB_CMD_PREADV`.
pub const IOCB_CMD_PREADV: u16 = 7;
/// `IOCB_CMD_PWRITEV`.
pub const IOCB_CMD_PWRITEV: u16 = 8;

// ── aio_flags ─────────────────────────────────────────────────────────────
/// `IOCB_FLAG_RESFD` — `aio_resfd` names an eventfd to signal on completion.
pub const IOCB_FLAG_RESFD: u32 = 1 << 0;
/// `IOCB_FLAG_IOPRIO` — `aio_reqprio` carries an ioprio class/level.
pub const IOCB_FLAG_IOPRIO: u32 = 1 << 1;

/// `struct __aio_sigset { const sigset_t *sigmask; size_t sigsetsize; }` —
/// `io_pgetevents`'s sixth argument.
pub const AIO_SIGSET_OFF_SIGMASK: u64 = 0;
/// `__aio_sigset.sigsetsize`.
pub const AIO_SIGSET_OFF_SIGSETSIZE: u64 = 8;
/// `sizeof(struct __aio_sigset)`.
pub const AIO_SIGSET_SIZE: u64 = 16;

/// Byte offset of event slot `idx` inside the ring region. The kernel indexes
/// the region as a flat `io_event` array whose slot 0 overlaps the header, so
/// event `i` sits one whole `io_event` past the array base — which is exactly
/// the end of the 32-byte header.
/// # C: O(1)
pub const fn event_byte_off(idx: u32) -> u64 { AIO_RING_HDR_SIZE + idx as u64 * IOEV_SIZE }
