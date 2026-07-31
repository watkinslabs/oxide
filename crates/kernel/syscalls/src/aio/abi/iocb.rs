// `struct iocb` decode plus the submit-time validation ladder, in the order
// `io_submit_one`/`__io_submit_one` apply it. The order is the contract: a
// caller that sets both a reserved field and a bad opcode must see the
// reserved-field verdict, and a caller with a bad fd must see EBADF before any
// per-opcode field check runs.

use syscall::errno::Errno;

use super::uapi::{
    IOCB_CMD_FDSYNC, IOCB_CMD_FSYNC, IOCB_CMD_POLL, IOCB_CMD_PREAD, IOCB_CMD_PREADV,
    IOCB_CMD_PWRITE, IOCB_CMD_PWRITEV, IOCB_FLAG_IOPRIO, IOCB_FLAG_RESFD,
    IOCB_OFF_BUF, IOCB_OFF_DATA, IOCB_OFF_FILDES, IOCB_OFF_FLAGS, IOCB_OFF_LIO_OPCODE,
    IOCB_OFF_NBYTES, IOCB_OFF_OFFSET, IOCB_OFF_REQPRIO, IOCB_OFF_RESERVED2, IOCB_OFF_RESFD,
    IOCB_OFF_RW_FLAGS, IOCB_SIZE,
};

/// Decoded `struct iocb`.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Iocb {
    pub data: u64,
    pub rw_flags: u32,
    pub opcode: u16,
    pub reqprio: i16,
    pub fildes: u32,
    pub buf: u64,
    pub nbytes: u64,
    pub offset: i64,
    pub reserved2: u64,
    pub flags: u32,
    pub resfd: u32,
}

/// The operations the submit switch accepts. Every other `aio_lio_opcode` —
/// including the `IOCB_CMD_NOOP` the UAPI header still enumerates, and the
/// retired `4` — falls through to `EINVAL`.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum AioOp {
    Pread,
    Pwrite,
    Preadv,
    Pwritev,
    /// Full file sync.
    Fsync,
    /// Data-only sync.
    Fdsync,
    Poll,
}

impl AioOp {
    /// True for the four read/write opcodes, which are the only ones that go
    /// through the ioprio + `RWF_*` preparation.
    /// # C: O(1)
    pub fn is_rw(self) -> bool {
        matches!(self, AioOp::Pread | AioOp::Pwrite | AioOp::Preadv | AioOp::Pwritev)
    }
    /// True for the two vectored opcodes (`aio_buf` is an iovec array and
    /// `aio_nbytes` its element count).
    /// # C: O(1)
    pub fn is_vectored(self) -> bool { matches!(self, AioOp::Preadv | AioOp::Pwritev) }
    /// True for a write-direction opcode.
    /// # C: O(1)
    pub fn is_write(self) -> bool { matches!(self, AioOp::Pwrite | AioOp::Pwritev) }
}

/// Decode the 64-byte wire form. Little-endian field order per the UAPI
/// header; `aio_key` is skipped because the kernel overwrites it at submit.
/// # C: O(1)
pub fn decode(b: &[u8; IOCB_SIZE as usize]) -> Iocb {
    let u32_at = |o: u64| -> u32 {
        let i = o as usize;
        u32::from_le_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
    };
    let u64_at = |o: u64| -> u64 {
        let i = o as usize;
        let mut w = [0u8; 8];
        w.copy_from_slice(&b[i..i + 8]);
        u64::from_le_bytes(w)
    };
    let u16_at = |o: u64| -> u16 {
        let i = o as usize;
        u16::from_le_bytes([b[i], b[i + 1]])
    };
    Iocb {
        data: u64_at(IOCB_OFF_DATA),
        rw_flags: u32_at(IOCB_OFF_RW_FLAGS),
        opcode: u16_at(IOCB_OFF_LIO_OPCODE),
        reqprio: u16_at(IOCB_OFF_REQPRIO) as i16,
        fildes: u32_at(IOCB_OFF_FILDES),
        buf: u64_at(IOCB_OFF_BUF),
        nbytes: u64_at(IOCB_OFF_NBYTES),
        offset: u64_at(IOCB_OFF_OFFSET) as i64,
        reserved2: u64_at(IOCB_OFF_RESERVED2),
        flags: u32_at(IOCB_OFF_FLAGS),
        resfd: u32_at(IOCB_OFF_RESFD),
    }
}

/// The two checks `io_submit_one` runs before it reserves a ring slot:
/// the forwards-compatibility reserved field, then the byte-count overflow
/// test (`aio_nbytes` read as a signed word must not be negative).
/// # C: O(1)
pub fn validate_common(io: &Iocb) -> Result<(), Errno> {
    if io.reserved2 != 0 { return Err(Errno::Einval); }
    if (io.nbytes as i64) < 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Map `aio_lio_opcode` onto the accepted set. # C: O(1)
pub fn classify(opcode: u16) -> Result<AioOp, Errno> {
    match opcode {
        IOCB_CMD_PREAD => Ok(AioOp::Pread),
        IOCB_CMD_PWRITE => Ok(AioOp::Pwrite),
        IOCB_CMD_FSYNC => Ok(AioOp::Fsync),
        IOCB_CMD_FDSYNC => Ok(AioOp::Fdsync),
        IOCB_CMD_POLL => Ok(AioOp::Poll),
        IOCB_CMD_PREADV => Ok(AioOp::Preadv),
        IOCB_CMD_PWRITEV => Ok(AioOp::Pwritev),
        _ => Err(Errno::Einval),
    }
}

/// Fields an `IOCB_CMD_FSYNC`/`IOCB_CMD_FDSYNC` submission may not set.
/// # C: O(1)
pub fn validate_fsync(io: &Iocb) -> Result<(), Errno> {
    if io.buf != 0 || io.offset != 0 || io.nbytes != 0 || io.rw_flags != 0 {
        return Err(Errno::Einval);
    }
    Ok(())
}

/// `IOCB_CMD_POLL`: `aio_buf` is a poll event mask that must fit the 16-bit
/// user `poll` word, and none of the transfer fields may be set. Returns the
/// requested mask; the caller adds the always-reported error/hangup bits.
/// # C: O(1)
pub fn validate_poll(io: &Iocb) -> Result<u16, Errno> {
    if io.buf > u16::MAX as u64 { return Err(Errno::Einval); }
    if io.offset != 0 || io.nbytes != 0 || io.rw_flags != 0 { return Err(Errno::Einval); }
    Ok(io.buf as u16)
}

/// Whether the submission asked for eventfd completion signalling.
/// # C: O(1)
pub fn wants_resfd(io: &Iocb) -> bool { io.flags & IOCB_FLAG_RESFD != 0 }

/// Whether `aio_reqprio` carries an ioprio value that must pass the capability
/// ladder. Without the flag `aio_reqprio` is ignored entirely — an arbitrary
/// value there is NOT an error.
/// # C: O(1)
pub fn wants_ioprio(io: &Iocb) -> bool { io.flags & IOCB_FLAG_IOPRIO != 0 }
