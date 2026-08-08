//! The 64-byte submission-queue entry, decoded once.
//!
//! Ungated on purpose: the wire offsets are ABI, and a slot file carrying
//! `#![cfg(target_os = "oxide-kernel")]` cannot be tested (CLAUDE.md
//! phantom-test rule). Several fields are unions whose meaning depends on the
//! opcode; the union members are named here so no call site re-derives an
//! offset.

/// `sizeof(struct io_uring_sqe)`.
pub const SQE_BYTES: usize = 64;

/// Decoded submission-queue entry.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub struct Sqe {
    pub opcode: u8,
    pub flags: u8,
    /// `ioprio`; also the per-op flags half of `recv`/`accept` multishot.
    pub ioprio: u16,
    pub fd: i32,
    /// `off`, also `addr2`.
    pub off: u64,
    /// `addr`, also `splice_off_in`.
    pub addr: u64,
    pub len: u32,
    /// The per-opcode flags word (`rw_flags`, `open_flags`, `msg_flags`, …).
    pub op_flags: u32,
    pub user_data: u64,
    /// `buf_index`, also `buf_group`.
    pub buf_index: u16,
    pub personality: u16,
    /// `splice_fd_in`, also `file_index`.
    pub splice_fd_in: i32,
    /// `addr_len` — the low half of the same word as `splice_fd_in`.
    pub addr_len: u16,
    pub addr3: u64,
}

impl Sqe {
    /// Decode the wire image. # C: O(1)
    pub fn from_bytes(b: &[u8; SQE_BYTES]) -> Self {
        let g16 = |o: usize| u16::from_le_bytes([b[o], b[o + 1]]);
        let g32 = |o: usize| u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]]);
        let g64 = |o: usize| {
            let mut v = [0u8; 8]; v.copy_from_slice(&b[o..o + 8]); u64::from_le_bytes(v)
        };
        Self {
            opcode: b[0], flags: b[1], ioprio: g16(2), fd: g32(4) as i32,
            off: g64(8), addr: g64(16), len: g32(24), op_flags: g32(28),
            user_data: g64(32), buf_index: g16(40), personality: g16(42),
            splice_fd_in: g32(44) as i32, addr_len: g16(44), addr3: g64(48),
        }
    }

    /// `file_index` — the same word as `splice_fd_in`, read unsigned. A direct
    /// descriptor request is 1-based, so 0 means "an ordinary fd".
    /// # C: O(1)
    pub fn file_index(&self) -> u32 { self.splice_fd_in as u32 }

    /// Map the `accept` unions onto `accept4(fd, addr, addrlen, flags)`.
    /// # C: O(1)
    pub fn accept_args(&self, fd: i32) -> syscall::SyscallArgs {
        syscall::SyscallArgs {
            a0: fd as u64, a1: self.addr, a2: self.off, a3: self.op_flags as u64, a4: 0, a5: 0,
        }
    }
}

#[cfg(test)]
#[path = "io_uring_sqe/tests.rs"]
mod tests;
